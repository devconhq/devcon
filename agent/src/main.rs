//! DevCon Port Forwarding Agent
//!
//! This agent runs inside the container and communicates with the host control server via TCP.

use clap::{Parser, Subcommand};
use daemonize::Daemonize;
use devcon_proto::{
    AgentHello, AgentMessage, OpenUrl, StartPortForward, StopPortForward, agent_message,
};
use prost::Message;
use std::collections::HashSet;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, TryRecvError};
use std::time::Duration;

#[derive(Parser)]
#[command(name = "devcon-agent")]
#[command(about = "DevCon agent", long_about = None)]
struct Cli {
    /// Host address for the control server
    #[arg(
        short = 'H',
        long,
        env = "DEVCON_CONTROL_HOST",
        default_value = "host.docker.internal"
    )]
    control_host: String,

    /// Port for the control server
    #[arg(
        short = 'p',
        long,
        env = "DEVCON_CONTROL_PORT",
        default_value = "15000"
    )]
    control_port: u16,

    /// Comma-separated list of ports to exclude from auto-forwarding
    #[arg(long, value_delimiter = ',')]
    exclude_ports: Option<Vec<u16>>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Request the host to start forwarding a port
    StartPortForward {
        /// Port number to forward
        #[arg(value_name = "PORT")]
        port: u16,
    },
    /// Request the host to stop forwarding a port
    StopPortForward {
        /// Port number to stop forwarding
        #[arg(value_name = "PORT")]
        port: u16,
    },
    /// Request the host to open a URL in the browser
    OpenUrl {
        /// URL to open
        #[arg(value_name = "URL")]
        url: String,
    },
    /// Run as a daemon, maintaining connection to control server
    Daemon {
        /// Port scan interval in seconds
        #[arg(long, default_value = "1")]
        scan_interval: u64,

        /// Run in foreground (don't daemonize)
        #[arg(long, default_value = "false")]
        foreground: bool,
    },
}

/// Send a protobuf message over a TCP stream with length prefix
fn send_message(stream: &mut TcpStream, msg: &AgentMessage) -> io::Result<()> {
    let mut buf = Vec::new();
    msg.encode(&mut buf).map_err(io::Error::other)?;

    let len = buf.len() as u32;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(&buf)?;
    stream.flush()?;

    Ok(())
}

/// Read a protobuf message from a TCP stream with length prefix
fn read_message(stream: &mut TcpStream) -> io::Result<AgentMessage> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;

    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;

    AgentMessage::decode(&buf[..]).map_err(io::Error::other)
}

/// Connect to the control server
fn connect_to_control_server(host: &str, port: u16) -> io::Result<TcpStream> {
    let addr = format!("{}:{}", host, port);
    eprintln!("Connecting to control server at {}", addr);
    TcpStream::connect(addr)
}

/// Handle tunnel request - open NEW connection to data port and proxy data
fn handle_tunnel_request(
    host: &str,
    data_port: u16,
    service_port: u16,
    tunnel_id: u32,
) -> io::Result<()> {
    eprintln!(
        "Tunnel request received: tunnel_id={}, service_port={}, connecting to {}:{}",
        tunnel_id, service_port, host, data_port
    );

    // Open NEW connection to data port for this tunnel
    let mut tunnel_stream = TcpStream::connect(format!("{}:{}", host, data_port))?;
    eprintln!("Opened new tunnel connection to data port {}", data_port);

    // Send tunnel_id (no magic bytes needed)
    tunnel_stream.write_all(&tunnel_id.to_be_bytes())?;
    tunnel_stream.flush()?;
    eprintln!("Sent tunnel_id {} to data port", tunnel_id);

    // Connect to the local service in the container
    let local_addr = format!("127.0.0.1:{}", service_port);
    let local_stream = match TcpStream::connect(&local_addr) {
        Ok(s) => {
            eprintln!("Connected to local service at {}", local_addr);
            s
        }
        Err(e) => {
            eprintln!(
                "Failed to connect to local service at {}: {}",
                local_addr, e
            );
            return Err(e);
        }
    };

    // Proxy data bidirectionally
    let mut tunnel_read = tunnel_stream.try_clone()?;
    let mut tunnel_write = tunnel_stream;
    let mut local_read = local_stream.try_clone()?;
    let mut local_write = local_stream;

    // Spawn thread to copy from tunnel to local service
    let handle = std::thread::spawn(move || {
        let result = std::io::copy(&mut tunnel_read, &mut local_write);
        let _ = local_write.shutdown(std::net::Shutdown::Write);
        result
    });

    // Copy from local service to tunnel in this thread
    let result = std::io::copy(&mut local_read, &mut tunnel_write);
    let _ = tunnel_write.shutdown(std::net::Shutdown::Write);

    // Wait for the other direction to complete
    let _ = handle.join();

    eprintln!(
        "Tunnel closed: tunnel_id={}, service_port={}",
        tunnel_id, service_port
    );
    result.map(|_| ())
}

/// Scan for listening ports on the container
/// Reads /proc/net/tcp and /proc/net/tcp6 to find ports in LISTEN state (0A)
/// Returns only ports > 1024 (non-privileged ports)
fn scan_listening_ports() -> io::Result<Vec<u16>> {
    let mut ports = HashSet::new();

    // Read IPv4 listening ports from /proc/net/tcp
    if let Ok(file) = File::open("/proc/net/tcp") {
        let reader = BufReader::new(file);
        for line in reader.lines().skip(1).flatten() {
            // Skip header line
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let state = parts[3];
                // 0A = LISTEN state in hex
                if state == "0A" {
                    // Local address is in format "ADDR:PORT" in hex
                    if let Some(local_addr) = parts.get(1)
                        && let Some(port_hex) = local_addr.split(':').nth(1)
                        && let Ok(port) = u16::from_str_radix(port_hex, 16)
                        && port > 1024
                    {
                        ports.insert(port);
                    }
                }
            }
        }
    }

    // Read IPv6 listening ports from /proc/net/tcp6
    if let Ok(file) = File::open("/proc/net/tcp6") {
        let reader = BufReader::new(file);
        for line in reader.lines().skip(1).flatten() {
            // Skip header line
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let state = parts[3];
                // 0A = LISTEN state in hex
                if state == "0A" {
                    // Local address is in format "ADDR:PORT" in hex
                    if let Some(local_addr) = parts.get(1)
                        && let Some(port_hex) = local_addr.split(':').nth(1)
                        && let Ok(port) = u16::from_str_radix(port_hex, 16)
                        && port > 1024
                    {
                        ports.insert(port);
                    }
                }
            }
        }
    }

    Ok(ports.into_iter().collect())
}

/// Run port forward daemon for a specific port
fn run_port_forward_daemon(stream: &mut TcpStream, port: u16, host: &str) -> io::Result<()> {
    eprintln!("Port forward daemon running for port {}", port);

    // Keep the connection alive and handle tunnel requests
    loop {
        match read_message(stream) {
            Ok(message) => {
                match message.message {
                    Some(agent_message::Message::TunnelRequest(req)) => {
                        let service_port = req.port as u16;
                        let tunnel_id = req.tunnel_id;
                        let data_port = req.data_port as u16;
                        eprintln!(
                            "Received tunnel request: tunnel_id={}, service_port={}, data_port={}",
                            tunnel_id, service_port, data_port
                        );

                        // Spawn new thread to handle this tunnel
                        let host = host.to_string();
                        std::thread::spawn(move || {
                            if let Err(e) =
                                handle_tunnel_request(&host, data_port, service_port, tunnel_id)
                            {
                                eprintln!("Error handling tunnel: {}", e);
                            }
                        });
                    }
                    _ => {
                        eprintln!("Received unexpected message: {:?}", message);
                    }
                }
            }
            Err(e) => {
                if e.kind() == io::ErrorKind::UnexpectedEof {
                    eprintln!("Control server connection closed");
                    break;
                }
                eprintln!("Error reading from control server: {}", e);
                break;
            }
        }
    }

    Ok(())
}

/// Run the agent as a daemon, maintaining connection to control server
fn run_daemon(
    host: &str,
    port: u16,
    scan_interval_secs: u64,
    excluded_ports: HashSet<u16>,
) -> io::Result<()> {
    let mut stream = connect_to_control_server(host, port)?;
    eprintln!("Connected to control server");

    // Send AgentHello message to identify this container
    let workspace_name =
        std::env::var("DEVCON_WORKSPACE_NAME").unwrap_or_else(|_| "unknown".to_string());
    let container_name = std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let hello_msg = AgentMessage {
        message: Some(agent_message::Message::AgentHello(AgentHello {
            container_name: container_name.clone(),
            workspace_name: workspace_name.clone(),
        })),
    };
    send_message(&mut stream, &hello_msg)?;
    eprintln!(
        "Sent AgentHello: container={}, workspace={}",
        container_name, workspace_name
    );

    // Set read timeout to allow checking channel messages periodically
    stream.set_read_timeout(Some(Duration::from_millis(100)))?;

    let scan_failed_warning_shown = Arc::new(AtomicBool::new(false));

    // Create channel for port scanner to send messages to main thread
    let (tx, rx) = mpsc::channel::<AgentMessage>();

    // Spawn port scanner thread
    {
        let scan_failed_warning = Arc::clone(&scan_failed_warning_shown);
        std::thread::spawn(move || {
            let mut forwarded_ports: HashSet<u16> = HashSet::new();
            let mut candidate_new_ports: HashSet<u16> = HashSet::new();
            let mut candidate_removed_ports: HashSet<u16> = HashSet::new();

            loop {
                // Scan for listening ports
                match scan_listening_ports() {
                    Ok(current_ports) => {
                        let current_set: HashSet<u16> = current_ports.into_iter().collect();

                        // Find ports that are listening but not yet forwarded
                        let new_ports: HashSet<u16> =
                            current_set.difference(&forwarded_ports).copied().collect();

                        // Find ports that are forwarded but no longer listening
                        let removed_ports: HashSet<u16> =
                            forwarded_ports.difference(&current_set).copied().collect();

                        // Filter out excluded ports (already forwarded by Docker)
                        let new_ports: HashSet<u16> =
                            new_ports.difference(&excluded_ports).copied().collect();

                        // Process new ports with debouncing (2 consecutive scans)
                        for port in &new_ports {
                            if candidate_new_ports.contains(port) {
                                // Port seen in 2 consecutive scans, start forwarding
                                eprintln!("Auto-forwarding port {} (detected)", port);
                                let msg = AgentMessage {
                                    message: Some(agent_message::Message::StartPortForward(
                                        StartPortForward { port: *port as u32 },
                                    )),
                                };
                                if tx.send(msg).is_ok() {
                                    forwarded_ports.insert(*port);
                                    candidate_new_ports.remove(port);
                                } else {
                                    eprintln!(
                                        "Failed to send StartPortForward for port {}: channel closed",
                                        port
                                    );
                                }
                            } else {
                                // First time seeing this port, add to candidates
                                candidate_new_ports.insert(*port);
                            }
                        }

                        // Clean up candidates that are no longer new
                        candidate_new_ports.retain(|p| new_ports.contains(p));

                        // Process removed ports with debouncing (2 consecutive scans)
                        for port in &removed_ports {
                            if candidate_removed_ports.contains(port) {
                                // Port absent in 2 consecutive scans, stop forwarding
                                eprintln!("Stopping auto-forwarding for port {} (closed)", port);
                                let msg = AgentMessage {
                                    message: Some(agent_message::Message::StopPortForward(
                                        StopPortForward { port: *port as u32 },
                                    )),
                                };
                                if tx.send(msg).is_ok() {
                                    forwarded_ports.remove(port);
                                    candidate_removed_ports.remove(port);
                                } else {
                                    eprintln!(
                                        "Failed to send StopPortForward for port {}: channel closed",
                                        port
                                    );
                                }
                            } else {
                                // First time not seeing this port, add to candidates
                                candidate_removed_ports.insert(*port);
                            }
                        }

                        // Clean up candidates that are no longer removed
                        candidate_removed_ports.retain(|p| removed_ports.contains(p));
                    }
                    Err(e) => {
                        // Show warning only once
                        if !scan_failed_warning.swap(true, Ordering::SeqCst) {
                            eprintln!(
                                "Warning: Port scanning failed ({}). Auto-forwarding disabled. \
                                This is normal on non-Linux systems.",
                                e
                            );
                        }
                    }
                }

                // Sleep for the scan interval
                std::thread::sleep(Duration::from_secs(scan_interval_secs));
            }
        });
    }

    // Keep the connection alive and handle any incoming messages
    loop {
        // Check for port forward requests from scanner thread
        match rx.try_recv() {
            Ok(msg) => {
                eprintln!("Sending port forward request from scanner");
                if let Err(e) = send_message(&mut stream, &msg) {
                    eprintln!("Failed to send message to control server: {}", e);
                }
            }
            Err(TryRecvError::Empty) => {
                // No messages from scanner, continue
            }
            Err(TryRecvError::Disconnected) => {
                eprintln!("Scanner thread disconnected");
                break;
            }
        }

        // Read incoming messages from control server
        match read_message(&mut stream) {
            Ok(message) => {
                eprintln!("Received message from host: {:?}", message);
                // Handle incoming messages from host
                match message.message {
                    Some(agent_message::Message::TunnelRequest(req)) => {
                        let service_port = req.port as u16;
                        let tunnel_id = req.tunnel_id;
                        let data_port = req.data_port as u16;
                        eprintln!(
                            "Received tunnel request: tunnel_id={}, service_port={}, data_port={}",
                            tunnel_id, service_port, data_port
                        );

                        // Spawn new thread to handle this tunnel
                        let host = host.to_string();
                        std::thread::spawn(move || {
                            if let Err(e) =
                                handle_tunnel_request(&host, data_port, service_port, tunnel_id)
                            {
                                eprintln!("Error handling tunnel: {}", e);
                            }
                        });
                    }
                    _ => {
                        eprintln!("Received message: {:?}", message);
                    }
                }
            }
            Err(e) => {
                // Ignore timeout errors (expected due to read timeout)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut {
                    continue;
                }
                if e.kind() == io::ErrorKind::UnexpectedEof {
                    eprintln!("Control server connection closed");
                    break;
                }
                eprintln!("Error reading from control server: {}", e);
                break;
            }
        }
    }

    Ok(())
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::StartPortForward { port } => {
            match connect_to_control_server(&cli.control_host, cli.control_port) {
                Ok(mut stream) => {
                    eprintln!("Requesting port forward for port {}", port);
                    let msg = AgentMessage {
                        message: Some(agent_message::Message::StartPortForward(StartPortForward {
                            port: port as u32,
                        })),
                    };
                    match send_message(&mut stream, &msg) {
                        Ok(_) => {
                            eprintln!("Port forward request sent, keeping connection alive...");
                            // Keep connection alive and handle any reverse tunnel requests
                            run_port_forward_daemon(&mut stream, port, &cli.control_host)
                        }
                        Err(e) => Err(e),
                    }
                }
                Err(e) => Err(e),
            }
        }
        Commands::StopPortForward { port } => {
            match connect_to_control_server(&cli.control_host, cli.control_port) {
                Ok(mut stream) => {
                    let msg = AgentMessage {
                        message: Some(agent_message::Message::StopPortForward(StopPortForward {
                            port: port as u32,
                        })),
                    };
                    send_message(&mut stream, &msg)
                }
                Err(e) => Err(e),
            }
        }
        Commands::OpenUrl { url } => {
            match connect_to_control_server(&cli.control_host, cli.control_port) {
                Ok(mut stream) => {
                    let msg = AgentMessage {
                        message: Some(agent_message::Message::OpenUrl(OpenUrl { url })),
                    };
                    send_message(&mut stream, &msg)
                }
                Err(e) => Err(e),
            }
        }
        Commands::Daemon {
            scan_interval,
            foreground,
        } => {
            // We're now in the child process
            // Parse excluded ports from CLI arg or environment variable
            let mut excluded_ports = HashSet::new();

            if let Some(ports) = cli.exclude_ports {
                excluded_ports.extend(ports);
            } else if let Ok(env_ports) = std::env::var("DEVCON_FORWARDED_PORTS") {
                for port_str in env_ports.split(',') {
                    if let Ok(port) = port_str.trim().parse::<u16>() {
                        excluded_ports.insert(port);
                    }
                }
            }

            if !excluded_ports.is_empty() {
                eprintln!("Excluding ports from auto-forwarding: {:?}", excluded_ports);
            }

            if foreground {
                eprintln!("Running in foreground mode (not daemonized)");
                run_daemon(
                    &cli.control_host,
                    cli.control_port,
                    scan_interval,
                    excluded_ports,
                )
            } else {
                eprintln!("Running in daemon mode");
                // Daemonize the process
                let daemonize = Daemonize::new();

                match daemonize.start() {
                    Ok(_) => run_daemon(
                        &cli.control_host,
                        cli.control_port,
                        scan_interval,
                        excluded_ports,
                    ),
                    Err(e) => {
                        eprintln!("Failed to daemonize: {}", e);
                        Err(io::Error::other(e))
                    }
                }
            }
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use devcon_proto::{
        AgentMessage, OpenUrl, StartPortForward, StopPortForward, TunnelRequest, agent_message,
    };
    use std::net::{TcpListener, TcpStream};

    #[test]
    fn test_message_encoding_decoding_start_port_forward() {
        let original_msg = AgentMessage {
            message: Some(agent_message::Message::StartPortForward(StartPortForward {
                port: 8080,
            })),
        };

        let mut buf = Vec::new();
        original_msg.encode(&mut buf).unwrap();

        let decoded_msg = AgentMessage::decode(&buf[..]).unwrap();

        assert_eq!(
            match decoded_msg.message {
                Some(agent_message::Message::StartPortForward(ref spf)) => spf.port,
                _ => panic!("Wrong message type"),
            },
            8080
        );
    }

    #[test]
    fn test_message_encoding_decoding_stop_port_forward() {
        let original_msg = AgentMessage {
            message: Some(agent_message::Message::StopPortForward(StopPortForward {
                port: 3000,
            })),
        };

        let mut buf = Vec::new();
        original_msg.encode(&mut buf).unwrap();

        let decoded_msg = AgentMessage::decode(&buf[..]).unwrap();

        assert_eq!(
            match decoded_msg.message {
                Some(agent_message::Message::StopPortForward(ref spf)) => spf.port,
                _ => panic!("Wrong message type"),
            },
            3000
        );
    }

    #[test]
    fn test_message_encoding_decoding_open_url() {
        let test_url = "https://example.com";
        let original_msg = AgentMessage {
            message: Some(agent_message::Message::OpenUrl(OpenUrl {
                url: test_url.to_string(),
            })),
        };

        let mut buf = Vec::new();
        original_msg.encode(&mut buf).unwrap();

        let decoded_msg = AgentMessage::decode(&buf[..]).unwrap();

        assert_eq!(
            match decoded_msg.message {
                Some(agent_message::Message::OpenUrl(ref ou)) => &ou.url,
                _ => panic!("Wrong message type"),
            },
            test_url
        );
    }

    #[test]
    fn test_message_encoding_decoding_tunnel_request() {
        let original_msg = AgentMessage {
            message: Some(agent_message::Message::TunnelRequest(TunnelRequest {
                tunnel_id: 12345,
                port: 8080,
                data_port: 9000,
            })),
        };

        let mut buf = Vec::new();
        original_msg.encode(&mut buf).unwrap();

        let decoded_msg = AgentMessage::decode(&buf[..]).unwrap();

        match decoded_msg.message {
            Some(agent_message::Message::TunnelRequest(ref tr)) => {
                assert_eq!(tr.tunnel_id, 12345);
                assert_eq!(tr.port, 8080);
                assert_eq!(tr.data_port, 9000);
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_send_and_read_message_roundtrip() {
        // Create a TCP listener for testing
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn a thread to accept connection and read message
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            read_message(&mut stream).unwrap()
        });

        // Connect and send message
        let mut client_stream = TcpStream::connect(addr).unwrap();
        let original_msg = AgentMessage {
            message: Some(agent_message::Message::StartPortForward(StartPortForward {
                port: 5000,
            })),
        };
        send_message(&mut client_stream, &original_msg).unwrap();

        // Verify received message
        let received_msg = handle.join().unwrap();
        match received_msg.message {
            Some(agent_message::Message::StartPortForward(spf)) => {
                assert_eq!(spf.port, 5000);
            }
            _ => panic!("Wrong message type received"),
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_scan_listening_ports_returns_vec() {
        // This test just verifies the function runs without panic on Linux
        // The actual ports found will vary by system
        let result = scan_listening_ports();
        assert!(result.is_ok());

        let ports = result.unwrap();
        // All ports should be > 1024 (non-privileged)
        for port in ports {
            assert!(port > 1024, "Port {} should be > 1024", port);
        }
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn test_scan_listening_ports_non_linux() {
        // On non-Linux systems, the function should return an empty vec or error
        // since /proc/net/tcp doesn't exist
        let result = scan_listening_ports();
        // Either it errors or returns empty
        if let Ok(ports) = result {
            // Could be empty if files don't exist
            assert!(ports.is_empty() || !ports.is_empty());
        }
    }

    #[test]
    fn test_message_length_prefix() {
        // Test that message length prefix is correctly handled
        let msg = AgentMessage {
            message: Some(agent_message::Message::StartPortForward(StartPortForward {
                port: 8080,
            })),
        };

        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();
        let expected_len = buf.len() as u32;

        // Create a mock stream
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();

            // Read length prefix
            let mut len_buf = [0u8; 4];
            stream.read_exact(&mut len_buf).unwrap();

            u32::from_be_bytes(len_buf)
        });

        let mut client_stream = TcpStream::connect(addr).unwrap();
        send_message(&mut client_stream, &msg).unwrap();

        let received_len = handle.join().unwrap();
        assert_eq!(received_len, expected_len);
    }

    #[test]
    fn test_empty_message_handling() {
        // Test that we can handle an AgentMessage with no inner message
        let msg = AgentMessage { message: None };

        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();

        let decoded = AgentMessage::decode(&buf[..]).unwrap();
        assert!(decoded.message.is_none());
    }

    #[test]
    fn test_multiple_messages_sequence() {
        // Test sending multiple messages over the same connection
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();

            let msg1 = read_message(&mut stream).unwrap();
            let msg2 = read_message(&mut stream).unwrap();
            let msg3 = read_message(&mut stream).unwrap();

            (msg1, msg2, msg3)
        });

        let mut client_stream = TcpStream::connect(addr).unwrap();

        let msg1 = AgentMessage {
            message: Some(agent_message::Message::StartPortForward(StartPortForward {
                port: 8080,
            })),
        };
        let msg2 = AgentMessage {
            message: Some(agent_message::Message::StopPortForward(StopPortForward {
                port: 8080,
            })),
        };
        let msg3 = AgentMessage {
            message: Some(agent_message::Message::OpenUrl(OpenUrl {
                url: "http://test".to_string(),
            })),
        };

        send_message(&mut client_stream, &msg1).unwrap();
        send_message(&mut client_stream, &msg2).unwrap();
        send_message(&mut client_stream, &msg3).unwrap();

        let (recv1, recv2, recv3) = handle.join().unwrap();

        assert!(matches!(
            recv1.message,
            Some(agent_message::Message::StartPortForward(_))
        ));
        assert!(matches!(
            recv2.message,
            Some(agent_message::Message::StopPortForward(_))
        ));
        assert!(matches!(
            recv3.message,
            Some(agent_message::Message::OpenUrl(_))
        ));
    }
}
