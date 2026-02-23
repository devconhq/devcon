// MIT License
//
// Copyright (c) 2025 DevCon Contributors
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

//! # Control Server
//!
//! This module implements the TCP control server that accepts connections from
//! container agents and manages port forwarding requests.

use crate::error::{Error, Result};
use comfy_table::{Cell, Color, Table};
use devcon_proto::AgentMessage;
use devcon_proto::agent_message::Message as ProtoMessage;
use prost::Message;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use tracing::{debug, error, info, warn};

/// Container identification information
#[derive(Debug, Clone)]
struct ContainerInfo {
    container_name: String,
    workspace_name: String,
}

/// Display-friendly port forward information
#[derive(Debug, Clone)]
pub struct PortForwardInfo {
    pub local_port: u16,
    pub container_port: u16,
    pub peer_address: String,
}

/// Type alias for a port forward entry containing the agent stream, container port, tunnel ID counter, data port, and container info
type ForwardEntry = (
    Arc<Mutex<TcpStream>>,
    u16,
    Arc<AtomicU32>,
    u16,
    Option<ContainerInfo>,
);

/// Type alias for status change callback
pub type StatusCallback = Arc<dyn Fn(&[PortForwardInfo]) + Send + Sync>;

/// Manages active port forwarding sessions
#[derive(Clone)]
struct PortForwardManager {
    /// Map of local_port -> (agent_stream, container_port, tunnel_id_counter, data_port, container_info)
    forwards: Arc<Mutex<HashMap<u16, ForwardEntry>>>,
    /// Map of tunnel_id -> pending client stream
    pending_tunnels: Arc<Mutex<HashMap<u32, TcpStream>>>,
    /// Optional callback for status updates
    status_callback: Option<StatusCallback>,
}

impl PortForwardManager {
    fn new(status_callback: Option<StatusCallback>) -> Self {
        Self {
            forwards: Arc::new(Mutex::new(HashMap::new())),
            pending_tunnels: Arc::new(Mutex::new(HashMap::new())),
            status_callback,
        }
    }

    /// Get current port forwards as display-friendly info
    fn get_port_forwards(&self) -> Vec<PortForwardInfo> {
        let forwards = self.forwards.lock().unwrap();
        forwards
            .iter()
            .filter_map(|(local_port, (_, container_port, _, _, container_info))| {
                container_info.as_ref().map(|info| PortForwardInfo {
                    local_port: *local_port,
                    container_port: *container_port,
                    peer_address: format!("{}:{}", info.container_name, info.workspace_name),
                })
            })
            .collect()
    }

    /// Notify status callback of current port forwards
    fn notify_status(&self) {
        if let Some(callback) = &self.status_callback {
            let forwards = self.get_port_forwards();
            callback(&forwards);
        }
    }

    /// Start forwarding a port through the control connection
    fn start_forward(
        &self,
        local_port: u16,
        container_port: u16,
        stream: Arc<Mutex<TcpStream>>,
        container_info: Option<ContainerInfo>,
    ) -> Result<()> {
        let mut forwards = self.forwards.lock().unwrap();

        if forwards.contains_key(&local_port) {
            return Err(Error::new(format!(
                "Port {} is already being forwarded",
                local_port
            )));
        }

        // Start the local listener for this port
        let listener = TcpListener::bind(format!("0.0.0.0:{}", local_port))
            .map_err(|e| Error::new(format!("Failed to bind to port {}: {}", local_port, e)))?;

        info!(
            "Listening on 0.0.0.0:{} for connections to forward to container port {}",
            local_port, container_port
        );

        // Create dedicated data listener on random port for this forward
        let data_listener = TcpListener::bind("0.0.0.0:0").map_err(|e| {
            Error::new(format!(
                "{}: {}",
                "Failed to bind data listener on random port", e
            ))
        })?;
        let data_port = data_listener.local_addr()?.port();

        info!(
            "Data listener for port {} started on 0.0.0.0:{}",
            local_port, data_port
        );

        // Store the forward mapping
        let tunnel_id_counter = Arc::new(AtomicU32::new(1));
        forwards.insert(
            local_port,
            (
                stream.clone(),
                container_port,
                tunnel_id_counter.clone(),
                data_port,
                container_info,
            ),
        );

        // Spawn dedicated data listener thread for this forward
        let pending_tunnels_data = self.pending_tunnels.clone();
        let forwards_clone_data = self.forwards.clone();
        thread::spawn(move || {
            for incoming_stream in data_listener.incoming() {
                match incoming_stream {
                    Ok(mut agent_stream) => {
                        // Read tunnel_id from the stream
                        let mut tunnel_id_buf = [0u8; 4];
                        if let Err(e) = agent_stream.read_exact(&mut tunnel_id_buf) {
                            error!("Failed to read tunnel_id from data connection: {}", e);
                            continue;
                        }
                        let tunnel_id = u32::from_be_bytes(tunnel_id_buf);

                        debug!(
                            "Data listener received tunnel connection with tunnel_id={}",
                            tunnel_id
                        );

                        let pending_clone = pending_tunnels_data.clone();
                        thread::spawn(move || {
                            if let Err(e) =
                                handle_tunnel_connection(agent_stream, tunnel_id, pending_clone)
                            {
                                error!("Error handling tunnel connection: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Error accepting data connection: {}", e);
                        // Check if we should stop listening (forward was stopped)
                        let forwards = forwards_clone_data.lock().unwrap();
                        if !forwards.contains_key(&local_port) {
                            break;
                        }
                    }
                }
            }
            debug!("Data listener thread for port {} exiting", local_port);
        });

        // Spawn thread to accept connections on the forwarded port
        let stream_clone = stream.clone();
        let forwards_clone = self.forwards.clone();
        let pending_tunnels = self.pending_tunnels.clone();

        thread::spawn(move || {
            for incoming_stream in listener.incoming() {
                match incoming_stream {
                    Ok(client_stream) => {
                        let agent_stream = stream_clone.clone();
                        let tunnel_id = tunnel_id_counter.fetch_add(1, Ordering::SeqCst);
                        let pending_clone = pending_tunnels.clone();

                        // Get the data_port from the forwards map
                        let data_port = {
                            let forwards = forwards_clone.lock().unwrap();
                            forwards.get(&local_port).map(|(_, _, _, dp, _)| *dp)
                        };

                        if let Some(data_port) = data_port {
                            thread::spawn(move || {
                                if let Err(e) = handle_forwarded_connection(
                                    client_stream,
                                    agent_stream,
                                    container_port,
                                    tunnel_id,
                                    pending_clone,
                                    data_port,
                                ) {
                                    error!("Error handling forwarded connection: {}", e);
                                }
                            });
                        } else {
                            error!("Forward for port {} no longer exists", local_port);
                            break;
                        }
                    }
                    Err(e) => {
                        error!("Error accepting connection: {}", e);
                        // Check if we should stop listening (forward was stopped)
                        let forwards = forwards_clone.lock().unwrap();
                        if !forwards.contains_key(&local_port) {
                            break;
                        }
                    }
                }
            }
            debug!(
                "Forwarded port listener thread for port {} exiting",
                local_port
            );
        });

        // Notify status callback
        drop(forwards); // Release lock before calling callback
        self.notify_status();

        Ok(())
    }

    /// Stop forwarding a port
    fn stop_forward(&self, local_port: u16) -> Result<()> {
        let mut forwards = self.forwards.lock().unwrap();

        if forwards.remove(&local_port).is_some() {
            drop(forwards); // Release lock before notification
            info!("Stopped forwarding port {}", local_port);
            self.notify_status();
            Ok(())
        } else {
            Err(Error::new(format!(
                "Port {} is not being forwarded",
                local_port
            )))
        }
    }
}

/// Handle a forwarded connection from host to container
/// This sends a tunnel request to the agent and waits for it to connect back
fn handle_forwarded_connection(
    client_stream: TcpStream,
    agent_stream: Arc<Mutex<TcpStream>>,
    container_port: u16,
    tunnel_id: u32,
    pending_tunnels: Arc<Mutex<HashMap<u32, TcpStream>>>,
    data_port: u16,
) -> Result<()> {
    debug!(
        "Handling forwarded connection to container port {}, tunnel_id={}",
        container_port, tunnel_id
    );

    // Store the client stream as pending
    {
        let mut pending = pending_tunnels.lock().unwrap();
        pending.insert(tunnel_id, client_stream);
        debug!(
            "Stored pending client for tunnel_id={}, total pending: {}",
            tunnel_id,
            pending.len()
        );
    }

    // Send tunnel request to agent over control connection
    let message = AgentMessage {
        message: Some(ProtoMessage::TunnelRequest(devcon_proto::TunnelRequest {
            port: container_port as u32,
            tunnel_id,
            data_port: data_port as u32,
        })),
    };

    let mut agent = agent_stream.lock().unwrap();
    send_message(&mut agent, &message)?;
    drop(agent); // Release lock immediately

    debug!(
        "Sent tunnel request to agent for port {}, tunnel_id={}, agent should connect back on data port {}",
        container_port, tunnel_id, data_port
    );

    // Wait up to 5 seconds for the tunnel to be established
    // This keeps the client stream alive in pending_tunnels
    let start = std::time::Instant::now();
    loop {
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Check if tunnel was taken (meaning agent connected)
        {
            let pending = pending_tunnels.lock().unwrap();
            if !pending.contains_key(&tunnel_id) {
                debug!("Tunnel {} successfully established", tunnel_id);
                return Ok(());
            }
        }

        // Timeout after 5 seconds
        if start.elapsed().as_secs() > 5 {
            warn!("Timeout waiting for tunnel {} to be established", tunnel_id);
            // Remove from pending to clean up
            let mut pending = pending_tunnels.lock().unwrap();
            pending.remove(&tunnel_id);
            return Err(Error::new("Tunnel establishment timeout".to_string()));
        }
    }
}

/// Send a protobuf message over a TCP stream with length prefix
fn send_message(stream: &mut TcpStream, message: &AgentMessage) -> Result<()> {
    let mut buf = Vec::new();
    message.encode(&mut buf)?;

    let len = buf.len() as u32;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(&buf)?;
    stream.flush()?;

    Ok(())
}

/// Open a URL in the default browser
fn open_url(url: &str) -> Result<()> {
    info!("Opening URL in browser: {}", url);
    open::that(url)
        .map_err(|e| Error::new(format!("{}: {}", "Failed to open URL in browser", e)))?;
    info!("Successfully opened URL");
    Ok(())
}

/// Read a protobuf message from a TCP stream with length prefix
fn read_message(stream: &mut TcpStream) -> Result<AgentMessage> {
    let mut len_buf = [0u8; 4];

    // Try to read the length prefix
    match stream.read_exact(&mut len_buf) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(Error::new(
                "Connection closed while reading message length".to_string(),
            ));
        }
        Err(e) => return Err(e.into()),
    }

    let len = u32::from_be_bytes(len_buf) as usize;

    // Validate message length to prevent excessive memory allocation
    if len == 0 {
        return Err(Error::new("Received zero-length message".to_string()));
    }
    if len > 10 * 1024 * 1024 {
        return Err(Error::new(format!(
            "Message too large: {} bytes (max 10MB)",
            len
        )));
    }

    let mut buf = vec![0u8; len];

    // Try to read the message body
    match stream.read_exact(&mut buf) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(Error::new(format!(
                "Connection closed while reading message body (expected {} bytes)",
                len
            )));
        }
        Err(e) => return Err(e.into()),
    }

    let message = AgentMessage::decode(&buf[..])
        .map_err(|e| Error::new(format!("{}: {}", "Failed to decode protobuf message", e)))?;
    Ok(message)
}

/// Handle a tunnel connection from agent (called by data listener)
fn handle_tunnel_connection(
    agent_stream: TcpStream,
    tunnel_id: u32,
    pending_tunnels: Arc<Mutex<HashMap<u32, TcpStream>>>,
) -> Result<()> {
    debug!("Handling tunnel connection for tunnel_id={}", tunnel_id);

    // Get the pending client stream for this tunnel_id
    let client_stream = {
        let mut pending = pending_tunnels.lock().unwrap();
        pending.remove(&tunnel_id)
    };

    if client_stream.is_none() {
        warn!("No pending client found for tunnel_id={}", tunnel_id);
        return Ok(());
    }

    let client_stream = client_stream.unwrap();
    info!(
        "Matched tunnel_id={} with pending client, starting bidirectional proxy",
        tunnel_id
    );

    // Proxy data bidirectionally
    let mut agent_read = agent_stream.try_clone()?;
    let mut agent_write = agent_stream;
    let mut client_read = client_stream.try_clone()?;
    let mut client_write = client_stream;

    // Spawn thread to copy from client to agent
    let handle = thread::spawn(move || {
        let result = std::io::copy(&mut client_read, &mut agent_write);
        let _ = agent_write.shutdown(std::net::Shutdown::Write);
        result
    });

    // Copy from agent to client in this thread
    let result = std::io::copy(&mut agent_read, &mut client_write);
    let _ = client_write.shutdown(std::net::Shutdown::Write);

    // Wait for the other direction to complete
    let _ = handle.join();

    debug!("Tunnel closed for tunnel_id={}", tunnel_id);
    result.map(|_| ()).map_err(|e| e.into())
}

/// Handle a single agent connection
fn handle_agent_connection(mut stream: TcpStream, manager: PortForwardManager) -> Result<()> {
    let peer_addr = stream.peer_addr()?;
    info!("New agent connection from {}", peer_addr);

    let stream_arc = Arc::new(Mutex::new(stream.try_clone()?));

    // Use peer address as identifier
    let peer_info = ContainerInfo {
        container_name: peer_addr.ip().to_string(),
        workspace_name: peer_addr.port().to_string(),
    };
    let mut container_info = Some(peer_info);

    loop {
        match read_message(&mut stream) {
            Ok(message) => match message.message {
                Some(ProtoMessage::StartPortForward(fwd)) => {
                    let port = fwd.port as u16;
                    info!("Agent requested port forward: {}", port);

                    if let Err(e) = manager.start_forward(
                        port,
                        port,
                        stream_arc.clone(),
                        container_info.clone(),
                    ) {
                        error!("Failed to start port forward: {}", e);
                    }
                }
                Some(ProtoMessage::StopPortForward(fwd)) => {
                    let port = fwd.port as u16;
                    info!("Agent requested stop port forward: {}", port);

                    if let Err(e) = manager.stop_forward(port) {
                        error!("Failed to stop port forward: {}", e);
                    }
                }
                Some(ProtoMessage::OpenUrl(url_msg)) => {
                    info!("Agent requested to open URL: {}", url_msg.url);
                    if let Err(e) = open_url(&url_msg.url) {
                        error!("Failed to open URL: {}", e);
                    }
                }
                Some(ProtoMessage::TunnelRequest(_)) => {
                    warn!(
                        "Received unexpected TunnelRequest from agent (this should only go agent->host)"
                    );
                }
                Some(ProtoMessage::AgentHello(hello)) => {
                    debug!(
                        "Agent identified as container: {}, workspace: {}",
                        hello.container_name, hello.workspace_name
                    );
                    // Update container info with actual identity
                    container_info = Some(ContainerInfo {
                        container_name: hello.container_name,
                        workspace_name: hello.workspace_name,
                    });
                }
                None => {
                    warn!("Received message with no content");
                }
            },
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("Connection closed")
                    || err_str.contains("UnexpectedEof")
                    || err_str.contains("connection reset")
                    || err_str.contains("Connection reset")
                {
                    debug!("Agent connection closed from {}: {}", peer_addr, e);
                    info!("Agent {} disconnected", peer_addr);
                } else {
                    error!("Error reading from agent {}: {}", peer_addr, e);
                }
                break;
            }
        }
    }

    Ok(())
}

/// Display port forwards as an inline table
pub fn display_forwards_inline(forwards: &[PortForwardInfo]) {
    if forwards.is_empty() {
        println!("No active port forwards");
        return;
    }

    let mut table = Table::new();
    table.set_header(vec![
        Cell::new("Peer Address").fg(Color::Cyan),
        Cell::new("Local Port").fg(Color::Cyan),
        Cell::new("Container Port").fg(Color::Cyan),
    ]);

    for forward in forwards {
        table.add_row(vec![
            Cell::new(&forward.peer_address),
            Cell::new(forward.local_port.to_string()).fg(Color::Green),
            Cell::new(forward.container_port.to_string()).fg(Color::Yellow),
        ]);
    }

    println!("{}", table);
}

/// Display port forwards in fullscreen mode (clears screen and redraws)
pub fn display_forwards_fullscreen(forwards: &[PortForwardInfo]) {
    // Clear screen and move cursor to top-left
    print!("\x1B[2J\x1B[1;1H");

    println!("=== DevCon Port Forwarding Status ===\n");

    if forwards.is_empty() {
        println!("No active port forwards");
    } else {
        let mut table = Table::new();
        table.set_header(vec![
            Cell::new("Peer Address").fg(Color::Cyan),
            Cell::new("Local Port").fg(Color::Cyan),
            Cell::new("Container Port").fg(Color::Cyan),
        ]);

        for forward in forwards {
            table.add_row(vec![
                Cell::new(&forward.peer_address),
                Cell::new(forward.local_port.to_string()).fg(Color::Green),
                Cell::new(forward.container_port.to_string()).fg(Color::Yellow),
            ]);
        }

        println!("{}", table);
    }

    println!("\nPress Ctrl+C to stop the control server");
}

/// Start the control server on the specified port
pub fn start_control_server(port: u16, status_callback: Option<StatusCallback>) -> Result<()> {
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port))
        .map_err(|e| Error::new(format!("Failed to bind to port {}: {}", port, e)))?;

    info!("Control server listening on 0.0.0.0:{}", port);

    let manager = PortForwardManager::new(status_callback);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let manager_clone = manager.clone();
                thread::spawn(move || {
                    if let Err(e) = handle_agent_connection(stream, manager_clone) {
                        error!("Error handling connection: {}", e);
                    }
                });
            }
            Err(e) => {
                error!("Error accepting connection: {}", e);
            }
        }
    }

    Ok(())
}
