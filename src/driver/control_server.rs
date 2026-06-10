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
use crate::output::OutputFormat;
use devcon_proto::AgentMessage;
use devcon_proto::agent_message::Message as ProtoMessage;
use prost::Message;
use serde_json::json;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use tracing::{debug, error, info, warn};

const MIN_AUTO_HOST_PORT: u16 = 30001;
const HOST_PORT_ALLOCATION_PICK_ATTEMPTS: usize = 128;

fn allocate_host_listener(
    forwards: &HashMap<u16, ForwardEntry>,
    requested_local_port: u16,
    container_port: u16,
) -> Result<(u16, TcpListener)> {
    allocate_host_listener_with_picker(forwards, requested_local_port, container_port, || {
        let start_port = requested_local_port.max(MIN_AUTO_HOST_PORT);
        openport::pick_unused_port(start_port..=u16::MAX)
    })
}

fn allocate_host_listener_with_picker<F>(
    forwards: &HashMap<u16, ForwardEntry>,
    requested_local_port: u16,
    container_port: u16,
    mut picker: F,
) -> Result<(u16, TcpListener)>
where
    F: FnMut() -> Option<u16>,
{
    for _ in 0..HOST_PORT_ALLOCATION_PICK_ATTEMPTS {
        let candidate_port = match picker() {
            Some(port) => port,
            None => continue,
        };

        if candidate_port < MIN_AUTO_HOST_PORT {
            debug!(
                "Host port {} below minimum {}, trying next",
                candidate_port, MIN_AUTO_HOST_PORT
            );
            continue;
        }

        if forwards.contains_key(&candidate_port) {
            debug!(
                "Host port {} already tracked in active forwards map, trying next",
                candidate_port
            );
            continue;
        }

        match TcpListener::bind(format!("0.0.0.0:{}", candidate_port)) {
            Ok(listener) => return Ok((candidate_port, listener)),
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                debug!(
                    "Host port {} already in use on bind, trying next",
                    candidate_port
                );
            }
            Err(e) => {
                return Err(Error::new(format!(
                    "Failed to bind to host port {}: {}",
                    candidate_port, e
                )));
            }
        }
    }

    Err(Error::new(format!(
        "Failed to allocate a host port for container port {} after {} attempts (requested local port: {})",
        container_port, HOST_PORT_ALLOCATION_PICK_ATTEMPTS, requested_local_port
    )))
}

/// Container identification information
#[derive(Debug, Clone)]
struct ContainerInfo {
    container_name: String,
    workspace_name: String,
}

/// Type alias for a port forward entry containing the agent stream, container port, tunnel ID counter, data port, and container info
type ForwardEntry = (
    Arc<Mutex<TcpStream>>,
    u16,
    Arc<AtomicU32>,
    u16,
    Option<ContainerInfo>,
);

type RelayMap = Arc<Mutex<HashMap<u32, Arc<Mutex<UnixStream>>>>>;

/// Manages active port forwarding sessions
#[derive(Clone)]
struct PortForwardManager {
    /// Map of local_port -> (agent_stream, container_port, tunnel_id_counter, data_port, container_info)
    forwards: Arc<Mutex<HashMap<u16, ForwardEntry>>>,
    /// Map of tunnel_id -> pending client stream
    pending_tunnels: Arc<Mutex<HashMap<u32, TcpStream>>>,
    /// Output format for user-facing notifications
    output: OutputFormat,
}

impl PortForwardManager {
    fn new(output: OutputFormat) -> Self {
        Self {
            forwards: Arc::new(Mutex::new(HashMap::new())),
            pending_tunnels: Arc::new(Mutex::new(HashMap::new())),
            output,
        }
    }

    fn output_format(&self) -> OutputFormat {
        self.output.clone()
    }

    /// Start forwarding a port through the control connection
    fn start_forward(
        &self,
        requested_local_port: u16,
        container_port: u16,
        stream: Arc<Mutex<TcpStream>>,
        container_info: Option<ContainerInfo>,
    ) -> Result<u16> {
        let mut forwards = self.forwards.lock().unwrap();
        let (local_port, listener) =
            allocate_host_listener(&forwards, requested_local_port, container_port)?;

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

        drop(forwards);

        Ok(local_port)
    }

    /// Stop forwarding by container port for the current agent connection.
    fn stop_forward(&self, container_port: u16, stream: &Arc<Mutex<TcpStream>>) -> Result<u16> {
        let mut forwards = self.forwards.lock().unwrap();
        let local_port = forwards.iter().find_map(
            |(host_port, (entry_stream, entry_container_port, _, _, _))| {
                if *entry_container_port == container_port && Arc::ptr_eq(entry_stream, stream) {
                    Some(*host_port)
                } else {
                    None
                }
            },
        );

        if let Some(local_port) = local_port {
            let _ = forwards.remove(&local_port);
            drop(forwards);
            info!(
                "Stopped forwarding host port {} for container port {}",
                local_port, container_port
            );
            Ok(local_port)
        } else {
            Err(Error::new(format!(
                "Container port {} is not being forwarded for this agent",
                container_port
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

fn emit_port_forward_event(
    output: &OutputFormat,
    event: &str,
    container_port: u16,
    host_port: u16,
    container_info: Option<&ContainerInfo>,
) {
    match output {
        OutputFormat::Json => {
            let payload = json!({
                "event": event,
                "containerPort": container_port,
                "hostPort": host_port,
                "containerName": container_info.map(|i| i.container_name.clone()),
                "workspaceName": container_info.map(|i| i.workspace_name.clone())
            });
            println!("{}", payload);
        }
        OutputFormat::Text => {
            let action = if event == "started" {
                "started"
            } else {
                "stopped"
            };
            println!(
                "port forward {}: container {} -> host {}",
                action, container_port, host_port
            );
        }
    }
}

fn send_relay_stop(
    stream_arc: &Arc<Mutex<TcpStream>>,
    relay_id: u32,
    error_msg: impl Into<String>,
) {
    let message = AgentMessage {
        message: Some(ProtoMessage::StopSocketRelay(devcon_proto::StopSocketRelay {
            relay_id,
            error: error_msg.into(),
        })),
    };
    if let Ok(mut stream) = stream_arc.lock() {
        let _ = send_message(&mut stream, &message);
    }
}

fn handle_start_socket_relay(
    relay_id: u32,
    socket_name: &str,
    upstream_target: &str,
    stream_arc: Arc<Mutex<TcpStream>>,
    relays: RelayMap,
) {
    let target = upstream_target.trim().to_string();
    if target.is_empty() {
        let msg = format!(
            "StartSocketRelay for '{}' missing upstream target",
            socket_name
        );
        warn!("{}", msg);
        send_relay_stop(&stream_arc, relay_id, msg);
        return;
    }

    let unix_stream = match UnixStream::connect(&target) {
        Ok(stream) => stream,
        Err(e) => {
            let msg = format!("Failed to connect relay target {}: {}", target, e);
            warn!("{}", msg);
            send_relay_stop(&stream_arc, relay_id, msg);
            return;
        }
    };

    let relay_stream = Arc::new(Mutex::new(unix_stream));
    {
        let mut guard = relays.lock().unwrap();
        guard.insert(relay_id, relay_stream.clone());
    }

    let read_stream = {
        let guard = relay_stream.lock().unwrap();
        match guard.try_clone() {
            Ok(stream) => stream,
            Err(e) => {
                let mut relays_guard = relays.lock().unwrap();
                relays_guard.remove(&relay_id);
                let msg = format!("Failed to clone relay stream for {}: {}", target, e);
                warn!("{}", msg);
                send_relay_stop(&stream_arc, relay_id, msg);
                return;
            }
        }
    };

    thread::spawn(move || {
        let mut reader = read_stream;
        let mut buf = vec![0u8; 8192];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => {
                    let mut relays_guard = relays.lock().unwrap();
                    relays_guard.remove(&relay_id);
                    drop(relays_guard);
                    send_relay_stop(&stream_arc, relay_id, "relay upstream closed");
                    break;
                }
                Ok(n) => {
                    let msg = AgentMessage {
                        message: Some(ProtoMessage::SocketRelayData(devcon_proto::SocketRelayData {
                            relay_id,
                            payload: buf[..n].to_vec(),
                            eof: false,
                        })),
                    };
                    let mut stream = match stream_arc.lock() {
                        Ok(stream) => stream,
                        Err(_) => break,
                    };
                    if let Err(e) = send_message(&mut stream, &msg) {
                        warn!("Failed sending relay data for relay {}: {}", relay_id, e);
                        break;
                    }
                }
                Err(e) => {
                    let mut relays_guard = relays.lock().unwrap();
                    relays_guard.remove(&relay_id);
                    drop(relays_guard);
                    send_relay_stop(
                        &stream_arc,
                        relay_id,
                        format!("relay upstream read error: {}", e),
                    );
                    break;
                }
            }
        }
    });
}

fn handle_socket_relay_data(relay_id: u32, payload: &[u8], eof: bool, relays: &RelayMap) {
    let relay = {
        let guard = relays.lock().unwrap();
        guard.get(&relay_id).cloned()
    };

    let Some(relay) = relay else {
        debug!("Ignoring relay data for unknown relay id {}", relay_id);
        return;
    };

    let mut stream = match relay.lock() {
        Ok(stream) => stream,
        Err(_) => return,
    };

    if !payload.is_empty() {
        let _ = stream.write_all(payload);
        let _ = stream.flush();
    }

    if eof {
        let _ = stream.shutdown(std::net::Shutdown::Write);
    }
}

fn handle_stop_socket_relay(relay_id: u32, relays: &RelayMap) {
    let relay = {
        let mut guard = relays.lock().unwrap();
        guard.remove(&relay_id)
    };
    if let Some(relay) = relay
        && let Ok(stream) = relay.lock()
    {
        let _ = stream.shutdown(std::net::Shutdown::Both);
    }
}

/// Handle a single agent connection
fn handle_agent_connection(mut stream: TcpStream, manager: PortForwardManager) -> Result<()> {
    let peer_addr = stream.peer_addr()?;
    info!("New agent connection from {}", peer_addr);
    let output = manager.output_format();

    let stream_arc = Arc::new(Mutex::new(stream.try_clone()?));

    // Use peer address as identifier
    let peer_info = ContainerInfo {
        container_name: peer_addr.ip().to_string(),
        workspace_name: peer_addr.port().to_string(),
    };
    let mut container_info = Some(peer_info);
    let relay_streams: RelayMap = Arc::new(Mutex::new(HashMap::new()));

    loop {
        match read_message(&mut stream) {
            Ok(message) => match message.message {
                Some(ProtoMessage::StartPortForward(fwd)) => {
                    let port = fwd.port as u16;
                    info!("Agent requested port forward: {}", port);

                    match manager.start_forward(
                        port,
                        port,
                        stream_arc.clone(),
                        container_info.clone(),
                    ) {
                        Ok(host_port) => {
                            if host_port != port {
                                info!(
                                    "Allocated host port {} for requested container port {}",
                                    host_port, port
                                );
                            }
                            emit_port_forward_event(
                                &output,
                                "started",
                                port,
                                host_port,
                                container_info.as_ref(),
                            );
                        }
                        Err(e) => {
                            error!("Failed to start port forward: {}", e);
                        }
                    }
                }
                Some(ProtoMessage::StopPortForward(fwd)) => {
                    let port = fwd.port as u16;
                    info!("Agent requested stop port forward: {}", port);

                    match manager.stop_forward(port, &stream_arc) {
                        Ok(host_port) => {
                            emit_port_forward_event(
                                &output,
                                "stopped",
                                port,
                                host_port,
                                container_info.as_ref(),
                            );
                        }
                        Err(e) => {
                            error!("Failed to stop port forward: {}", e);
                        }
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
                Some(ProtoMessage::StartSocketRelay(req)) => {
                    info!(
                        "Starting socket relay id={} socket={} target={}",
                        req.relay_id,
                        req.socket_name,
                        req.upstream_target
                    );
                    handle_start_socket_relay(
                        req.relay_id,
                        &req.socket_name,
                        &req.upstream_target,
                        stream_arc.clone(),
                        relay_streams.clone(),
                    );
                }
                Some(ProtoMessage::SocketRelayData(data)) => {
                    handle_socket_relay_data(
                        data.relay_id,
                        &data.payload,
                        data.eof,
                        &relay_streams,
                    );
                }
                Some(ProtoMessage::StopSocketRelay(stop)) => {
                    if !stop.error.is_empty() {
                        info!(
                            "Stopping socket relay id={} with agent message: {}",
                            stop.relay_id, stop.error
                        );
                    }
                    handle_stop_socket_relay(stop.relay_id, &relay_streams);
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

/// Start the control server on the specified port
pub fn start_control_server(port: u16, output: OutputFormat) -> Result<()> {
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port))
        .map_err(|e| Error::new(format!("Failed to bind to port {}: {}", port, e)))?;

    info!("Control server listening on 0.0.0.0:{}", port);

    let manager = PortForwardManager::new(output);

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

#[cfg(test)]
mod tests {
    use super::*;

    fn stream_pair() -> (Arc<Mutex<TcpStream>>, Arc<Mutex<TcpStream>>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind pair listener");
        let addr = listener.local_addr().expect("get pair listener addr");
        let client = TcpStream::connect(addr).expect("connect pair client");
        let (server, _) = listener.accept().expect("accept pair server");
        (Arc::new(Mutex::new(server)), Arc::new(Mutex::new(client)))
    }

    #[test]
    fn allocate_host_listener_uses_next_port_when_requested_is_busy() {
        let forwards: HashMap<u16, ForwardEntry> = HashMap::new();
        let mut picks = vec![Some(20000), Some(35001)].into_iter();
        let (allocated, _listener) =
            allocate_host_listener_with_picker(&forwards, 3000, 3000, || picks.next().flatten())
                .expect("allocate host listener");

        assert!(
            allocated >= MIN_AUTO_HOST_PORT,
            "allocation should use high host ports"
        );
        assert_eq!(allocated, 35001);
    }

    #[test]
    fn allocate_host_listener_fails_after_picker_exhaustion() {
        let forwards: HashMap<u16, ForwardEntry> = HashMap::new();
        let mut picks = std::iter::repeat_n(None, HOST_PORT_ALLOCATION_PICK_ATTEMPTS + 1);

        let err =
            allocate_host_listener_with_picker(&forwards, 3000, 3000, || picks.next().flatten())
                .expect_err("allocation should fail when picker cannot provide ports");

        assert!(
            err.to_string().contains(&format!(
                "after {} attempts",
                HOST_PORT_ALLOCATION_PICK_ATTEMPTS
            )),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn stop_forward_removes_only_matching_agent_stream() {
        let manager = PortForwardManager::new(OutputFormat::Text);
        let (stream_a_server, stream_a_client) = stream_pair();
        let (stream_b_server, stream_b_client) = stream_pair();
        let counter = Arc::new(AtomicU32::new(1));

        {
            let mut forwards = manager.forwards.lock().expect("lock forwards");
            forwards.insert(
                41000,
                (stream_a_server.clone(), 3000, counter.clone(), 45000, None),
            );
            forwards.insert(42000, (stream_b_server, 3000, counter, 46000, None));
        }

        let stopped = manager
            .stop_forward(3000, &stream_a_server)
            .expect("stop should match stream A");
        assert_eq!(stopped, 41000);

        let forwards = manager.forwards.lock().expect("lock forwards after stop");
        assert!(!forwards.contains_key(&41000));
        assert!(forwards.contains_key(&42000));

        drop(stream_a_client);
        drop(stream_b_client);
    }

}
