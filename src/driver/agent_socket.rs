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

//! # Agent Socket Helpers
//!
//! Detection and management of forwarded agent sockets (SSH, GPG, GitHub CLI)
//! and related utilities used during container start.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use tracing::{debug, info, warn};

use crate::devcontainer::ForwardPort;

/// Detects the SSH agent socket path from the environment.
///
/// Attempts to find the SSH agent socket using the SSH_AUTH_SOCK environment variable.
/// Validates that the socket file exists on the filesystem.
///
/// # Returns
///
/// Returns `Some(PathBuf)` with the socket path if found and valid, `None` otherwise.
pub(crate) fn detect_ssh_socket() -> Option<PathBuf> {
    let socket_path = std::env::var("SSH_AUTH_SOCK").ok()?;
    let path = PathBuf::from(&socket_path);

    if path.exists() {
        debug!("Detected SSH agent socket at: {}", socket_path);
        Some(path)
    } else {
        warn!(
            "SSH_AUTH_SOCK is set to '{}' but socket does not exist",
            socket_path
        );
        None
    }
}

/// Detects the GPG agent socket path using gpgconf.
///
/// Attempts to find the GPG agent socket by running `gpgconf --list-dir agent-socket`.
/// If the socket doesn't exist but GPG is configured, attempts to start the GPG agent.
/// Validates that the socket file exists on the filesystem.
///
/// # Returns
///
/// Returns `Some(PathBuf)` with the socket path if found and valid, `None` otherwise.
pub(crate) fn detect_gpg_socket() -> Option<PathBuf> {
    let output = std::process::Command::new("gpgconf")
        .arg("--list-dir")
        .arg("agent-socket")
        .output()
        .ok()?;

    if !output.status.success() {
        debug!("gpgconf command failed, GPG agent socket not detected");
        return None;
    }

    let socket_path = String::from_utf8(output.stdout).ok()?;
    let socket_path = socket_path.trim();
    let path = PathBuf::from(socket_path);

    if path.exists() {
        debug!("Detected GPG agent socket at: {}", socket_path);
        return Some(path);
    }

    // Socket doesn't exist - try to start the GPG agent
    debug!(
        "GPG socket not found at {}, attempting to start agent",
        socket_path
    );

    let launch_result = std::process::Command::new("gpgconf")
        .arg("--launch")
        .arg("gpg-agent")
        .status();

    match launch_result {
        Ok(status) if status.success() => {
            info!("Started GPG agent");

            // Wait briefly for socket to appear
            std::thread::sleep(std::time::Duration::from_millis(500));

            if path.exists() {
                info!("GPG agent socket now available at: {}", socket_path);
                return Some(path);
            } else {
                warn!("GPG agent started but socket not found at {}", socket_path);
            }
        }
        Ok(_) => {
            debug!("Failed to start GPG agent (non-zero exit)");
        }
        Err(e) => {
            debug!("Failed to launch GPG agent: {}", e);
        }
    }

    // Final check failed
    warn!("GPG agent socket not available at {}", socket_path);
    None
}

/// Detects the GitHub CLI configuration directory path.
///
/// Attempts to find the GitHub CLI config directory at `~/.config/gh`.
/// Validates that the directory exists and contains a `hosts.yml` file.
///
/// # Returns
///
/// Returns `Some(PathBuf)` with the config directory path if found and valid, `None` otherwise.
pub(crate) fn detect_gh_config() -> Option<PathBuf> {
    let home_dir = std::env::var("HOME").ok()?;
    let gh_config_dir = PathBuf::from(home_dir).join(".config").join("gh");

    if !gh_config_dir.exists() {
        debug!(
            "GitHub CLI config directory not found at {:?}",
            gh_config_dir
        );
        return None;
    }

    // Check if hosts.yml exists (this is where auth tokens are stored)
    let hosts_file = gh_config_dir.join("hosts.yml");
    if !hosts_file.exists() {
        debug!("GitHub CLI hosts.yml not found, may not be authenticated");
        return None;
    }

    debug!("Detected GitHub CLI config at: {:?}", gh_config_dir);
    Some(gh_config_dir)
}

pub(crate) fn extract_container_port(port: &ForwardPort) -> Option<u16> {
    match port {
        ForwardPort::Port(p) => Some(*p),
        ForwardPort::HostPort(mapping) => mapping.split(':').nth(1).and_then(|s| s.parse().ok()),
    }
}

pub(crate) fn ensure_ssh_port_forwarded(ports: &mut Vec<ForwardPort>, ssh_port: u16) {
    let has_ssh = ports
        .iter()
        .filter_map(extract_container_port)
        .any(|container_port| container_port == ssh_port);

    if !has_ssh {
        ports.push(ForwardPort::Port(ssh_port));
    }
}

pub(crate) fn shell_single_quote(input: &str) -> String {
    input.replace('\'', "'\"'\"'")
}

/// Ensures a stable (persistent-path) Unix socket exists that bridges the current
/// ephemeral `ssh_auth_sock` (e.g. macOS `com.apple.launchd.*/Listeners`).
///
/// The stable socket lives at `$XDG_RUNTIME_DIR/devcon/ssh-agent.sock` and can
/// be bind-mounted into containers without the mount source changing across
/// reboots.  A `socat` helper process performs the actual forwarding.
///
/// Returns `Some(stable_path)` on success.  Returns `None` (with a warning) if
/// `socat` is not installed or the socket cannot be created.
pub(crate) fn ensure_stable_ssh_agent_socket(ssh_auth_sock: &Path) -> Option<PathBuf> {
    let dir = dirs::runtime_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("devcon");
    let stable_path = dir.join("ssh-agent.sock");
    let pid_path = dir.join("ssh-socat.pid");

    // Kill any existing socat we spawned previously.
    if let Ok(pid_str) = fs::read_to_string(&pid_path)
        && let Ok(pid) = pid_str.trim().parse::<u32>()
    {
        // best-effort kill; ignore errors (process may already be gone)
        let _ = std::process::Command::new("kill")
            .arg(pid.to_string())
            .output();
        debug!("Sent kill to previous socat pid {}", pid);
    }

    // Remove stale socket file if present.
    let _ = fs::remove_file(&stable_path);

    if let Err(e) = fs::create_dir_all(&dir) {
        warn!("Failed to create SSH agent socket dir {:?}: {}", dir, e);
        return None;
    }

    // Verify socat is available.
    let socat_check = std::process::Command::new("socat")
        .arg("-V")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if socat_check.is_err() || !socat_check.unwrap().success() {
        warn!(
            "socat not found or not executable; SSH agent socket forwarding skipped. \
             Install socat to enable SSH agent forwarding via bind mount."
        );
        return None;
    }

    // Spawn socat as a background process.
    let listen_arg = format!(
        "UNIX-LISTEN:{},fork,reuseaddr",
        stable_path.to_string_lossy()
    );
    let connect_arg = format!("UNIX-CONNECT:{}", ssh_auth_sock.to_string_lossy());

    let child = std::process::Command::new("socat")
        .arg(&listen_arg)
        .arg(&connect_arg)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();

    match child {
        Err(e) => {
            warn!("Failed to spawn socat for SSH agent forwarding: {}", e);
            return None;
        }
        Ok(child) => {
            if let Err(e) = fs::write(&pid_path, child.id().to_string()) {
                warn!("Failed to write socat PID file: {}", e);
            }
            debug!(
                "Spawned socat (pid {}) for SSH agent forwarding",
                child.id()
            );
        }
    }

    // Give socat a moment to create the socket.
    std::thread::sleep(std::time::Duration::from_millis(100));

    if stable_path.exists() {
        info!("Stable SSH agent socket ready at {:?}", stable_path);
        Some(stable_path)
    } else {
        warn!(
            "socat started but stable SSH agent socket {:?} did not appear; \
             SSH agent forwarding skipped",
            stable_path
        );
        None
    }
}

pub(crate) fn detect_public_ssh_key() -> Option<String> {
    if let Ok(value) = std::env::var("DEVCON_SSH_PUBLIC_KEY") {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }

    let home = dirs::home_dir()?;
    let candidates = ["id_ed25519.pub", "id_ecdsa.pub", "id_rsa.pub", "id_dsa.pub"];

    for candidate in candidates {
        let path = home.join(".ssh").join(candidate);
        let content = match fs::read_to_string(&path) {
            Ok(content) => content,
            Err(_) => continue,
        };
        let trimmed = content.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }

    None
}
