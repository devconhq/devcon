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
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::AgentForwardingConfig;
use tracing::{debug, info, warn};

use crate::devcontainer::ForwardPort;
use crate::error::Error;

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

pub(crate) fn is_transient_agent_mount_start_error(error: &Error) -> bool {
    let Error::Runtime(message) = error else {
        return false;
    };

    let lower = message.to_ascii_lowercase();

    let mount_related = lower.contains("error mounting")
        || lower.contains("mount src=")
        || lower.contains(" mount ");
    let agent_related = lower.contains("/ssh-agent")
        || lower.contains("s.gpg-agent")
        || lower.contains("ssh_auth_sock")
        || lower.contains("/run/devcon-agents");
    let missing_or_invalid_source =
        lower.contains("not a directory") || lower.contains("no such file or directory");

    mount_related && agent_related && missing_or_invalid_source
}

/// Returns the path to the stable agent socket directory, creating it if necessary.
///
/// The directory `$HOME/.local/share/devcon/agent-sockets` survives reboots, unlike
/// the ephemeral macOS launchd socket directories. Devcon keeps symlinks inside this
/// directory that point to the current real socket paths, refreshed on every `start`.
pub(crate) fn agent_socket_stable_dir() -> Option<PathBuf> {
    let dir = dirs::home_dir()?.join(".local/share/devcon/agent-sockets");
    if let Err(e) = fs::create_dir_all(&dir) {
        warn!("Failed to create agent socket stable dir {:?}: {}", dir, e);
        return None;
    }
    Some(dir)
}

/// Returns a deterministic forwarding profile key.
///
/// The default profile is shared by all containers that rely on auto-detection.
/// Explicit override paths get an isolated profile key to prevent cross-routing.
pub(crate) fn agent_socket_profile_key(agent_fwd: &AgentForwardingConfig) -> String {
    let ssh = agent_fwd
        .ssh_socket_path
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let gpg = agent_fwd
        .gpg_socket_path
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    match (ssh, gpg) {
        (None, None) => "default".to_string(),
        _ => {
            // Keep the on-disk path compact and filename-safe.
            let fingerprint = format!(
                "ssh={}|gpg={}",
                ssh.unwrap_or("auto"),
                gpg.unwrap_or("auto")
            );
            let digest = sha256::digest(fingerprint.as_bytes());
            format!("override-{}", &digest[..16])
        }
    }
}

/// Returns the stable directory for a forwarding profile.
pub(crate) fn agent_socket_profile_dir(profile_key: &str) -> Option<PathBuf> {
    let base = agent_socket_stable_dir()?;
    let dir = base.join(profile_key);
    if let Err(e) = fs::create_dir_all(&dir) {
        warn!(
            "Failed to create profile agent socket stable dir {:?}: {}",
            dir, e
        );
        return None;
    }
    Some(dir)
}

/// Creates or atomically replaces the symlink `stable_dir/link_name → target`.
///
/// Returns `true` on success. On failure, logs a warning and returns `false` so
/// callers can fall back to a direct socket bind-mount.
pub(crate) fn update_agent_socket_symlink(
    stable_dir: &Path,
    link_name: &str,
    target: &Path,
) -> bool {
    use std::os::unix::fs::symlink;
    let link_path = stable_dir.join(link_name);
    // No-op when the symlink already points to the correct target.
    if fs::read_link(&link_path).is_ok_and(|existing| existing == target) {
        debug!("Agent socket symlink {:?} already up-to-date", link_path);
        return true;
    }
    // Remove any existing file or symlink (ignore ENOENT).
    let _ = fs::remove_file(&link_path);
    match symlink(target, &link_path) {
        Ok(()) => {
            debug!(
                "Updated agent socket symlink {:?} → {:?}",
                link_path, target
            );
            true
        }
        Err(e) => {
            warn!(
                "Failed to create agent socket symlink {:?} → {:?}: {}",
                link_path, target, e
            );
            false
        }
    }
}

/// Writes endpoint metadata for observability and future proxy lifecycle management.
pub(crate) fn write_agent_socket_metadata(
    stable_dir: &Path,
    link_name: &str,
    profile_key: &str,
    target: &Path,
) -> bool {
    let metadata_path = stable_dir.join(format!("{}.meta", link_name));
    let updated = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |dur| dur.as_secs());
    let content = format!(
        "profile={profile}\ntarget={target}\nupdated_unix={updated}\n",
        profile = profile_key,
        target = target.display(),
        updated = updated
    );

    match fs::write(&metadata_path, content) {
        Ok(()) => true,
        Err(e) => {
            warn!(
                "Failed to write agent socket metadata {:?}: {}",
                metadata_path, e
            );
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;

    #[test]
    fn test_is_transient_agent_mount_start_error_matches_stale_ssh_mount() {
        let err =
            Error::Runtime("error mounting: /ssh-agent: no such file or directory".to_string());
        assert!(is_transient_agent_mount_start_error(&err));
    }

    #[test]
    fn test_is_transient_agent_mount_start_error_ignores_unrelated_start_error() {
        let err = Error::Runtime("permission denied opening file".to_string());
        assert!(!is_transient_agent_mount_start_error(&err));
    }

    #[test]
    fn test_is_transient_agent_mount_start_error_matches_stable_dir_missing() {
        let err = Error::Runtime(
            "error mounting: mount src=/run/devcon-agents not a directory".to_string(),
        );
        assert!(is_transient_agent_mount_start_error(&err));
    }

    #[test]
    fn test_update_agent_socket_symlink_creates_new() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.sock");
        std::fs::write(&target, b"").unwrap();

        let stable = tempfile::tempdir().unwrap();
        let result = update_agent_socket_symlink(stable.path(), "ssh-agent", &target);
        assert!(result);
        assert!(stable.path().join("ssh-agent").exists());
    }

    #[test]
    fn test_update_agent_socket_symlink_replaces_stale() {
        let dir = tempfile::tempdir().unwrap();
        let old_target = dir.path().join("old.sock");
        let new_target = dir.path().join("new.sock");
        std::fs::write(&old_target, b"").unwrap();
        std::fs::write(&new_target, b"").unwrap();

        let stable = tempfile::tempdir().unwrap();
        update_agent_socket_symlink(stable.path(), "ssh-agent", &old_target);
        let result = update_agent_socket_symlink(stable.path(), "ssh-agent", &new_target);
        assert!(result);

        let link = std::fs::read_link(stable.path().join("ssh-agent")).unwrap();
        assert_eq!(link, new_target);
    }

    #[test]
    fn test_update_agent_socket_symlink_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.sock");
        std::fs::write(&target, b"").unwrap();

        let stable = tempfile::tempdir().unwrap();
        update_agent_socket_symlink(stable.path(), "ssh-agent", &target);
        let result = update_agent_socket_symlink(stable.path(), "ssh-agent", &target);
        assert!(result);
        let link = std::fs::read_link(stable.path().join("ssh-agent")).unwrap();
        assert_eq!(link, target);
    }

    #[test]
    fn test_agent_socket_profile_key_default_without_overrides() {
        let cfg = AgentForwardingConfig::default();
        assert_eq!(agent_socket_profile_key(&cfg), "default");
    }

    #[test]
    fn test_agent_socket_profile_key_override_is_stable_and_scoped() {
        let cfg_a = AgentForwardingConfig {
            ssh_socket_path: Some("/tmp/ssh-a.sock".to_string()),
            ..Default::default()
        };
        let cfg_b = AgentForwardingConfig {
            ssh_socket_path: Some("/tmp/ssh-a.sock".to_string()),
            ..Default::default()
        };
        let cfg_c = AgentForwardingConfig {
            ssh_socket_path: Some("/tmp/ssh-b.sock".to_string()),
            ..Default::default()
        };

        let a = agent_socket_profile_key(&cfg_a);
        let b = agent_socket_profile_key(&cfg_b);
        let c = agent_socket_profile_key(&cfg_c);

        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(a.starts_with("override-"));
    }

    #[test]
    fn test_agent_socket_profile_dir_is_nested_under_base_stable_dir() {
        let profile = "test-profile";
        let dir = agent_socket_profile_dir(profile).unwrap();
        let base = agent_socket_stable_dir().unwrap();
        assert_eq!(dir, base.join(profile));
        assert!(dir.exists());
    }

    #[test]
    fn test_write_agent_socket_metadata_creates_expected_file() {
        let stable = tempfile::tempdir().unwrap();
        let target = stable.path().join("ssh.sock");
        std::fs::write(&target, b"").unwrap();

        assert!(write_agent_socket_metadata(
            stable.path(),
            "ssh-agent",
            "default",
            &target
        ));

        let metadata = std::fs::read_to_string(stable.path().join("ssh-agent.meta")).unwrap();
        assert!(metadata.contains("profile=default"));
        assert!(metadata.contains(&format!("target={}", target.display())));
        assert!(metadata.contains("updated_unix="));
    }
}

mod sha256 {
    use sha2::{Digest, Sha256};

    pub(crate) fn digest(input: &[u8]) -> String {
        Sha256::digest(input)
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect()
    }
}
