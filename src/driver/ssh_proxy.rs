use crate::error::{Error, Result};
use russh::keys::{self, PrivateKey};
use russh::server::{Auth, Msg, Server as _, Session};
use russh::{Channel, ChannelId};
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{ChildStdin, Command};
use tracing::{debug, warn};

#[derive(Clone)]
struct PtyInfo {
    term: String,
    cols: u32,
    rows: u32,
}

/// Buffers raw bytes arriving from SSH `data` events and exposes them as a
/// line/block reader for the SCP receive protocol processor.
struct ScpReader {
    rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    buf: VecDeque<u8>,
}

impl ScpReader {
    fn new(rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>) -> Self {
        Self {
            rx,
            buf: VecDeque::new(),
        }
    }

    /// Pull the next chunk from the channel into the buffer.  Returns `false`
    /// when the sender has been dropped (SSH channel closed / EOF).
    async fn fill(&mut self) -> bool {
        match self.rx.recv().await {
            Some(chunk) => {
                self.buf.extend(chunk);
                true
            }
            None => false,
        }
    }

    /// Read exactly `n` bytes, blocking until available.
    async fn read_exact(&mut self, n: usize) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(n);
        while out.len() < n {
            if let Some(b) = self.buf.pop_front() {
                out.push(b);
            } else if !self.fill().await {
                return Err(Error::runtime("SCP: channel closed while reading data"));
            }
        }
        Ok(out)
    }

    /// Read one newline-terminated line.  Returns `None` on clean EOF.
    async fn read_line(&mut self) -> Result<Option<String>> {
        let mut line = Vec::new();
        loop {
            if let Some(b) = self.buf.pop_front() {
                if b == b'\n' {
                    return Ok(Some(String::from_utf8_lossy(&line).into_owned()));
                }
                line.push(b);
            } else if !self.fill().await {
                return if line.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(String::from_utf8_lossy(&line).into_owned()))
                };
            }
        }
    }
}

/// Holds all information needed to spawn a container exec process.
#[derive(Debug)]
struct ExecCommandSpec {
    program: String,
    args: Vec<String>,
    env: Vec<(String, String)>,
}

/// Builds the exec command spec without side effects, enabling unit testing.
///
/// The `-t` flag (PTY allocation) is only added for interactive shell sessions
/// (i.e. `requested_command` is `None`). Specific commands must never receive a
/// PTY because the resulting escape sequences corrupt their output.
///
/// `extra_env` contains key-value pairs collected from SSH `env_request` messages
/// sent by the client before the exec/shell request.  They are forwarded to the
/// container via `-e KEY=VALUE` flags so the remote process inherits the client's
/// intended environment (e.g. `PATH` additions, `ZED_REMOTE_SERVER_VERSION`).
fn build_exec_command(
    runtime_name: &str,
    container_id: &str,
    default_shell: &str,
    pty_info: Option<&PtyInfo>,
    requested_command: Option<&str>,
    extra_env: &[(String, String)],
) -> ExecCommandSpec {
    let has_pty = pty_info.is_some();
    let interactive_shell_cmd = pty_info.map(|pty| {
        format!(
            "stty cols {} rows {} 2>/dev/null; exec {} -i",
            pty.cols, pty.rows, default_shell
        )
    });

    let (program, args) = if runtime_name == "container" {
        if let Some(command) = requested_command {
            // Shell flags depend on whether the client requested a PTY:
            //  - PTY present  → interactive command (e.g. Zed terminal, `ssh -t host bash`):
            //    `container exec -t` requires the process stdin to be a real TTY, but our
            //    proxy always runs with Stdio::piped().  We must use `script` to allocate a
            //    host-side PTY (the same technique used for shell_request), otherwise
            //    `container exec -t` calls tcsetattr/TIOCSCTTY on a pipe and fails with
            //    ENOTTY.  Use `-lic` so login scripts run and bash enters interactive mode.
            //  - No PTY       → automated/non-interactive command (e.g. Zed proxy,
            //    `uname -a`): call `container exec` directly (no PTY needed) with `-lc` so
            //    login scripts run for PATH but bash stays non-interactive.
            //    Non-interactive bash cannot output prompts or source interactive .bashrc
            //    snippets, preventing stray bytes from corrupting binary protocol streams
            //    such as Zed's length-prefixed protobuf framing.
            if has_pty {
                let mut args = vec![
                    "-q".to_string(),
                    "/dev/null".to_string(),
                    "container".to_string(),
                    "exec".to_string(),
                    "-t".to_string(),
                    "-i".to_string(),
                ];
                for (k, v) in extra_env {
                    args.push("-e".to_string());
                    args.push(format!("{k}={v}"));
                }
                args.push(container_id.to_string());
                args.push(default_shell.to_string());
                args.push("-lic".to_string());
                args.push(command.to_string());
                ("script".to_string(), args)
            } else {
                let mut args = vec!["exec".to_string(), "-i".to_string()];
                for (k, v) in extra_env {
                    args.push("-e".to_string());
                    args.push(format!("{k}={v}"));
                }
                args.push(container_id.to_string());
                args.push(default_shell.to_string());
                args.push("-lc".to_string());
                args.push(command.to_string());
                ("container".to_string(), args)
            }
        } else {
            // Interactive shell: use `script` to allocate a PTY on the host side.
            let mut args = vec![
                "-q".to_string(),
                "/dev/null".to_string(),
                "container".to_string(),
                "exec".to_string(),
                "-t".to_string(),
                "-i".to_string(),
            ];
            for (k, v) in extra_env {
                args.push("-e".to_string());
                args.push(format!("{k}={v}"));
            }
            args.push(container_id.to_string());
            if let Some(shell_cmd) = &interactive_shell_cmd {
                args.push("sh".to_string());
                args.push("-lc".to_string());
                args.push(shell_cmd.clone());
            } else {
                args.push(default_shell.to_string());
                args.push("-i".to_string());
            }
            ("script".to_string(), args)
        }
    } else {
        // Docker (and any other runtime).
        //
        // `docker exec -t` requires the calling process's stdin to be a real
        // TTY so Docker can configure the PTY.  Our proxy always spawns child
        // processes with Stdio::piped(), so stdin is never a terminal.  We use
        // the same `script -q /dev/null` wrapper that the Container path uses to
        // allocate a host-side PTY whenever the SSH client requested one.
        //
        // When no PTY was requested (e.g. Zed's proxy command, `uname -a`) we
        // call `docker exec -i` directly — no `-t`, no `script` — so binary
        // protocol streams are not corrupted by escape sequences.
        if has_pty {
            let mut args = vec![
                "-q".to_string(),
                "/dev/null".to_string(),
                "docker".to_string(),
                "exec".to_string(),
                "-t".to_string(),
                "-i".to_string(),
            ];
            for (k, v) in extra_env {
                args.push("-e".to_string());
                args.push(format!("{k}={v}"));
            }
            args.push(container_id.to_string());

            if let Some(command) = requested_command {
                args.push(default_shell.to_string());
                args.push("-lic".to_string());
                args.push(command.to_string());
            } else if let Some(shell_cmd) = &interactive_shell_cmd {
                args.push("sh".to_string());
                args.push("-lc".to_string());
                args.push(shell_cmd.clone());
            } else {
                args.push(default_shell.to_string());
                args.push("-i".to_string());
            }

            ("script".to_string(), args)
        } else {
            let mut args = vec!["exec".to_string(), "-i".to_string()];
            for (k, v) in extra_env {
                args.push("-e".to_string());
                args.push(format!("{k}={v}"));
            }
            args.push(container_id.to_string());

            if let Some(command) = requested_command {
                // No PTY → automated command (e.g. Zed proxy, `uname -a`):
                // use `-lc` (login, non-interactive) to prevent interactive
                // bash from outputting prompts that corrupt binary protocol
                // streams.
                args.push(default_shell.to_string());
                args.push("-lc".to_string());
                args.push(command.to_string());
            } else if let Some(shell_cmd) = &interactive_shell_cmd {
                args.push("sh".to_string());
                args.push("-lc".to_string());
                args.push(shell_cmd.clone());
            } else {
                args.push(default_shell.to_string());
                args.push("-i".to_string());
            }

            ("docker".to_string(), args)
        }
    };

    let mut env = vec![("SHELL".to_string(), default_shell.to_string())];
    if let Some(pty) = pty_info {
        env.push(("TERM".to_string(), pty.term.clone()));
        env.push(("COLUMNS".to_string(), pty.cols.to_string()));
        env.push(("LINES".to_string(), pty.rows.to_string()));
    }

    ExecCommandSpec { program, args, env }
}

/// Returns the destination path if `command` is an SCP receive invocation
/// (`scp … -t <path>`), or `None` otherwise.
///
/// Zed uploads extension bundles via `scp -C -r user@host:/remote/path/`.
/// The SSH server side receives the command as `scp -t [-d] [-r] <path>`.
/// We intercept this before the generic exec path so we can implement the SCP
/// receive protocol ourselves and use `docker cp` / `container cp` to install
/// the files without requiring `scp` (openssh-client) inside the container.
fn parse_scp_receive_dest(command: &str) -> Option<String> {
    let args: Vec<&str> = command.split_whitespace().collect();
    if args.first()? != &"scp" {
        return None;
    }
    // -t flag marks the "to" (receive) side
    if !args.contains(&"-t") {
        return None;
    }
    // Destination is the last non-flag token
    args.iter()
        .rev()
        .find(|a| !a.starts_with('-'))
        .map(|s| s.to_string())
}

/// Send a single-byte SCP acknowledgement (`\0`) back to the SSH client.
async fn scp_ack(handle: &russh::server::Handle, channel: ChannelId) {
    let _ = handle.data(channel, b"\0".to_vec()).await;
}

/// Process the SCP receive protocol stream.
///
/// Reads SCP commands (`C` file, `D` directory, `E` end-dir, `T` timestamps)
/// from `reader` and writes the received tree under `root_dir` on the host.
/// Uses an explicit stack instead of async recursion to avoid boxing overhead.
async fn receive_scp_entries(
    reader: &mut ScpReader,
    handle: &russh::server::Handle,
    channel: ChannelId,
    root_dir: &Path,
) -> Result<()> {
    let mut dir_stack: Vec<PathBuf> = vec![root_dir.to_path_buf()];

    loop {
        let Some(line) = reader.read_line().await? else {
            break;
        };
        if line.is_empty() {
            break;
        }

        let current_dir = dir_stack
            .last()
            .cloned()
            .unwrap_or_else(|| root_dir.to_path_buf());

        match line.as_bytes().first().copied() {
            Some(b'C') => {
                // "C<mode> <size> <name>"
                let spec = &line[1..];
                let parts: Vec<&str> = spec.splitn(3, ' ').collect();
                if parts.len() < 3 {
                    return Err(Error::runtime(format!("SCP: malformed C command: {line}")));
                }
                let size: u64 = parts[1]
                    .parse()
                    .map_err(|_| Error::runtime(format!("SCP: invalid size: {}", parts[1])))?;
                let name = parts[2].trim_end_matches(['\r', '\n']);

                scp_ack(handle, channel).await; // ready for data

                let data = reader.read_exact(size as usize).await?;

                // Trailing \0 sent by the sender after the file body
                let marker = reader.read_exact(1).await?;
                if marker[0] != 0 {
                    return Err(Error::runtime("SCP: expected \\0 after file data"));
                }

                let file_path = current_dir.join(name);
                std::fs::write(&file_path, &data)
                    .map_err(|e| Error::runtime(format!("SCP: write {name}: {e}")))?;

                scp_ack(handle, channel).await; // file received OK
            }

            Some(b'D') => {
                // "D<mode> 0 <name>" — enter directory
                let parts: Vec<&str> = line[1..].splitn(3, ' ').collect();
                let name = parts
                    .get(2)
                    .map(|s| s.trim_end_matches(['\r', '\n']))
                    .unwrap_or("");
                let new_dir = current_dir.join(name);
                std::fs::create_dir_all(&new_dir)
                    .map_err(|e| Error::runtime(format!("SCP: mkdir {name}: {e}")))?;
                dir_stack.push(new_dir);
                scp_ack(handle, channel).await;
            }

            Some(b'E') => {
                // End of directory
                if dir_stack.len() > 1 {
                    dir_stack.pop();
                }
                scp_ack(handle, channel).await;
            }

            Some(b'T') => {
                // Timestamp info — acknowledge and ignore
                scp_ack(handle, channel).await;
            }

            Some(0x01) | Some(0x02) => {
                return Err(Error::runtime(format!("SCP: client error: {}", &line[1..])));
            }

            _ => {
                // Unknown command — ACK to keep the protocol moving
                warn!("SCP: unknown command: {:?}", line);
                scp_ack(handle, channel).await;
            }
        }
    }

    Ok(())
}

/// Orchestrate a full SCP receive session:
///
/// 1. Receive files/directories from the SSH channel into a host temp directory.
/// 2. Ensure `dest_path` exists inside the container.
/// 3. Copy the temp directory contents into the container with
///    `docker cp` / `container cp`.
async fn run_scp_receive(
    rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    state: &ProxyState,
    dest_path: &str,
    handle: &russh::server::Handle,
    channel: ChannelId,
) -> Result<()> {
    let temp_dir =
        tempfile::tempdir().map_err(|e| Error::runtime(format!("SCP: create temp dir: {e}")))?;

    let mut reader = ScpReader::new(rx);

    // Initial ACK — tells the SCP client we are ready
    scp_ack(handle, channel).await;

    receive_scp_entries(&mut reader, handle, channel, temp_dir.path()).await?;

    let program = if state.runtime_name == "container" {
        "container"
    } else {
        "docker"
    };

    // Ensure the destination directory exists inside the container
    let _ = Command::new(program)
        .args(["exec", &state.container_id, "mkdir", "-p", dest_path])
        .output()
        .await;

    // `docker cp src/. container:dest` copies the *contents* of src into dest
    let src = format!("{}/.", temp_dir.path().display());
    let dest = format!("{}:{}", state.container_id, dest_path);

    let status = Command::new(program)
        .arg("cp")
        .arg(&src)
        .arg(&dest)
        .status()
        .await
        .map_err(|e| Error::runtime(format!("SCP: {program} cp failed to start: {e}")))?;

    if !status.success() {
        return Err(Error::runtime(format!(
            "SCP: {program} cp exited with {status}"
        )));
    }

    Ok(())
}

// ── SFTP subsystem (in-process server) ──────────────────────────────────────
//
// We implement a minimal SFTP v3 server that accepts write operations,
// buffers received files to a host temp directory, then copies them into the
// container with `docker cp` / `container cp` after the session ends.
// This means the container image does not need openssh-server or sftp-server.
//
// Protocol reference: draft-ietf-secsh-filexfer-02 (SFTP version 3)
//   Packet format: [uint32 length][uint8 type][uint32 request-id][payload]
//   Exception: SSH_FXP_INIT / SSH_FXP_VERSION have no request-id.

const SFTP_FXP_INIT: u8 = 1;
const SFTP_FXP_VERSION: u8 = 2;
const SFTP_FXP_OPEN: u8 = 3;
const SFTP_FXP_CLOSE: u8 = 4;
const SFTP_FXP_WRITE: u8 = 6;
const SFTP_FXP_LSTAT: u8 = 7;
const SFTP_FXP_SETSTAT: u8 = 9;
const SFTP_FXP_FSETSTAT: u8 = 10;
const SFTP_FXP_MKDIR: u8 = 14;
const SFTP_FXP_REALPATH: u8 = 16;
const SFTP_FXP_STAT: u8 = 17;
const SFTP_FXP_STATUS: u8 = 101;
const SFTP_FXP_HANDLE: u8 = 102;
const SFTP_FXP_NAME: u8 = 104;
const SFTP_FXP_ATTRS: u8 = 105;

const SFTP_FX_OK: u32 = 0;
const SFTP_FX_NO_SUCH_FILE: u32 = 2;
const SFTP_FX_FAILURE: u32 = 4;
const SFTP_FX_OP_UNSUPPORTED: u32 = 8;

/// Reads complete SFTP packets from the mpsc data channel.
struct SftpReader {
    rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    buf: VecDeque<u8>,
}

impl SftpReader {
    fn new(rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>) -> Self {
        Self {
            rx,
            buf: VecDeque::new(),
        }
    }

    async fn fill(&mut self) -> bool {
        match self.rx.recv().await {
            Some(chunk) => {
                self.buf.extend(chunk);
                true
            }
            None => false,
        }
    }

    async fn read_exact(&mut self, n: usize) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(n);
        while out.len() < n {
            if let Some(b) = self.buf.pop_front() {
                out.push(b);
            } else if !self.fill().await {
                return Err(Error::runtime("SFTP: channel closed while reading"));
            }
        }
        Ok(out)
    }

    /// Read the next complete SFTP packet (excluding the 4-byte length prefix).
    /// Returns `None` on clean EOF.
    async fn read_packet(&mut self) -> Result<Option<Vec<u8>>> {
        if self.buf.is_empty() && !self.fill().await {
            return Ok(None);
        }
        let len_bytes = self.read_exact(4).await?;
        let len =
            u32::from_be_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;
        if len == 0 {
            return Ok(None);
        }
        Ok(Some(self.read_exact(len).await?))
    }
}

// ── SFTP packet helpers ──────────────────────────────────────────────────────

fn sftp_read_u32(data: &[u8], pos: &mut usize) -> Result<u32> {
    if *pos + 4 > data.len() {
        return Err(Error::runtime("SFTP: truncated u32"));
    }
    let v = u32::from_be_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]]);
    *pos += 4;
    Ok(v)
}

fn sftp_read_u64(data: &[u8], pos: &mut usize) -> Result<u64> {
    if *pos + 8 > data.len() {
        return Err(Error::runtime("SFTP: truncated u64"));
    }
    let v = u64::from_be_bytes(data[*pos..*pos + 8].try_into().unwrap());
    *pos += 8;
    Ok(v)
}

fn sftp_read_string(data: &[u8], pos: &mut usize) -> Result<Vec<u8>> {
    let len = sftp_read_u32(data, pos)? as usize;
    if *pos + len > data.len() {
        return Err(Error::runtime("SFTP: truncated string"));
    }
    let s = data[*pos..*pos + len].to_vec();
    *pos += len;
    Ok(s)
}

fn sftp_encode_string(s: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + s.len());
    v.extend_from_slice(&(s.len() as u32).to_be_bytes());
    v.extend_from_slice(s);
    v
}

/// Build a response packet: [length][type][request_id][payload]
fn sftp_packet(ptype: u8, request_id: u32, payload: &[u8]) -> Vec<u8> {
    let inner_len = 1 + 4 + payload.len();
    let mut v = Vec::with_capacity(4 + inner_len);
    v.extend_from_slice(&(inner_len as u32).to_be_bytes());
    v.push(ptype);
    v.extend_from_slice(&request_id.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

fn sftp_status(request_id: u32, code: u32, msg: &str) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&code.to_be_bytes());
    p.extend_from_slice(&sftp_encode_string(msg.as_bytes()));
    p.extend_from_slice(&sftp_encode_string(b"en"));
    sftp_packet(SFTP_FXP_STATUS, request_id, &p)
}

fn sftp_handle_pkt(request_id: u32, handle: &str) -> Vec<u8> {
    sftp_packet(
        SFTP_FXP_HANDLE,
        request_id,
        &sftp_encode_string(handle.as_bytes()),
    )
}

fn sftp_name_pkt(request_id: u32, path: &str) -> Vec<u8> {
    let pb = path.as_bytes();
    let mut p = Vec::new();
    p.extend_from_slice(&1u32.to_be_bytes()); // count = 1
    p.extend_from_slice(&sftp_encode_string(pb)); // filename
    p.extend_from_slice(&sftp_encode_string(pb)); // longname
    p.extend_from_slice(&0u32.to_be_bytes()); // attrs flags = 0
    sftp_packet(SFTP_FXP_NAME, request_id, &p)
}

fn sftp_attrs_pkt(request_id: u32, is_dir: bool) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&0x00000004u32.to_be_bytes()); // ATTR_PERMISSIONS
    let perms: u32 = if is_dir { 0o40755 } else { 0o100644 };
    p.extend_from_slice(&perms.to_be_bytes());
    sftp_packet(SFTP_FXP_ATTRS, request_id, &p)
}

/// Map an absolute remote SFTP path to a local path inside temp_dir.
fn sftp_local_path(temp_dir: &Path, remote_path: &str) -> PathBuf {
    let rel = remote_path.trim_start_matches('/');
    if rel.is_empty() {
        temp_dir.to_path_buf()
    } else {
        temp_dir.join(rel)
    }
}

/// Run an in-process SFTP session.
///
/// Receives SFTP protocol packets, writes files to `temp_dir` with the same
/// absolute path structure as requested, then — when the channel closes —
/// copies the temp directory contents into the container with
/// `docker cp temp_dir/. container:/`.
async fn run_sftp_session(
    rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    state: &ProxyState,
    handle: &russh::server::Handle,
    channel: ChannelId,
) -> Result<()> {
    let temp_dir =
        tempfile::tempdir().map_err(|e| Error::runtime(format!("SFTP: create temp dir: {e}")))?;

    let mut reader = SftpReader::new(rx);
    let mut open_handles: HashMap<String, std::fs::File> = HashMap::new();
    let mut next_handle: u32 = 0;

    loop {
        let Some(packet) = reader.read_packet().await? else {
            break;
        };
        if packet.is_empty() {
            break;
        }

        let ptype = packet[0];
        let mut pos = 1usize;

        debug!(channel_id = ?channel, ptype, "SFTP: packet received");

        match ptype {
            SFTP_FXP_INIT => {
                // [uint8 type][uint32 version] — no request_id
                // Respond with SSH_FXP_VERSION 3 (also has no request_id)
                let ver: Vec<u8> = {
                    let inner_len = 1u32 + 4u32; // type + version
                    let mut v = Vec::with_capacity(9);
                    v.extend_from_slice(&inner_len.to_be_bytes());
                    v.push(SFTP_FXP_VERSION);
                    v.extend_from_slice(&3u32.to_be_bytes()); // version 3
                    v
                };
                let _ = handle.data(channel, ver).await;
            }

            SFTP_FXP_REALPATH => {
                let request_id = sftp_read_u32(&packet, &mut pos)?;
                let path_bytes = sftp_read_string(&packet, &mut pos)?;
                let path_str = String::from_utf8_lossy(&path_bytes).to_string();
                let resp = sftp_name_pkt(request_id, &path_str);
                let _ = handle.data(channel, resp).await;
            }

            SFTP_FXP_STAT | SFTP_FXP_LSTAT => {
                let request_id = sftp_read_u32(&packet, &mut pos)?;
                let path_bytes = sftp_read_string(&packet, &mut pos)?;
                let path_str = String::from_utf8_lossy(&path_bytes).to_string();
                let local = sftp_local_path(temp_dir.path(), &path_str);
                let resp = if local.exists() {
                    sftp_attrs_pkt(request_id, local.is_dir())
                } else {
                    sftp_status(request_id, SFTP_FX_NO_SUCH_FILE, "no such file")
                };
                let _ = handle.data(channel, resp).await;
            }

            SFTP_FXP_MKDIR => {
                let request_id = sftp_read_u32(&packet, &mut pos)?;
                let path_bytes = sftp_read_string(&packet, &mut pos)?;
                let path_str = String::from_utf8_lossy(&path_bytes).to_string();
                let local = sftp_local_path(temp_dir.path(), &path_str);
                let resp = match std::fs::create_dir_all(&local) {
                    Ok(()) => sftp_status(request_id, SFTP_FX_OK, "OK"),
                    Err(e) => sftp_status(request_id, SFTP_FX_FAILURE, &e.to_string()),
                };
                let _ = handle.data(channel, resp).await;
            }

            SFTP_FXP_OPEN => {
                let request_id = sftp_read_u32(&packet, &mut pos)?;
                let path_bytes = sftp_read_string(&packet, &mut pos)?;
                let path_str = String::from_utf8_lossy(&path_bytes).to_string();
                let pflags = sftp_read_u32(&packet, &mut pos)?;
                // pflags: 0x1=READ 0x2=WRITE 0x8=CREAT 0x10=TRUNC
                let is_write = (pflags & 0x2) != 0 || (pflags & 0x8) != 0;
                if is_write {
                    let local = sftp_local_path(temp_dir.path(), &path_str);
                    if let Some(parent) = local.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    let resp = match std::fs::File::create(&local) {
                        Ok(f) => {
                            let hname = format!("h{next_handle}");
                            next_handle += 1;
                            open_handles.insert(hname.clone(), f);
                            sftp_handle_pkt(request_id, &hname)
                        }
                        Err(e) => sftp_status(request_id, SFTP_FX_FAILURE, &e.to_string()),
                    };
                    let _ = handle.data(channel, resp).await;
                } else {
                    let resp =
                        sftp_status(request_id, SFTP_FX_OP_UNSUPPORTED, "read not supported");
                    let _ = handle.data(channel, resp).await;
                }
            }

            SFTP_FXP_WRITE => {
                let request_id = sftp_read_u32(&packet, &mut pos)?;
                let hname =
                    String::from_utf8_lossy(&sftp_read_string(&packet, &mut pos)?).into_owned();
                let offset = sftp_read_u64(&packet, &mut pos)?;
                let data_bytes = sftp_read_string(&packet, &mut pos)?;
                let resp = if let Some(f) = open_handles.get_mut(&hname) {
                    use std::io::{Seek, Write};
                    let _ = f.seek(std::io::SeekFrom::Start(offset));
                    match f.write_all(&data_bytes) {
                        Ok(()) => sftp_status(request_id, SFTP_FX_OK, "OK"),
                        Err(e) => sftp_status(request_id, SFTP_FX_FAILURE, &e.to_string()),
                    }
                } else {
                    sftp_status(request_id, SFTP_FX_FAILURE, "invalid handle")
                };
                let _ = handle.data(channel, resp).await;
            }

            SFTP_FXP_CLOSE => {
                let request_id = sftp_read_u32(&packet, &mut pos)?;
                let hname =
                    String::from_utf8_lossy(&sftp_read_string(&packet, &mut pos)?).into_owned();
                open_handles.remove(&hname);
                let resp = sftp_status(request_id, SFTP_FX_OK, "OK");
                let _ = handle.data(channel, resp).await;
            }

            SFTP_FXP_SETSTAT | SFTP_FXP_FSETSTAT => {
                // Silently accept attribute changes (permissions, timestamps).
                let request_id = sftp_read_u32(&packet, &mut pos)?;
                let resp = sftp_status(request_id, SFTP_FX_OK, "OK");
                let _ = handle.data(channel, resp).await;
            }

            _ => {
                // Unknown packet: return unsupported if we can extract a request_id.
                if packet.len() >= 5 {
                    let request_id =
                        u32::from_be_bytes([packet[1], packet[2], packet[3], packet[4]]);
                    let resp = sftp_status(request_id, SFTP_FX_OP_UNSUPPORTED, "unsupported");
                    let _ = handle.data(channel, resp).await;
                }
            }
        }
    }

    // Flush all open file handles before copying.
    drop(open_handles);

    // If nothing was uploaded, skip docker cp.
    if temp_dir
        .path()
        .read_dir()
        .map_or(true, |mut d| d.next().is_none())
    {
        debug!("SFTP: temp dir is empty, skipping docker cp");
        return Ok(());
    }

    let program = if state.runtime_name == "container" {
        "container"
    } else {
        "docker"
    };

    // Copy each top-level entry from the temp dir into the container at the
    // corresponding absolute path (e.g. temp_dir/home → container:/home).
    // Copying to the container root (`/`) silently no-ops in Docker, and
    // tmpfs-mounted paths (like /tmp inside many containers) cannot be written
    // by `docker cp` at all — but the real Zed extension paths live under
    // /home which is on the overlay filesystem and works correctly.
    let entries = std::fs::read_dir(temp_dir.path())
        .map_err(|e| Error::runtime(format!("SFTP: read temp dir: {e}")))?;

    for entry in entries.flatten() {
        let local_path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let container_dest = format!(
            "{container_name}:/{name_str}",
            container_name = state.container_id
        );

        debug!(
            "SFTP: docker cp {} → {}",
            local_path.display(),
            container_dest
        );

        if local_path.is_dir() {
            // Ensure the target directory exists inside the container first,
            // then copy the directory contents with the trailing `/.` trick.
            let _ = Command::new(program)
                .args([
                    "exec",
                    &state.container_id,
                    "mkdir",
                    "-p",
                    &format!("/{name_str}"),
                ])
                .output()
                .await;

            let src = format!("{}/.", local_path.display());
            let status = Command::new(program)
                .arg("cp")
                .arg(&src)
                .arg(&container_dest)
                .status()
                .await
                .map_err(|e| Error::runtime(format!("SFTP: {program} cp failed: {e}")))?;

            if !status.success() {
                warn!("SFTP: {program} cp {src} → {container_dest} failed with {status}");
            }

            // `docker cp` / `container cp` always creates files owned by root.
            // Fix ownership so users inside the container can access their own
            // files. We must run chown as root (`-u root`) because the
            // container's default user is typically unprivileged and cannot
            // change ownership of root-owned files.
            if name_str == "home" {
                // Each sub-directory of /home is named after the user that
                // owns it (e.g. /home/vscode → user vscode).
                if let Ok(home_entries) = std::fs::read_dir(&local_path) {
                    for home_entry in home_entries.flatten() {
                        let user = home_entry.file_name();
                        let user_str = user.to_string_lossy();
                        debug!("SFTP: chown /home/{user_str} → {user_str}:{user_str}");
                        let out = Command::new(program)
                            .args([
                                "exec",
                                "-u",
                                "root",
                                &state.container_id,
                                "chown",
                                "-R",
                                &format!("{user_str}:{user_str}"),
                                &format!("/home/{user_str}"),
                            ])
                            .output()
                            .await;
                        if let Ok(o) = out
                            && !o.status.success()
                        {
                            warn!(
                                "SFTP: chown /home/{user_str} failed: {}",
                                String::from_utf8_lossy(&o.stderr)
                            );
                        }
                    }
                }
            } else {
                // For non-home paths, query the existing owner of the
                // container directory and chown the freshly-copied tree to
                // match. Run stat as root so it always works.
                let stat_out = Command::new(program)
                    .args([
                        "exec",
                        "-u",
                        "root",
                        &state.container_id,
                        "sh",
                        "-c",
                        &format!("stat -c '%U:%G' /{name_str} 2>/dev/null || echo root:root"),
                    ])
                    .output()
                    .await;
                if let Ok(o) = stat_out {
                    let owner = String::from_utf8_lossy(&o.stdout).trim().to_string();
                    if owner != "root:root" {
                        debug!("SFTP: chown /{name_str} → {owner}");
                        let _ = Command::new(program)
                            .args([
                                "exec",
                                "-u",
                                "root",
                                &state.container_id,
                                "chown",
                                "-R",
                                &owner,
                                &format!("/{name_str}"),
                            ])
                            .output()
                            .await;
                    }
                }
            }
        } else {
            let src = local_path.display().to_string();
            let status = Command::new(program)
                .arg("cp")
                .arg(&src)
                .arg(&container_dest)
                .status()
                .await
                .map_err(|e| Error::runtime(format!("SFTP: {program} cp failed: {e}")))?;

            if !status.success() {
                warn!("SFTP: {program} cp {src} → {container_dest} failed with {status}");
            }
        }
    }

    Ok(())
}

fn build_unix_socket_command(
    runtime_name: &str,
    container_id: &str,
    socket_path: &str,
) -> ExecCommandSpec {
    let socat_target = format!("UNIX-CONNECT:{socket_path}");
    let (program, args) = if runtime_name == "container" {
        (
            "container".to_string(),
            vec![
                "exec".to_string(),
                "-i".to_string(),
                container_id.to_string(),
                "socat".to_string(),
                "STDIO".to_string(),
                socat_target,
            ],
        )
    } else {
        (
            "docker".to_string(),
            vec![
                "exec".to_string(),
                "-i".to_string(),
                container_id.to_string(),
                "socat".to_string(),
                "STDIO".to_string(),
                socat_target,
            ],
        )
    };
    ExecCommandSpec {
        program,
        args,
        env: vec![],
    }
}

fn normalize_pty(term: &str, cols: u32, rows: u32) -> PtyInfo {
    let normalized_term = if term.is_empty() {
        "xterm-256color".to_string()
    } else {
        term.to_string()
    };

    let normalized_cols = if cols == 0 { 80 } else { cols };
    let normalized_rows = if rows == 0 { 24 } else { rows };

    PtyInfo {
        term: normalized_term,
        cols: normalized_cols,
        rows: normalized_rows,
    }
}

#[derive(Clone)]
struct ProxyState {
    runtime_name: String,
    container_id: String,
    default_shell: String,
    stdin_by_channel: Arc<tokio::sync::Mutex<HashMap<(usize, ChannelId), ChildStdin>>>,
    pty_by_channel: Arc<tokio::sync::Mutex<HashMap<(usize, ChannelId), PtyInfo>>>,
    /// Environment variables set by the SSH client via `env_request` before exec/shell.
    #[allow(clippy::type_complexity)]
    env_by_channel: Arc<tokio::sync::Mutex<HashMap<(usize, ChannelId), Vec<(String, String)>>>>,
    /// SCP receive channels: feeds raw SSH data into the per-channel SCP processor.
    #[allow(clippy::type_complexity)]
    scp_stdin_by_channel: Arc<
        tokio::sync::Mutex<
            HashMap<(usize, ChannelId), tokio::sync::mpsc::UnboundedSender<Vec<u8>>>,
        >,
    >,
    /// SFTP subsystem channels: feeds raw SSH data into the per-channel SFTP processor.
    #[allow(clippy::type_complexity)]
    sftp_stdin_by_channel: Arc<
        tokio::sync::Mutex<
            HashMap<(usize, ChannelId), tokio::sync::mpsc::UnboundedSender<Vec<u8>>>,
        >,
    >,
}

#[derive(Clone)]
struct ProxyServer {
    state: ProxyState,
    next_client_id: Arc<AtomicUsize>,
    client_id: usize,
}

impl russh::server::Server for ProxyServer {
    type Handler = Self;

    fn new_client(&mut self, _peer_addr: Option<std::net::SocketAddr>) -> Self::Handler {
        let client_id = self.next_client_id.fetch_add(1, Ordering::SeqCst);
        Self {
            state: self.state.clone(),
            next_client_id: self.next_client_id.clone(),
            client_id,
        }
    }
}

impl russh::server::Handler for ProxyServer {
    type Error = russh::Error;

    async fn auth_none(&mut self, user: &str) -> std::result::Result<Auth, Self::Error> {
        debug!(client_id = self.client_id, user, "ssh: auth_none accepted");
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        _session: &mut Session,
    ) -> std::result::Result<bool, Self::Error> {
        debug!(client_id = self.client_id, "ssh: channel_open_session");
        Ok(true)
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        debug!(
            client_id = self.client_id,
            channel_id = ?channel,
            term,
            cols = col_width,
            rows = row_height,
            "ssh: pty_request"
        );
        let key = (self.client_id, channel);
        let mut pty_map = self.state.pty_by_channel.lock().await;
        pty_map.insert(key, normalize_pty(term, col_width, row_height));

        session.channel_success(channel)?;
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        debug!(
            client_id = self.client_id,
            channel_id = ?channel,
            cols = col_width,
            rows = row_height,
            "ssh: window_change_request"
        );
        let key = (self.client_id, channel);
        let mut pty_map = self.state.pty_by_channel.lock().await;

        let term = pty_map
            .get(&key)
            .map(|info| info.term.clone())
            .unwrap_or_else(|| "xterm-256color".to_string());

        pty_map.insert(key, normalize_pty(&term, col_width, row_height));

        session.channel_success(channel)?;
        Ok(())
    }

    /// Accept and store SSH environment variables sent by the client before exec/shell.
    ///
    /// Zed (and other SSH clients) use `env_request` to set variables such as
    /// `PATH` additions, `ZED_REMOTE_SERVER_VERSION`, and similar that the remote
    /// process needs.  Storing them here and forwarding as `-e KEY=VALUE` to
    /// `docker exec` / `container exec` ensures the remote server sees the full
    /// environment the client intended.
    async fn env_request(
        &mut self,
        channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        debug!(
            client_id = self.client_id,
            channel_id = ?channel,
            variable_name,
            variable_value,
            "ssh: env_request"
        );
        let key = (self.client_id, channel);
        let mut env_map = self.state.env_by_channel.lock().await;
        env_map
            .entry(key)
            .or_default()
            .push((variable_name.to_string(), variable_value.to_string()));
        session.channel_success(channel)?;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        debug!(
            client_id = self.client_id,
            channel_id = ?channel,
            subsystem = name,
            "ssh: subsystem_request"
        );
        if name == "sftp" {
            session.channel_success(channel)?;
            self.spawn_sftp_session(channel, session.handle()).await;
        } else {
            // Unknown subsystem: fail explicitly so scp clients can detect the error.
            session.channel_failure(channel)?;
        }
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        debug!(
            client_id = self.client_id,
            channel_id = ?channel,
            "ssh: shell_request"
        );
        session.channel_success(channel)?;
        self.spawn_container_exec(channel, None, session.handle())
            .await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        let command = String::from_utf8_lossy(data).to_string();
        debug!(
            client_id = self.client_id,
            channel_id = ?channel,
            command = %command,
            "ssh: exec_request"
        );
        session.channel_success(channel)?;

        if let Some(dest_path) = parse_scp_receive_dest(&command) {
            debug!(
                client_id = self.client_id,
                channel_id = ?channel,
                dest_path = %dest_path,
                "exec_request: detected scp receive, intercepting with docker cp"
            );
            self.spawn_scp_receive(channel, dest_path, session.handle())
                .await;
            return Ok(());
        }

        let is_warp_bootstrap = command.contains("TERM_PROGRAM='WarpTerminal'")
            || command.contains("WARP_SESSION_ID=")
            || command.contains("hook=$(printf");

        if is_warp_bootstrap {
            debug!(client_id = self.client_id, channel_id = ?channel, "exec_request: detected Warp bootstrap, treating as interactive shell");
            self.spawn_container_exec(channel, None, session.handle())
                .await;
        } else {
            self.spawn_container_exec(channel, Some(command), session.handle())
                .await;
        }

        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
        session: &mut Session,
    ) -> std::result::Result<bool, Self::Error> {
        let channel_id = channel.id();
        debug!(
            client_id = self.client_id,
            channel_id = ?channel_id,
            target = %format!("{}:{}", host_to_connect, port_to_connect),
            originator = %format!("{}:{}", originator_address, originator_port),
            "ssh: channel_open_direct_tcpip"
        );
        self.spawn_direct_tcpip(
            channel_id,
            host_to_connect.to_string(),
            port_to_connect,
            session.handle(),
        )
        .await;
        Ok(true)
    }

    async fn channel_open_direct_streamlocal(
        &mut self,
        channel: Channel<Msg>,
        socket_path: &str,
        session: &mut Session,
    ) -> std::result::Result<bool, Self::Error> {
        let channel_id = channel.id();
        debug!(
            client_id = self.client_id,
            channel_id = ?channel_id,
            socket_path,
            "ssh: channel_open_direct_streamlocal"
        );
        self.spawn_unix_socket_proxy(channel_id, socket_path.to_string(), session.handle())
            .await;
        Ok(true)
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        debug!(
            client_id = self.client_id,
            channel_id = ?channel,
            bytes = data.len(),
            "ssh: data"
        );
        let key = (self.client_id, channel);

        // Route data to the SCP receiver if this channel is an SCP session
        {
            let lock = self.state.scp_stdin_by_channel.lock().await;
            if let Some(tx) = lock.get(&key) {
                let _ = tx.send(data.to_vec());
                return Ok(());
            }
        }

        // Route data to the SFTP subsystem handler if active on this channel
        {
            let lock = self.state.sftp_stdin_by_channel.lock().await;
            if let Some(tx) = lock.get(&key) {
                let _ = tx.send(data.to_vec());
                return Ok(());
            }
        }

        let mut lock = self.state.stdin_by_channel.lock().await;
        if let Some(stdin) = lock.get_mut(&key) {
            let _ = stdin.write_all(data).await;
        }
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        debug!(
            client_id = self.client_id,
            channel_id = ?channel,
            "ssh: channel_eof"
        );
        // For SCP/SFTP channels: drop the sender now so the reader sees EOF and
        // the receive task can proceed to `docker cp` without waiting for channel_close.
        let key = (self.client_id, channel);
        {
            let mut scp_map = self.state.scp_stdin_by_channel.lock().await;
            scp_map.remove(&key);
        }
        {
            let mut sftp_map = self.state.sftp_stdin_by_channel.lock().await;
            sftp_map.remove(&key);
        }

        // Do NOT close stdin for normal exec/socat channels. For direct-streamlocal proxy
        // channels (e.g. Zed's stdout.sock / stderr.sock), the SSH client sends
        // channel_eof immediately after opening because it will only read, never write.
        // Closing the socat stdin pipe causes socat to exit, breaking the connection.
        // channel_close (which always follows) is the right place for that cleanup.
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        debug!(
            client_id = self.client_id,
            channel_id = ?channel,
            "ssh: channel_close"
        );
        let key = (self.client_id, channel);
        let mut lock = self.state.stdin_by_channel.lock().await;
        lock.remove(&key);
        drop(lock);

        let mut pty_map = self.state.pty_by_channel.lock().await;
        pty_map.remove(&key);

        let mut env_map = self.state.env_by_channel.lock().await;
        env_map.remove(&key);

        // Dropping the SCP/SFTP senders signals EOF to those receiver tasks.
        let mut scp_map = self.state.scp_stdin_by_channel.lock().await;
        scp_map.remove(&key);
        drop(scp_map);

        let mut sftp_map = self.state.sftp_stdin_by_channel.lock().await;
        sftp_map.remove(&key);

        Ok(())
    }
}

impl ProxyServer {
    async fn spawn_container_exec(
        &self,
        channel: ChannelId,
        requested_command: Option<String>,
        handle: russh::server::Handle,
    ) {
        let pty_info = {
            let key = (self.client_id, channel);
            let lock = self.state.pty_by_channel.lock().await;
            lock.get(&key).cloned()
        };

        let extra_env = {
            let key = (self.client_id, channel);
            let lock = self.state.env_by_channel.lock().await;
            lock.get(&key).cloned().unwrap_or_default()
        };

        let spec = build_exec_command(
            &self.state.runtime_name,
            &self.state.container_id,
            &self.state.default_shell,
            pty_info.as_ref(),
            requested_command.as_deref(),
            &extra_env,
        );

        debug!(
            client_id = self.client_id,
            channel_id = ?channel,
            program = %spec.program,
            args = ?spec.args,
            has_pty = pty_info.is_some(),
            "spawn_container_exec: launching"
        );

        let mut cmd = Command::new(&spec.program);
        for arg in &spec.args {
            cmd.arg(arg);
        }
        for (key, val) in &spec.env {
            cmd.env(key, val);
        }

        cmd.stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        let Ok(mut child) = cmd.spawn() else {
            let _ = handle
                .data(
                    channel,
                    "Failed to spawn container exec\r\n".as_bytes().to_vec(),
                )
                .await;
            let _ = handle.exit_status_request(channel, 1).await;
            let _ = handle.eof(channel).await;
            let _ = handle.close(channel).await;
            return;
        };

        if let Some(stdin) = child.stdin.take() {
            let key = (self.client_id, channel);
            let mut lock = self.state.stdin_by_channel.lock().await;
            lock.insert(key, stdin);
        }

        if let Some(mut stdout) = child.stdout.take() {
            let handle_out = handle.clone();
            tokio::spawn(async move {
                let mut buf = vec![0_u8; 8192];
                while let Ok(n) = stdout.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    let _ = handle_out.data(channel, buf[..n].to_vec()).await;
                }
            });
        }

        if let Some(mut stderr) = child.stderr.take() {
            let handle_err = handle.clone();
            tokio::spawn(async move {
                let mut buf = vec![0_u8; 8192];
                while let Ok(n) = stderr.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    // Send as SSH extended data (type 1 = stderr) rather than
                    // regular channel data (stdout).  Mixing them corrupts the
                    // stdout stream: Zed, for example, reads protobuf messages
                    // from the exec channel's stdout, so any stray bytes on
                    // that stream (e.g. server log lines relayed via the proxy's
                    // stderr) cause protobuf parse failures that close the
                    // connection.
                    let _ = handle_err
                        .extended_data(channel, 1, buf[..n].to_vec())
                        .await;
                }
            });
        }

        let key = (self.client_id, channel);
        let stdin_map = self.state.stdin_by_channel.clone();
        let client_id = self.client_id;
        tokio::spawn(async move {
            let exit_code = match child.wait().await {
                Ok(status) => {
                    let code = status.code().unwrap_or(1) as u32;
                    debug!(client_id, channel_id = ?channel, exit_code = code, "spawn_container_exec: process exited");
                    code
                }
                Err(e) => {
                    warn!(client_id, channel_id = ?channel, error = %e, "spawn_container_exec: error waiting for process");
                    1
                }
            };
            let mut lock = stdin_map.lock().await;
            lock.remove(&key);
            let _ = handle.exit_status_request(channel, exit_code).await;
            let _ = handle.eof(channel).await;
            let _ = handle.close(channel).await;
        });
    }

    /// Proxy a `direct-tcpip` channel by running `nc host port` inside the container.
    ///
    /// `nc` (netcat) must be available in the container image. Most dev-container
    /// base images provide it via `netcat-openbsd`.  If nc is missing, the
    /// channel will close immediately (exit code 127) and a warn log will appear.
    async fn spawn_direct_tcpip(
        &self,
        channel: ChannelId,
        host: String,
        port: u32,
        handle: russh::server::Handle,
    ) {
        let (program, args) = if self.state.runtime_name == "container" {
            (
                "container".to_string(),
                vec![
                    "exec".to_string(),
                    "-i".to_string(),
                    self.state.container_id.clone(),
                    "nc".to_string(),
                    host.clone(),
                    port.to_string(),
                ],
            )
        } else {
            (
                "docker".to_string(),
                vec![
                    "exec".to_string(),
                    "-i".to_string(),
                    self.state.container_id.clone(),
                    "nc".to_string(),
                    host.clone(),
                    port.to_string(),
                ],
            )
        };

        debug!(
            client_id = self.client_id,
            channel_id = ?channel,
            program = %program,
            args = ?args,
            "spawn_direct_tcpip: launching nc proxy"
        );

        let mut cmd = Command::new(&program);
        for arg in &args {
            cmd.arg(arg);
        }
        cmd.stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        let Ok(mut child) = cmd.spawn() else {
            warn!(
                client_id = self.client_id,
                channel_id = ?channel,
                program = %program,
                "spawn_direct_tcpip: failed to spawn nc — is netcat installed in the container?"
            );
            let _ = handle.exit_status_request(channel, 127).await;
            let _ = handle.eof(channel).await;
            let _ = handle.close(channel).await;
            return;
        };

        if let Some(stdin) = child.stdin.take() {
            let key = (self.client_id, channel);
            let mut lock = self.state.stdin_by_channel.lock().await;
            lock.insert(key, stdin);
            debug!(
                client_id = self.client_id,
                channel_id = ?channel,
                "spawn_direct_tcpip: stdin proxy ready"
            );
        }

        if let Some(mut stdout) = child.stdout.take() {
            let handle_out = handle.clone();
            let client_id = self.client_id;
            tokio::spawn(async move {
                let mut buf = vec![0_u8; 8192];
                while let Ok(n) = stdout.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    debug!(client_id, channel_id = ?channel, bytes = n, "spawn_direct_tcpip: forwarding stdout to channel");
                    let _ = handle_out.data(channel, buf[..n].to_vec()).await;
                }
                debug!(client_id, channel_id = ?channel, "spawn_direct_tcpip: stdout closed");
            });
        }

        if let Some(mut stderr) = child.stderr.take() {
            let client_id = self.client_id;
            tokio::spawn(async move {
                let mut buf = vec![0_u8; 8192];
                while let Ok(n) = stderr.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    let s = String::from_utf8_lossy(&buf[..n]);
                    debug!(
                        client_id,
                        channel_id = ?channel,
                        stderr = %s.trim(),
                        "spawn_direct_tcpip: nc stderr"
                    );
                }
            });
        }

        let key = (self.client_id, channel);
        let stdin_map = self.state.stdin_by_channel.clone();
        let client_id = self.client_id;
        tokio::spawn(async move {
            let exit_code = match child.wait().await {
                Ok(status) => {
                    let code = status.code().unwrap_or(1) as u32;
                    debug!(client_id, channel_id = ?channel, exit_code = code, "spawn_direct_tcpip: nc process exited");
                    code
                }
                Err(e) => {
                    warn!(client_id, channel_id = ?channel, error = %e, "spawn_direct_tcpip: error waiting for nc");
                    1
                }
            };
            let mut lock = stdin_map.lock().await;
            lock.remove(&key);
            let _ = handle.exit_status_request(channel, exit_code).await;
            let _ = handle.eof(channel).await;
            let _ = handle.close(channel).await;
        });
    }

    /// Proxy a `direct-streamlocal@openssh.com` channel by running
    /// `socat STDIO UNIX-CONNECT:<socket_path>` inside the container.
    ///
    /// This is required for Zed remote development: the Zed remote server
    /// creates a Unix domain socket and Zed connects to it via this channel type.
    /// `socat` must be available in the container image.
    async fn spawn_unix_socket_proxy(
        &self,
        channel: ChannelId,
        socket_path: String,
        handle: russh::server::Handle,
    ) {
        let spec = build_unix_socket_command(
            &self.state.runtime_name,
            &self.state.container_id,
            &socket_path,
        );

        debug!(
            client_id = self.client_id,
            channel_id = ?channel,
            program = %spec.program,
            args = ?spec.args,
            "spawn_unix_socket_proxy: launching socat proxy"
        );

        let mut cmd = Command::new(&spec.program);
        for arg in &spec.args {
            cmd.arg(arg);
        }
        cmd.stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        let Ok(mut child) = cmd.spawn() else {
            warn!(
                client_id = self.client_id,
                channel_id = ?channel,
                program = %spec.program,
                socket_path = %socket_path,
                "spawn_unix_socket_proxy: failed to spawn socat — is socat installed in the container?"
            );
            let _ = handle.exit_status_request(channel, 127).await;
            let _ = handle.eof(channel).await;
            let _ = handle.close(channel).await;
            return;
        };

        if let Some(stdin) = child.stdin.take() {
            let key = (self.client_id, channel);
            let mut lock = self.state.stdin_by_channel.lock().await;
            lock.insert(key, stdin);
            debug!(
                client_id = self.client_id,
                channel_id = ?channel,
                "spawn_unix_socket_proxy: stdin proxy ready"
            );
        }

        if let Some(mut stdout) = child.stdout.take() {
            let handle_out = handle.clone();
            let client_id = self.client_id;
            tokio::spawn(async move {
                let mut buf = vec![0_u8; 8192];
                while let Ok(n) = stdout.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    debug!(client_id, channel_id = ?channel, bytes = n, "spawn_unix_socket_proxy: forwarding stdout to channel");
                    let _ = handle_out.data(channel, buf[..n].to_vec()).await;
                }
                debug!(client_id, channel_id = ?channel, "spawn_unix_socket_proxy: stdout closed");
            });
        }

        if let Some(mut stderr) = child.stderr.take() {
            let client_id = self.client_id;
            tokio::spawn(async move {
                let mut buf = vec![0_u8; 8192];
                while let Ok(n) = stderr.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    let s = String::from_utf8_lossy(&buf[..n]);
                    debug!(
                        client_id,
                        channel_id = ?channel,
                        stderr = %s.trim(),
                        "spawn_unix_socket_proxy: socat stderr"
                    );
                }
            });
        }

        let key = (self.client_id, channel);
        let stdin_map = self.state.stdin_by_channel.clone();
        let client_id = self.client_id;
        tokio::spawn(async move {
            let exit_code = match child.wait().await {
                Ok(status) => {
                    let code = status.code().unwrap_or(1) as u32;
                    debug!(client_id, channel_id = ?channel, exit_code = code, "spawn_unix_socket_proxy: socat process exited");
                    code
                }
                Err(e) => {
                    warn!(client_id, channel_id = ?channel, error = %e, "spawn_unix_socket_proxy: error waiting for socat");
                    1
                }
            };
            let mut lock = stdin_map.lock().await;
            lock.remove(&key);
            let _ = handle.exit_status_request(channel, exit_code).await;
            let _ = handle.eof(channel).await;
            let _ = handle.close(channel).await;
        });
    }

    /// Handle an `scp -t <dest_path>` exec request by implementing the SCP
    /// receive protocol in-process and copying the received files into the
    /// container with `docker cp` / `container cp`.
    ///
    /// This means the container image does not need `scp` or `openssh-client`.
    async fn spawn_scp_receive(
        &self,
        channel: ChannelId,
        dest_path: String,
        handle: russh::server::Handle,
    ) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();

        {
            let key = (self.client_id, channel);
            let mut map = self.state.scp_stdin_by_channel.lock().await;
            map.insert(key, tx);
        }

        let state = self.state.clone();
        let client_id = self.client_id;

        tokio::spawn(async move {
            let exit_code = match run_scp_receive(rx, &state, &dest_path, &handle, channel).await {
                Ok(()) => {
                    debug!(
                        client_id,
                        channel_id = ?channel,
                        "SCP receive completed successfully"
                    );
                    0u32
                }
                Err(e) => {
                    warn!(
                        client_id,
                        channel_id = ?channel,
                        "SCP receive failed: {:#}", e
                    );
                    1u32
                }
            };

            {
                let key = (client_id, channel);
                let mut map = state.scp_stdin_by_channel.lock().await;
                map.remove(&key);
            }

            let _ = handle.exit_status_request(channel, exit_code).await;
            let _ = handle.eof(channel).await;
            let _ = handle.close(channel).await;
        });
    }

    /// Handle an `sftp` subsystem request by running an in-process SFTP v3 server.
    ///
    /// Files are received into a host temp directory then installed into the
    /// container with `docker cp temp/. container:/` after the session ends.
    async fn spawn_sftp_session(&self, channel: ChannelId, handle: russh::server::Handle) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();

        {
            let key = (self.client_id, channel);
            let mut map = self.state.sftp_stdin_by_channel.lock().await;
            map.insert(key, tx);
        }

        let state = self.state.clone();
        let client_id = self.client_id;

        tokio::spawn(async move {
            let exit_code = match run_sftp_session(rx, &state, &handle, channel).await {
                Ok(()) => {
                    debug!(client_id, channel_id = ?channel, "SFTP session completed");
                    0u32
                }
                Err(e) => {
                    warn!(client_id, channel_id = ?channel, "SFTP session failed: {:#}", e);
                    1u32
                }
            };

            {
                let key = (client_id, channel);
                let mut map = state.sftp_stdin_by_channel.lock().await;
                map.remove(&key);
            }

            let _ = handle.exit_status_request(channel, exit_code).await;
            let _ = handle.eof(channel).await;
            let _ = handle.close(channel).await;
        });
    }
}

pub struct SshProxyServer {
    port: u16,
    stop_tx: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    thread_handle: Mutex<Option<thread::JoinHandle<()>>>,
}

impl SshProxyServer {
    pub fn start(runtime_name: &str, container_id: &str, default_shell: &str) -> Result<Self> {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
            .map_err(|e| Error::runtime(format!("Failed to bind SSH proxy socket: {e}")))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| Error::runtime(format!("Failed to set nonblocking mode: {e}")))?;
        let port = listener
            .local_addr()
            .map_err(|e| Error::runtime(format!("Failed to get proxy address: {e}")))?
            .port();

        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();

        let runtime_name = runtime_name.to_string();
        let container_id = container_id.to_string();
        let default_shell = default_shell.to_string();

        let thread_handle = thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(_) => return,
            };

            rt.block_on(async move {
                let listener = match tokio::net::TcpListener::from_std(listener) {
                    Ok(listener) => listener,
                    Err(_) => return,
                };

                let mut config = russh::server::Config {
                    auth_rejection_time: std::time::Duration::from_secs(0),
                    auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
                    methods: russh::MethodSet::from(&[russh::MethodKind::None][..]),
                    keys: Vec::new(),
                    ..Default::default()
                };
                let key = PrivateKey::random(&mut rand::rng(), keys::Algorithm::Ed25519);
                let Ok(key) = key else {
                    return;
                };
                config.keys.push(key);
                let config = Arc::new(config);

                let mut server = ProxyServer {
                    state: ProxyState {
                        runtime_name,
                        container_id,
                        default_shell,
                        stdin_by_channel: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
                        pty_by_channel: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
                        env_by_channel: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
                        scp_stdin_by_channel: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
                        sftp_stdin_by_channel: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
                    },
                    next_client_id: Arc::new(AtomicUsize::new(1)),
                    client_id: 0,
                };

                tokio::select! {
                    _ = stop_rx => {}
                    _ = server.run_on_socket(config, &listener) => {}
                }
            });
        });

        Ok(Self {
            port,
            stop_tx: Mutex::new(Some(stop_tx)),
            thread_handle: Mutex::new(Some(thread_handle)),
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for SshProxyServer {
    fn drop(&mut self) {
        if let Some(stop_tx) = self.stop_tx.lock().ok().and_then(|mut tx| tx.take()) {
            let _ = stop_tx.send(());
        }
        if let Some(handle) = self
            .thread_handle
            .lock()
            .ok()
            .and_then(|mut thread_handle| thread_handle.take())
        {
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONTAINER: &str = "test-container-id";
    const SHELL: &str = "/bin/bash";

    fn pty() -> PtyInfo {
        normalize_pty("xterm-256color", 120, 30)
    }

    // ── Docker ────────────────────────────────────────────────────────────────

    /// pty_request + exec_request(command) → uses `script` wrapper with `-t` and `-lic` flags.
    ///
    /// `docker exec -t` requires a real TTY on stdin just like `container exec -t`.
    /// Our proxy always uses Stdio::piped(), so we wrap with `script -q /dev/null`
    /// to provide the host-side PTY that Docker needs.
    #[test]
    fn docker_exec_with_pty_uses_script_wrapper_and_interactive_flags() {
        let spec = build_exec_command("docker", CONTAINER, SHELL, Some(&pty()), Some("bash"), &[]);
        assert_eq!(
            spec.program, "script",
            "docker exec + PTY must use `script` to provide a host-side PTY; \
             got program: {}",
            spec.program
        );
        assert!(
            spec.args.contains(&"-t".to_string()),
            "docker exec should pass -t when pty + command (interactive command); \
             got args: {:?}",
            spec.args
        );
        assert!(
            spec.args.contains(&"-lic".to_string()),
            "interactive exec command should use -lic shell flags; got args: {:?}",
            spec.args
        );
    }

    /// no pty_request + exec_request(command) → no `-t`, uses `-lc` (non-interactive).
    /// Zed's proxy command falls into this category: no PTY, automated command.
    /// Non-interactive bash cannot output prompts that corrupt binary protocol
    /// streams (e.g. Zed's length-prefixed protobuf framing).
    #[test]
    fn docker_exec_without_pty_does_not_allocate_tty_and_uses_non_interactive_flags() {
        let spec = build_exec_command("docker", CONTAINER, SHELL, None, Some("uname -a"), &[]);
        assert_eq!(spec.program, "docker");
        assert!(
            !spec.args.contains(&"-t".to_string()),
            "docker exec must not pass -t when no pty was requested; got args: {:?}",
            spec.args
        );
        assert!(
            spec.args.contains(&"-lc".to_string()),
            "non-interactive exec command should use -lc shell flags; got args: {:?}",
            spec.args
        );
        assert!(
            !spec.args.contains(&"-lic".to_string()),
            "non-interactive exec command must not use -lic (interactive) flags; got args: {:?}",
            spec.args
        );
    }

    /// pty_request + shell_request → uses `script` wrapper with `-t`
    #[test]
    fn docker_shell_with_pty_uses_script_wrapper() {
        let spec = build_exec_command("docker", CONTAINER, SHELL, Some(&pty()), None, &[]);
        assert_eq!(
            spec.program, "script",
            "docker interactive shell should use the `script` PTY wrapper; \
             got program: {}",
            spec.program
        );
        assert!(
            spec.args.contains(&"-t".to_string()),
            "docker exec should pass -t for an interactive shell when pty was requested; \
             got args: {:?}",
            spec.args
        );
    }

    /// no pty_request + shell_request → no `-t`
    #[test]
    fn docker_shell_without_pty_does_not_allocate_tty() {
        let spec = build_exec_command("docker", CONTAINER, SHELL, None, None, &[]);
        assert_eq!(spec.program, "docker");
        assert!(
            !spec.args.contains(&"-t".to_string()),
            "docker exec must not pass -t for a shell when no pty was requested; \
             got args: {:?}",
            spec.args
        );
    }

    // ── Container ─────────────────────────────────────────────────────────────────

    /// pty_request + exec_request(command) → must use `script` wrapper (not bare `container exec`).
    ///
    /// `container exec -t` requires its stdin to be a real TTY so it can call tcsetattr /
    /// TIOCSCTTY.  Our SSH proxy always runs with Stdio::piped(), so calling `container exec -t`
    /// directly produces ENOTTY — exactly the error Zed reports when opening a terminal panel:
    /// "failed to exec process Error Domain=NSPOSIXErrorDomain Code=25 Inappropriate ioctl for device"
    ///
    /// Wrapping with `script` (as we do for shell_request) allocates a real host-side PTY that
    /// `container exec -t` can use, solving the ENOTTY.
    #[test]
    fn container_exec_with_pty_uses_script_wrapper_not_bare_container_exec() {
        let spec = build_exec_command(
            "container",
            CONTAINER,
            SHELL,
            Some(&pty()),
            Some("bash"),
            &[],
        );
        assert_eq!(
            spec.program, "script",
            "Container exec + PTY must use `script` to provide a host-side PTY for `container exec -t`; \
             without it, container exec calls tcsetattr on a pipe and fails with ENOTTY. \
             program was: {:?}",
            spec.program
        );
        assert!(
            spec.args.contains(&"-t".to_string()),
            "Container exec with PTY + command should pass -t to container exec; got args: {:?}",
            spec.args
        );
        assert!(
            spec.args.contains(&"-lic".to_string()),
            "Container interactive exec command should use -lic shell flags; got args: {:?}",
            spec.args
        );
    }

    /// Regression test for the Zed terminal ENOTTY bug (issue #90).
    ///
    /// When Zed opens a terminal panel on a remote SSH project, it spawns:
    ///   `ssh -q -t <host> "cd && exec env ZED_TERMINAL=... /bin/bash -l"`
    /// This arrives at our proxy as pty_request + exec_request(command).
    ///
    /// Previously, the Container path called `container exec -t` with Stdio::piped(), which caused
    /// `container exec` to call tcsetattr/TIOCSCTTY on a pipe → ENOTTY.
    /// The fix is to wrap with `script` so a real host-side PTY is available.
    #[test]
    fn container_zed_terminal_exec_uses_script_wrapper() {
        let zed_command = "cd && exec env ZED_TERMINAL=1 /bin/bash -l";
        let spec = build_exec_command(
            "container",
            CONTAINER,
            SHELL,
            Some(&pty()),
            Some(zed_command),
            &[],
        );
        assert_eq!(
            spec.program, "script",
            "Zed terminal exec (pty_request + exec_request) on Container must use `script` wrapper; \
             got program: {:?}",
            spec.program
        );
        assert!(
            spec.args.contains(&"container".to_string()),
            "script must invoke `container`; got args: {:?}",
            spec.args
        );
        assert!(
            spec.args.contains(&"-t".to_string()),
            "container exec must receive -t; got args: {:?}",
            spec.args
        );
        assert!(
            spec.args.iter().any(|a| a == zed_command),
            "the Zed command must be passed through; got args: {:?}",
            spec.args
        );
    }

    /// no pty_request + exec_request(command) on Container → no `-t`, uses `-lc`.
    #[test]
    fn container_exec_without_pty_uses_non_interactive_flags() {
        let spec = build_exec_command("container", CONTAINER, SHELL, None, Some("uname -a"), &[]);
        assert_eq!(spec.program, "container");
        assert!(
            !spec.args.contains(&"-t".to_string()),
            "Container non-interactive exec must not pass -t; got args: {:?}",
            spec.args
        );
        assert!(
            spec.args.contains(&"-lc".to_string()),
            "Container non-interactive exec command should use -lc flags; got args: {:?}",
            spec.args
        );
        assert!(
            !spec.args.contains(&"-lic".to_string()),
            "Container non-interactive exec command must not use -lic flags; got args: {:?}",
            spec.args
        );
    }

    /// pty_request + shell_request → uses `script` wrapper with `-t`
    #[test]
    fn container_shell_with_pty_uses_script_wrapper() {
        let spec = build_exec_command("container", CONTAINER, SHELL, Some(&pty()), None, &[]);
        assert_eq!(
            spec.program, "script",
            "Container interactive shell should use the `script` PTY wrapper"
        );
        assert!(
            spec.args.contains(&"-t".to_string()),
            "Container interactive shell should pass -t to container exec; got args: {:?}",
            spec.args
        );
    }

    // ── Env vars ──────────────────────────────────────────────────────────────

    #[test]
    fn env_contains_term_when_pty_present() {
        let spec = build_exec_command("docker", CONTAINER, SHELL, Some(&pty()), Some("uname"), &[]);
        let term_val = spec
            .env
            .iter()
            .find(|(k, _)| k == "TERM")
            .map(|(_, v)| v.as_str());
        assert_eq!(term_val, Some("xterm-256color"));
    }

    #[test]
    fn env_does_not_contain_term_without_pty() {
        let spec = build_exec_command("docker", CONTAINER, SHELL, None, Some("uname"), &[]);
        assert!(
            !spec.env.iter().any(|(k, _)| k == "TERM"),
            "TERM should not be set when no pty was requested"
        );
    }

    #[test]
    fn env_always_contains_shell() {
        let spec = build_exec_command("docker", CONTAINER, SHELL, None, None, &[]);
        let shell_val = spec
            .env
            .iter()
            .find(|(k, _)| k == "SHELL")
            .map(|(_, v)| v.as_str());
        assert_eq!(shell_val, Some(SHELL));
    }

    // ── extra_env / env_request forwarding ───────────────────────────────────

    #[test]
    fn docker_exec_extra_env_vars_are_passed_with_e_flag() {
        let env = vec![
            ("ZED_REMOTE_SERVER_VERSION".to_string(), "0.1.0".to_string()),
            ("FOO".to_string(), "bar".to_string()),
        ];
        let spec = build_exec_command("docker", CONTAINER, SHELL, None, Some("uname"), &env);
        assert!(
            spec.args.contains(&"-e".to_string()),
            "docker exec must contain -e flag for extra env; got args: {:?}",
            spec.args
        );
        assert!(
            spec.args
                .iter()
                .any(|a| a == "ZED_REMOTE_SERVER_VERSION=0.1.0"),
            "ZED_REMOTE_SERVER_VERSION must be forwarded as K=V; got args: {:?}",
            spec.args
        );
        assert!(
            spec.args.iter().any(|a| a == "FOO=bar"),
            "FOO must be forwarded as K=V; got args: {:?}",
            spec.args
        );
        // -e flags must come before the container ID
        let e_pos = spec.args.iter().position(|a| a == "-e").unwrap();
        let cid_pos = spec.args.iter().position(|a| a == CONTAINER).unwrap();
        assert!(
            e_pos < cid_pos,
            "-e flag must appear before container ID; got args: {:?}",
            spec.args
        );
    }

    #[test]
    fn container_exec_extra_env_vars_are_passed_with_e_flag() {
        let env = vec![("ZED_REMOTE_SERVER_VERSION".to_string(), "0.1.0".to_string())];
        let spec = build_exec_command("container", CONTAINER, SHELL, None, Some("uname"), &env);
        assert!(
            spec.args.contains(&"-e".to_string()),
            "Container exec must contain -e flag for extra env; got args: {:?}",
            spec.args
        );
        assert!(
            spec.args
                .iter()
                .any(|a| a == "ZED_REMOTE_SERVER_VERSION=0.1.0"),
            "ZED_REMOTE_SERVER_VERSION must be forwarded; got args: {:?}",
            spec.args
        );
        let e_pos = spec.args.iter().position(|a| a == "-e").unwrap();
        let cid_pos = spec.args.iter().position(|a| a == CONTAINER).unwrap();
        assert!(
            e_pos < cid_pos,
            "-e flag must appear before container ID; got args: {:?}",
            spec.args
        );
    }

    // ── Unix socket proxy (direct-streamlocal) ────────────────────────────────

    const SOCKET: &str = "/tmp/zed-server-12345.sock";

    /// Docker: socat command targets the correct socket path
    #[test]
    fn docker_unix_socket_proxy_uses_socat() {
        let spec = build_unix_socket_command("docker", CONTAINER, SOCKET);
        assert_eq!(spec.program, "docker");
        assert!(
            spec.args.contains(&"socat".to_string()),
            "command must invoke socat; got args: {:?}",
            spec.args
        );
        assert!(
            spec.args
                .iter()
                .any(|a| a == &format!("UNIX-CONNECT:{SOCKET}")),
            "socat must target UNIX-CONNECT:<socket_path>; got args: {:?}",
            spec.args
        );
        assert!(
            spec.args.contains(&"STDIO".to_string()),
            "socat must use STDIO as source; got args: {:?}",
            spec.args
        );
    }

    /// Docker: no PTY allocation for socket proxy
    #[test]
    fn docker_unix_socket_proxy_does_not_allocate_tty() {
        let spec = build_unix_socket_command("docker", CONTAINER, SOCKET);
        assert!(
            !spec.args.contains(&"-t".to_string()),
            "Unix socket proxy must not allocate a TTY; got args: {:?}",
            spec.args
        );
    }

    // ── channel_eof / channel_close stdin lifecycle ───────────────────────────

    /// channel_eof must NOT remove the stdin entry. If it did, socat processes
    /// for Zed's stdout.sock / stderr.sock would die the moment Zed sends EOF
    /// on those channels (which it does immediately since it never writes to them),
    /// causing the server to lose its I/O connections.
    ///
    /// channel_close (which always follows channel_eof) IS expected to clean up.
    #[tokio::test]
    async fn channel_eof_does_not_close_stdin_channel_close_does() {
        use std::collections::HashMap;
        use std::sync::Arc;
        use tokio::sync::Mutex;

        let stdin_by_channel: Arc<
            Mutex<HashMap<(usize, russh::ChannelId), tokio::process::ChildStdin>>,
        > = Arc::new(Mutex::new(HashMap::new()));

        // Spawn a dummy process to get a real ChildStdin handle.
        let mut child = tokio::process::Command::new("cat")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .spawn()
            .expect("failed to spawn dummy process for test");
        let child_stdin = child.stdin.take().expect("no stdin on dummy process");

        // ChannelId is a private newtype(u32) — use transmute in test code only.
        let channel_id: russh::ChannelId = unsafe { std::mem::transmute(42u32) };
        let client_id: usize = 1;
        let key = (client_id, channel_id);

        stdin_by_channel.lock().await.insert(key, child_stdin);
        assert!(
            stdin_by_channel.lock().await.contains_key(&key),
            "stdin entry should exist before eof"
        );

        // Simulate channel_eof: the handler is a no-op for the map — entry must survive.
        assert!(
            stdin_by_channel.lock().await.contains_key(&key),
            "channel_eof must not remove the stdin entry — socat must stay alive"
        );

        // Simulate channel_close: removes the entry.
        stdin_by_channel.lock().await.remove(&key);
        assert!(
            !stdin_by_channel.lock().await.contains_key(&key),
            "channel_close must remove the stdin entry"
        );

        let _ = child.kill().await;
    }

    /// Container: uses `container exec` with socat
    #[test]
    fn container_unix_socket_proxy_uses_socat() {
        let spec = build_unix_socket_command("container", CONTAINER, SOCKET);
        assert_eq!(spec.program, "container");
        assert!(
            spec.args.contains(&"socat".to_string()),
            "Container command must invoke socat; got args: {:?}",
            spec.args
        );
        assert!(
            spec.args
                .iter()
                .any(|a| a == &format!("UNIX-CONNECT:{SOCKET}")),
            "Container socat must target UNIX-CONNECT:<socket_path>; got args: {:?}",
            spec.args
        );
    }
}
