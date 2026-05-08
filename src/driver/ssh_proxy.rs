use crate::error::{Error, Result};
use russh::keys::ssh_key::rand_core::OsRng;
use russh::keys::{self, PrivateKey};
use russh::server::{Auth, Msg, Server as _, Session};
use russh::{Channel, ChannelId, CryptoVec};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{ChildStdin, Command};

#[derive(Clone)]
struct PtyInfo {
    term: String,
    cols: u32,
    rows: u32,
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
fn build_exec_command(
    runtime_name: &str,
    container_id: &str,
    default_shell: &str,
    pty_info: Option<&PtyInfo>,
    requested_command: Option<&str>,
) -> ExecCommandSpec {
    let has_pty = pty_info.is_some();
    let interactive_shell_cmd = pty_info.map(|pty| {
        format!(
            "stty cols {} rows {} 2>/dev/null; exec {} -i",
            pty.cols, pty.rows, default_shell
        )
    });

    let (program, args) = if runtime_name == "apple" {
        if let Some(command) = requested_command {
            // For specific commands, skip the `script` PTY wrapper to avoid
            // escape sequences polluting command output (e.g. `uname`).
            let args = vec![
                "exec".to_string(),
                "-i".to_string(),
                container_id.to_string(),
                default_shell.to_string(),
                "-lic".to_string(),
                command.to_string(),
            ];
            ("container".to_string(), args)
        } else {
            // Interactive shell: use `script` to allocate a PTY on the host side.
            let mut args = vec![
                "-q".to_string(),
                "/dev/null".to_string(),
                "container".to_string(),
                "exec".to_string(),
                "-t".to_string(),
                "-i".to_string(),
                container_id.to_string(),
            ];
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
        let mut args = vec!["exec".to_string()];
        // Only allocate a PTY when running an interactive shell, not for
        // specific commands.  Allocating a PTY for commands like `uname`
        // injects cursor-control escape sequences into their output which
        // breaks clients that parse the result (e.g. Zed remote development).
        if has_pty && requested_command.is_none() {
            args.push("-t".to_string());
        }
        args.push("-i".to_string());
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

        ("docker".to_string(), args)
    };

    let mut env = vec![("SHELL".to_string(), default_shell.to_string())];
    if let Some(pty) = pty_info {
        env.push(("TERM".to_string(), pty.term.clone()));
        env.push(("COLUMNS".to_string(), pty.cols.to_string()));
        env.push(("LINES".to_string(), pty.rows.to_string()));
    }

    ExecCommandSpec { program, args, env }
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

    async fn auth_none(&mut self, _user: &str) -> std::result::Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        _session: &mut Session,
    ) -> std::result::Result<bool, Self::Error> {
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

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
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
        session.channel_success(channel)?;

        let is_warp_bootstrap = command.contains("TERM_PROGRAM='WarpTerminal'")
            || command.contains("WARP_SESSION_ID=")
            || command.contains("hook=$(printf");

        if is_warp_bootstrap {
            self.spawn_container_exec(channel, None, session.handle())
                .await;
        } else {
            self.spawn_container_exec(channel, Some(command), session.handle())
                .await;
        }

        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        let key = (self.client_id, channel);
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
        let key = (self.client_id, channel);
        let mut lock = self.state.stdin_by_channel.lock().await;
        lock.remove(&key);
        drop(lock);

        let mut pty_map = self.state.pty_by_channel.lock().await;
        pty_map.remove(&key);
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        let key = (self.client_id, channel);
        let mut lock = self.state.stdin_by_channel.lock().await;
        lock.remove(&key);
        drop(lock);

        let mut pty_map = self.state.pty_by_channel.lock().await;
        pty_map.remove(&key);
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

        let spec = build_exec_command(
            &self.state.runtime_name,
            &self.state.container_id,
            &self.state.default_shell,
            pty_info.as_ref(),
            requested_command.as_deref(),
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
                    CryptoVec::from("Failed to spawn container exec\r\n"),
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
                    let _ = handle_out
                        .data(channel, CryptoVec::from(buf[..n].to_vec()))
                        .await;
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
                    let _ = handle_err
                        .data(channel, CryptoVec::from(buf[..n].to_vec()))
                        .await;
                }
            });
        }

        let key = (self.client_id, channel);
        let stdin_map = self.state.stdin_by_channel.clone();
        tokio::spawn(async move {
            let exit_code = match child.wait().await {
                Ok(status) => status.code().unwrap_or(1) as u32,
                Err(_) => 1,
            };
            let mut lock = stdin_map.lock().await;
            lock.remove(&key);
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
                let key = PrivateKey::random(&mut OsRng, keys::Algorithm::Ed25519);
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

    /// pty_request + exec_request(command) → no `-t` (regression guard for #90)
    #[test]
    fn docker_exec_with_pty_does_not_allocate_tty() {
        let spec = build_exec_command("docker", CONTAINER, SHELL, Some(&pty()), Some("uname"));
        assert_eq!(spec.program, "docker");
        assert!(
            !spec.args.contains(&"-t".to_string()),
            "docker exec must not pass -t for a specific command even when pty was requested; \
             got args: {:?}",
            spec.args
        );
    }

    /// pty_request + shell_request → `-t` is present
    #[test]
    fn docker_shell_with_pty_allocates_tty() {
        let spec = build_exec_command("docker", CONTAINER, SHELL, Some(&pty()), None);
        assert_eq!(spec.program, "docker");
        assert!(
            spec.args.contains(&"-t".to_string()),
            "docker exec should pass -t for an interactive shell when pty was requested; \
             got args: {:?}",
            spec.args
        );
    }

    /// no pty_request + exec_request(command) → no `-t`
    #[test]
    fn docker_exec_without_pty_does_not_allocate_tty() {
        let spec = build_exec_command("docker", CONTAINER, SHELL, None, Some("uname"));
        assert_eq!(spec.program, "docker");
        assert!(
            !spec.args.contains(&"-t".to_string()),
            "docker exec must not pass -t when no pty was requested; got args: {:?}",
            spec.args
        );
    }

    /// no pty_request + shell_request → no `-t`
    #[test]
    fn docker_shell_without_pty_does_not_allocate_tty() {
        let spec = build_exec_command("docker", CONTAINER, SHELL, None, None);
        assert_eq!(spec.program, "docker");
        assert!(
            !spec.args.contains(&"-t".to_string()),
            "docker exec must not pass -t for a shell when no pty was requested; \
             got args: {:?}",
            spec.args
        );
    }

    // ── Apple ─────────────────────────────────────────────────────────────────

    /// pty_request + exec_request(command) → uses `container exec` directly, no `script` wrapper
    #[test]
    fn apple_exec_with_pty_does_not_use_script_wrapper() {
        let spec = build_exec_command("apple", CONTAINER, SHELL, Some(&pty()), Some("uname"));
        assert_eq!(
            spec.program, "container",
            "Apple exec with a specific command should call `container` directly, not `script`; \
             program was: {:?}",
            spec.program
        );
        assert!(
            !spec.args.contains(&"-t".to_string()),
            "Apple exec with a specific command must not pass -t; got args: {:?}",
            spec.args
        );
    }

    /// pty_request + shell_request → uses `script` wrapper with `-t`
    #[test]
    fn apple_shell_with_pty_uses_script_wrapper() {
        let spec = build_exec_command("apple", CONTAINER, SHELL, Some(&pty()), None);
        assert_eq!(
            spec.program, "script",
            "Apple interactive shell should use the `script` PTY wrapper"
        );
        assert!(
            spec.args.contains(&"-t".to_string()),
            "Apple interactive shell should pass -t to container exec; got args: {:?}",
            spec.args
        );
    }

    // ── Env vars ──────────────────────────────────────────────────────────────

    #[test]
    fn env_contains_term_when_pty_present() {
        let spec = build_exec_command("docker", CONTAINER, SHELL, Some(&pty()), Some("uname"));
        let term_val = spec
            .env
            .iter()
            .find(|(k, _)| k == "TERM")
            .map(|(_, v)| v.as_str());
        assert_eq!(term_val, Some("xterm-256color"));
    }

    #[test]
    fn env_does_not_contain_term_without_pty() {
        let spec = build_exec_command("docker", CONTAINER, SHELL, None, Some("uname"));
        assert!(
            !spec.env.iter().any(|(k, _)| k == "TERM"),
            "TERM should not be set when no pty was requested"
        );
    }

    #[test]
    fn env_always_contains_shell() {
        let spec = build_exec_command("docker", CONTAINER, SHELL, None, None);
        let shell_val = spec
            .env
            .iter()
            .find(|(k, _)| k == "SHELL")
            .map(|(_, v)| v.as_str());
        assert_eq!(shell_val, Some(SHELL));
    }
}
