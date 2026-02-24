use crate::error::{Error, Result};
use rand_core::OsRng;
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

        let has_pty = pty_info.is_some();

        let interactive_shell_cmd = pty_info.as_ref().map(|pty| {
            format!(
                "stty cols {} rows {} 2>/dev/null; exec {} -i",
                pty.cols, pty.rows, self.state.default_shell
            )
        });

        let mut cmd = if self.state.runtime_name == "apple" {
            let mut c = Command::new("script");
            c.arg("-q").arg("/dev/null");
            c.arg("container").arg("exec").arg("-t").arg("-i");
            c.arg(&self.state.container_id);
            if let Some(command) = requested_command {
                c.arg(&self.state.default_shell).arg("-lic").arg(command);
            } else if let Some(shell_cmd) = &interactive_shell_cmd {
                c.arg("sh").arg("-lc").arg(shell_cmd);
            } else {
                c.arg(&self.state.default_shell).arg("-i");
            }
            c
        } else {
            let mut c = match self.state.runtime_name.as_str() {
                "apple" => {
                    let mut inner = Command::new("container");
                    inner.arg("exec");
                    inner
                }
                _ => {
                    let mut inner = Command::new("docker");
                    inner.arg("exec");
                    inner
                }
            };

            if has_pty && self.state.runtime_name == "docker" {
                c.arg("-t");
            }

            c.arg("-i").arg(&self.state.container_id);

            if let Some(command) = requested_command {
                c.arg(&self.state.default_shell).arg("-lic").arg(command);
            } else {
                if let Some(shell_cmd) = &interactive_shell_cmd {
                    c.arg("sh").arg("-lc").arg(shell_cmd);
                } else {
                    c.arg(&self.state.default_shell).arg("-i");
                }
            }

            c
        };

        if let Some(pty) = pty_info {
            cmd.env("TERM", pty.term)
                .env("COLUMNS", pty.cols.to_string())
                .env("LINES", pty.rows.to_string());
        }

        cmd.env("SHELL", &self.state.default_shell);

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
                loop {
                    let Ok(n) = stdout.read(&mut buf).await else {
                        break;
                    };
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
                loop {
                    let Ok(n) = stderr.read(&mut buf).await else {
                        break;
                    };
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

                let mut config = russh::server::Config::default();
                config.auth_rejection_time = std::time::Duration::from_secs(0);
                config.auth_rejection_time_initial = Some(std::time::Duration::from_secs(0));
                config.methods = russh::MethodSet::from(&[russh::MethodKind::None][..]);
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
