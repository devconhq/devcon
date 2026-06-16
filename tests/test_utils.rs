#![allow(dead_code)]
use std::{collections::HashMap, path::PathBuf, process::Command};
use tempfile::TempDir;

/// Represents a container runtime type
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Runtime {
    Docker,
    Container,
}

/// Get the runtime to use for tests from environment variable
pub fn get_runtime() -> Runtime {
    match std::env::var("CONTAINER_RUNTIME")
        .unwrap_or_else(|_| "docker".to_string())
        .as_str()
    {
        "container" => Runtime::Container,
        _ => Runtime::Docker,
    }
}

/// Get the runtime command name
pub fn runtime_cmd(runtime: Runtime) -> &'static str {
    match runtime {
        Runtime::Docker => "docker",
        Runtime::Container => "container",
    }
}

/// Check if a runtime is available
pub fn is_runtime_available(runtime: Runtime) -> bool {
    let mut cmd = Command::new(runtime_cmd(runtime));
    match runtime {
        // `docker info` confirms the daemon is reachable
        Runtime::Docker => cmd.arg("info"),
        // `container system status` is the equivalent for Apple container
        Runtime::Container => cmd.args(["system", "status"]),
    };
    cmd.output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// Returns true when the caller explicitly set `CONTAINER_RUNTIME` in the
/// environment.  When the env var is present, tests must not silently skip on
/// an unavailable runtime — they should fail loudly so CI catches misconfigurations.
pub fn is_runtime_explicitly_requested() -> bool {
    std::env::var("CONTAINER_RUNTIME").is_ok()
}

/// Create an empty test config file in a temp directory
/// Returns the path to the config file
pub fn create_test_config() -> std::path::PathBuf {
    create_test_config_with_contents("# Test config\nagents:\n    disable: true\n")
}

/// Create a test config file from YAML content in a temp directory.
/// Returns the path to the config file.
pub fn create_test_config_with_contents(contents: &str) -> std::path::PathBuf {
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("test-config.yaml");

    std::fs::write(&config_path, contents).expect("Failed to write test config");

    // We need to leak the temp_dir to keep it alive for the test duration
    // This is acceptable for tests as they're short-lived
    std::mem::forget(temp_dir);

    config_path
}

/// Create a test devcontainer with the given configuration
pub fn create_test_devcontainer(name: &str, image: &str, features: Option<&str>) -> TempDir {
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let devcontainer_path = temp_dir.path().join(".devcontainer");
    std::fs::create_dir_all(&devcontainer_path).expect("Failed to create .devcontainer dir");

    let features_json = features.unwrap_or("{}");
    let container_content = format!(
        r#"{{
    "name": "{}",
    "image": "{}",
    "features": {}
}}"#,
        name, image, features_json
    );

    std::fs::write(
        devcontainer_path.join("devcontainer.json"),
        container_content,
    )
    .expect("Failed to write devcontainer.json");

    temp_dir
}

/// Create a test devcontainer with a Dockerfile
pub fn create_test_devcontainer_with_dockerfile(name: &str, dockerfile_content: &str) -> TempDir {
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let devcontainer_path = temp_dir.path().join(".devcontainer");
    std::fs::create_dir_all(&devcontainer_path).expect("Failed to create .devcontainer dir");

    let container_content = format!(
        r#"{{
    "name": "{}",
    "build": {{
        "dockerfile": "Dockerfile"
    }}
}}"#,
        name
    );

    std::fs::write(
        devcontainer_path.join("devcontainer.json"),
        container_content,
    )
    .expect("Failed to write devcontainer.json");

    std::fs::write(devcontainer_path.join("Dockerfile"), dockerfile_content)
        .expect("Failed to write Dockerfile");

    temp_dir
}

/// Create a test devcontainer with lifecycle hooks
pub fn create_test_devcontainer_with_hooks(
    name: &str,
    image: &str,
    on_create: Option<serde_json::Value>,
    post_create: Option<serde_json::Value>,
) -> TempDir {
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let devcontainer_path = temp_dir.path().join(".devcontainer");
    std::fs::create_dir_all(&devcontainer_path).expect("Failed to create .devcontainer dir");

    let mut config = serde_json::json!({
        "name": name,
        "image": image,
    });

    if let Some(cmd) = on_create {
        config["onCreateCommand"] = cmd;
    }

    if let Some(cmd) = post_create {
        config["postCreateCommand"] = cmd;
    }

    let container_content =
        serde_json::to_string_pretty(&config).expect("Failed to serialize config");

    std::fs::write(
        devcontainer_path.join("devcontainer.json"),
        container_content,
    )
    .expect("Failed to write devcontainer.json");

    temp_dir
}

/// Verify that a container image exists
pub fn verify_image_exists(runtime: Runtime, image_name: &str) -> bool {
    let cmd = runtime_cmd(runtime);
    let format = match runtime {
        Runtime::Docker => "{{.Repository}}:{{.Tag}}",
        Runtime::Container => "json",
    };

    let output = Command::new(cmd)
        .arg("image")
        .arg("list")
        .arg("--format")
        .arg(format)
        .output()
        .expect("Failed to list images");

    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout.lines().any(|line| line.contains(image_name))
}

/// Get the container name/ID from devcon output
#[allow(dead_code)]
pub fn extract_container_name(output: &str) -> Option<String> {
    // Look for container name in output - this is a simple heuristic
    // May need to be adjusted based on actual devcon output format
    for line in output.lines() {
        if line.contains("Container") || line.contains("container") {
            // Extract container name/ID - adjust pattern as needed
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(name) = parts.last() {
                return Some(name.to_string());
            }
        }
    }
    None
}

/// Stop a running container
#[allow(dead_code)]
pub fn stop_container(runtime: Runtime, container_id: &str) {
    let cmd = runtime_cmd(runtime);
    let _ = Command::new(cmd).arg("stop").arg(container_id).output();
}

/// Remove all containers and images belonging to a devcon test project.
///
/// Stops and force-removes any containers labelled `devcon.project=<project_name>`,
/// then removes all images whose repository matches `devcon-<project_name>`.
/// Call this at the start of tests that create containers so stale state from
/// previous runs does not interfere.
#[allow(dead_code)]
pub fn cleanup_test_artifacts(runtime: Runtime, project_name: &str) {
    let cmd = runtime_cmd(runtime);
    let label = format!("devcon.project={}", project_name);
    let image_prefix = format!("devcon-{}", project_name);

    match runtime {
        Runtime::Docker => {
            // Find all containers (running or stopped) for this project
            let ps_output = Command::new(cmd)
                .args([
                    "ps",
                    "-a",
                    "--filter",
                    &format!("label={}", label),
                    "--format",
                    "{{.ID}}",
                ])
                .output();
            if let Ok(out) = ps_output {
                let ids = String::from_utf8_lossy(&out.stdout);
                for id in ids.lines().map(str::trim).filter(|s| !s.is_empty()) {
                    let _ = Command::new(cmd).args(["rm", "-f", id]).output();
                }
            }

            // Remove all images for this project (latest + any build-* tags)
            let img_output = Command::new(cmd)
                .args(["image", "ls", "--format", "{{.Repository}}:{{.Tag}}"])
                .output();
            if let Ok(out) = img_output {
                let tags = String::from_utf8_lossy(&out.stdout);
                for tag in tags
                    .lines()
                    .map(str::trim)
                    .filter(|t| t.starts_with(&image_prefix))
                {
                    let _ = Command::new(cmd).args(["rmi", "-f", tag]).output();
                }
            }
        }
        Runtime::Container => {
            // Container: list all containers and filter by name prefix
            let ls_output = Command::new(cmd)
                .args(["container", "list", "--all", "--format", "json"])
                .output();
            if let Ok(out) = ls_output
                && let Ok(entries) = serde_json::from_slice::<Vec<serde_json::Value>>(&out.stdout)
            {
                for entry in entries {
                    let name = entry["name"].as_str().unwrap_or("");
                    // devcon container name is devcon.<project_name>
                    if name == format!("devcon.{}", project_name) {
                        let _ = Command::new(cmd)
                            .args(["container", "rm", "-f", name])
                            .output();
                    }
                }
            }
            // Remove images
            let img_output = Command::new(cmd)
                .args(["image", "list", "--format", "json"])
                .output();
            if let Ok(out) = img_output
                && let Ok(entries) = serde_json::from_slice::<Vec<serde_json::Value>>(&out.stdout)
            {
                for entry in entries {
                    let repo = entry["repository"].as_str().unwrap_or("");
                    let tag = entry["tag"].as_str().unwrap_or("");
                    let full = format!("{}:{}", repo, tag);
                    if full.starts_with(&image_prefix) {
                        let _ = Command::new(cmd)
                            .args(["image", "rm", "-f", &full])
                            .output();
                    }
                }
            }
        }
    }
}

/// Clean up a container by name
#[allow(dead_code)]
pub fn cleanup_container(runtime: Runtime, container_name: &str) {
    let cmd = runtime_cmd(runtime);
    let _ = Command::new(cmd)
        .arg("rm")
        .arg("-f")
        .arg(container_name)
        .output();
}

/// Clean up an image by name
#[allow(dead_code)]
pub fn cleanup_image(runtime: Runtime, image_name: &str) {
    let cmd = runtime_cmd(runtime);
    let subcommand = match runtime {
        Runtime::Docker => "rmi",
        Runtime::Container => "image",
    };

    let mut cmd_builder = Command::new(cmd);
    cmd_builder.arg(subcommand);

    if runtime == Runtime::Container {
        cmd_builder.arg("rm");
    }

    cmd_builder.arg("-f").arg(image_name);
    let _ = cmd_builder.output();
}

/// Execute a command inside a running container
pub fn exec_in_container(
    runtime: Runtime,
    container_name: &str,
    command: &[&str],
) -> Result<String, String> {
    let cmd = runtime_cmd(runtime);
    let mut cmd_builder = Command::new(cmd);
    cmd_builder.arg("exec").arg(container_name);

    for arg in command {
        cmd_builder.arg(arg);
    }

    let output = cmd_builder
        .output()
        .map_err(|e| format!("Failed to execute command: {}", e))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

/// Get the running container ID for a DevCon project name.
pub fn get_running_container_id(runtime: Runtime, project_name: &str) -> Option<String> {
    let cmd = runtime_cmd(runtime);

    match runtime {
        Runtime::Docker => {
            let label = format!("devcon.project={}", project_name);
            let output = Command::new(cmd)
                .args([
                    "ps",
                    "--filter",
                    &format!("label={}", label),
                    "--format",
                    "{{.ID}}",
                ])
                .output()
                .ok()?;

            if !output.status.success() {
                return None;
            }

            String::from_utf8_lossy(&output.stdout)
                .lines()
                .map(str::trim)
                .find(|line| !line.is_empty())
                .map(ToString::to_string)
        }
        Runtime::Container => {
            let output = Command::new(cmd)
                .args(["container", "list", "--format", "json"])
                .output()
                .ok()?;

            if !output.status.success() {
                return None;
            }

            let entries = serde_json::from_slice::<Vec<serde_json::Value>>(&output.stdout).ok()?;
            let expected_name = format!("devcon.{}", project_name);

            entries.iter().find_map(|entry| {
                let name = entry["name"].as_str().unwrap_or("");
                if name == expected_name {
                    entry["id"].as_str().map(ToString::to_string)
                } else {
                    None
                }
            })
        }
    }
}

/// Get the image ID for a given image tag, returns None if not found
#[allow(dead_code)]
pub fn get_image_id(runtime: Runtime, image_tag: &str) -> Option<String> {
    let cmd = runtime_cmd(runtime);
    let output = Command::new(cmd)
        .arg("image")
        .arg("inspect")
        .arg(image_tag)
        .arg("--format")
        .arg("{{.Id}}")
        .output()
        .ok()?;

    if output.status.success() {
        let id = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if id.is_empty() { None } else { Some(id) }
    } else {
        None
    }
}

/// Check if a container is running
#[allow(dead_code)]
pub fn is_container_running(runtime: Runtime, container_name: &str) -> bool {
    let cmd = runtime_cmd(runtime);
    let output = Command::new(cmd)
        .arg("ps")
        .arg("--filter")
        .arg(format!("name={}", container_name))
        .arg("--format")
        .arg("{{.Names}}")
        .output()
        .expect("Failed to check running containers");

    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout.lines().any(|line| line == container_name)
}

/// Generate a unique test image name
#[allow(dead_code)]
pub fn generate_test_image_name(test_name: &str) -> String {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    format!("devcon-test-{}:{}", test_name, timestamp)
}

// ─────────────────────────────────────────────────────────────────────────────
// Fluent builder helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Skip the current test when the given runtime is not available.
///
/// If `CONTAINER_RUNTIME` was explicitly set in the environment the test
/// **panics** instead of skipping, so CI immediately surfaces a misconfigured
/// or not-started runtime rather than reporting a false-green "0 tests run".
///
/// ```ignore
/// skip_if_unavailable!(get_runtime());
/// ```
#[macro_export]
macro_rules! skip_if_unavailable {
    ($runtime:expr) => {
        let runtime = $runtime;
        if !$crate::test_utils::is_runtime_available(runtime) {
            if $crate::test_utils::is_runtime_explicitly_requested() {
                panic!(
                    "{:?} runtime was requested via CONTAINER_RUNTIME but is not available. \
                     Ensure the runtime daemon is running before executing integration tests.",
                    runtime
                );
            }
            println!("Skipping test: {:?} runtime not available", runtime);
            return;
        }
    };
}

/// Skip the current test when no SSH agent socket is available on the host.
///
/// ```ignore
/// skip_if_no_ssh_agent!();
/// ```
#[macro_export]
macro_rules! skip_if_no_ssh_agent {
    () => {
        match std::env::var("SSH_AUTH_SOCK") {
            Ok(path) if std::path::Path::new(&path).exists() => {}
            _ => {
                println!("Skipping test: no SSH agent socket available (SSH_AUTH_SOCK)");
                return;
            }
        }
    };
}

/// Skip the current test when no GPG agent is available on the host.
///
/// ```ignore
/// skip_if_no_gpg_agent!();
/// ```
#[macro_export]
macro_rules! skip_if_no_gpg_agent {
    () => {
        let gpg_ok = std::process::Command::new("gpgconf")
            .args(["--list-dir", "agent-socket"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !gpg_ok {
            println!("Skipping test: no GPG agent available (gpgconf)");
            return;
        }
    };
}

// ─── TestConfig ───────────────────────────────────────────────────────────────

/// Builder for the devcon YAML config used in tests.
///
/// Holds the `TempDir` so the file stays alive until the builder is dropped,
/// avoiding the `mem::forget` leak in the old `create_test_config_with_contents`.
pub struct TestConfig {
    _dir: TempDir,
    pub path: PathBuf,
}

impl TestConfig {
    fn from_yaml(yaml: &str) -> Self {
        let dir = tempfile::tempdir().expect("Failed to create temp dir for TestConfig");
        let path = dir.path().join("test-config.yaml");
        std::fs::write(&path, yaml).expect("Failed to write test config");
        TestConfig { _dir: dir, path }
    }

    /// Config with agents disabled (fastest; no SSH setup).
    pub fn agents_disabled() -> Self {
        Self::from_yaml("# Test config\nagents:\n    disable: true\n")
    }

    /// Config with agents enabled at a custom SSH port.
    pub fn with_ssh_port(port: u16) -> Self {
        Self::from_yaml(&format!(
            "agents:\n  disable: false\n  sshPort: {port}\n  skipSshSetup: false\n"
        ))
    }

    /// Config with agents enabled but SSH setup skipped.
    pub fn skip_ssh_setup() -> Self {
        Self::from_yaml("agents:\n  disable: false\n  skipSshSetup: true\n")
    }

    /// Config with agents enabled (default port 22, no SSH skip).
    pub fn agents_enabled() -> Self {
        Self::from_yaml("agents:\n  disable: false\n")
    }

    /// Config from raw YAML string.
    pub fn from_raw(yaml: &str) -> Self {
        Self::from_yaml(yaml)
    }

    /// Config for dotfiles cloning (agents disabled for speed).
    pub fn with_dotfiles(url: &str) -> Self {
        Self::from_yaml(&format!(
            "dotfilesRepository: {url}\nagents:\n  disable: true\n"
        ))
    }

    /// Config with SSH agent forwarding enabled (requires `devcon serve` to be running).
    pub fn with_ssh_forwarding() -> Self {
        Self::from_yaml(
            "agents:\n  disable: false\n  skipSshSetup: false\nagentForwarding:\n  sshEnabled: true\n",
        )
    }

    /// Config with GPG agent forwarding enabled (requires `devcon serve` to be running).
    pub fn with_gpg_forwarding() -> Self {
        Self::from_yaml(
            "agents:\n  disable: false\n  skipSshSetup: false\nagentForwarding:\n  gpgEnabled: true\n",
        )
    }
}

// ─── DevcontainerBuilder ──────────────────────────────────────────────────────

enum DevcontainerSource {
    Image(String),
    Dockerfile(String),
}

/// A feature whose source lives on the local filesystem (inside the workspace).
struct LocalFeatureSpec {
    dir_name: String,
    install_sh: String,
    opts: serde_json::Map<String, serde_json::Value>,
}

/// Fluent builder for a temporary devcontainer workspace.
///
/// ```ignore
/// let workspace = DevcontainerBuilder::new("test-python")
///     .image("mcr.microsoft.com/devcontainers/base:ubuntu")
///     .feature("ghcr.io/devcontainers/features/python", &[("version", "3.12")])
///     .on_create("echo hello")
///     .build();
/// ```
pub struct DevcontainerBuilder {
    name: String,
    source: DevcontainerSource,
    features: HashMap<String, serde_json::Value>,
    on_create: Option<serde_json::Value>,
    post_create: Option<serde_json::Value>,
    remote_env: HashMap<String, String>,
    container_env: HashMap<String, String>,
    local_features: Vec<LocalFeatureSpec>,
}

impl DevcontainerBuilder {
    pub fn new(name: impl Into<String>) -> Self {
        DevcontainerBuilder {
            name: name.into(),
            source: DevcontainerSource::Image("mcr.microsoft.com/devcontainers/base:ubuntu".into()),
            features: HashMap::new(),
            on_create: None,
            post_create: None,
            remote_env: HashMap::new(),
            container_env: HashMap::new(),
            local_features: Vec::new(),
        }
    }

    /// Use a registry image as the base.
    pub fn image(mut self, image: impl Into<String>) -> Self {
        self.source = DevcontainerSource::Image(image.into());
        self
    }

    /// Use an inline Dockerfile as the build source.
    pub fn dockerfile(mut self, content: impl Into<String>) -> Self {
        self.source = DevcontainerSource::Dockerfile(content.into());
        self
    }

    /// Add a devcontainer feature.  `opts` is a slice of `(key, value)` option pairs.
    pub fn feature(mut self, id: impl Into<String>, opts: &[(&str, &str)]) -> Self {
        let opts_map: serde_json::Map<String, serde_json::Value> = opts
            .iter()
            .map(|(k, v)| (k.to_string(), serde_json::Value::String(v.to_string())))
            .collect();
        self.features
            .insert(id.into(), serde_json::Value::Object(opts_map));
        self
    }

    /// Set `onCreateCommand` to a shell string.
    pub fn on_create(mut self, cmd: impl Into<String>) -> Self {
        self.on_create = Some(serde_json::Value::String(cmd.into()));
        self
    }

    /// Set `onCreateCommand` to a JSON value (string, array, or object).
    pub fn on_create_value(mut self, cmd: serde_json::Value) -> Self {
        self.on_create = Some(cmd);
        self
    }

    /// Set `postCreateCommand` to a shell string.
    pub fn post_create(mut self, cmd: impl Into<String>) -> Self {
        self.post_create = Some(serde_json::Value::String(cmd.into()));
        self
    }

    /// Set `postCreateCommand` to a JSON value.
    pub fn post_create_value(mut self, cmd: serde_json::Value) -> Self {
        self.post_create = Some(cmd);
        self
    }

    /// Add a `remoteEnv` variable.
    pub fn remote_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.remote_env.insert(key.into(), value.into());
        self
    }

    /// Add a `containerEnv` variable.
    pub fn container_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.container_env.insert(key.into(), value.into());
        self
    }

    /// Add a local filesystem feature.
    ///
    /// Creates `.devcontainer/<dir_name>/devcontainer-feature.json` and
    /// `.devcontainer/<dir_name>/install.sh` (executable) in the workspace, then
    /// registers `"./<dir_name>"` in the features map.
    pub fn local_feature(
        mut self,
        dir_name: impl Into<String>,
        install_sh: impl Into<String>,
        opts: &[(&str, &str)],
    ) -> Self {
        let opts_map: serde_json::Map<String, serde_json::Value> = opts
            .iter()
            .map(|(k, v)| (k.to_string(), serde_json::Value::String(v.to_string())))
            .collect();
        self.local_features.push(LocalFeatureSpec {
            dir_name: dir_name.into(),
            install_sh: install_sh.into(),
            opts: opts_map,
        });
        self
    }

    /// Write the workspace to a `TempDir` and return the handle.
    pub fn build(mut self) -> TempDir {
        let dir = tempfile::tempdir().expect("Failed to create temp workspace dir");
        let dc_path = dir.path().join(".devcontainer");
        std::fs::create_dir_all(&dc_path).expect("Failed to create .devcontainer dir");

        let mut config = serde_json::json!({ "name": self.name });

        match self.source {
            DevcontainerSource::Image(img) => {
                config["image"] = serde_json::Value::String(img);
            }
            DevcontainerSource::Dockerfile(content) => {
                std::fs::write(dc_path.join("Dockerfile"), content)
                    .expect("Failed to write Dockerfile");
                config["build"] = serde_json::json!({ "dockerfile": "Dockerfile" });
            }
        }

        // Write local feature directories and register them in the features map.
        for lf in &self.local_features {
            let lf_dir = dc_path.join(&lf.dir_name);
            std::fs::create_dir_all(&lf_dir).expect("Failed to create local feature dir");

            let feature_json = serde_json::json!({
                "id": &lf.dir_name,
                "version": "1.0.0",
                "name": &lf.dir_name,
                "description": "Local test feature"
            });
            std::fs::write(
                lf_dir.join("devcontainer-feature.json"),
                serde_json::to_string_pretty(&feature_json)
                    .expect("Failed to serialise feature JSON"),
            )
            .expect("Failed to write devcontainer-feature.json");

            let install_sh_path = lf_dir.join("install.sh");
            std::fs::write(&install_sh_path, &lf.install_sh).expect("Failed to write install.sh");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = std::fs::metadata(&install_sh_path).unwrap().permissions();
                perms.set_mode(0o755);
                std::fs::set_permissions(&install_sh_path, perms)
                    .expect("Failed to chmod install.sh");
            }

            self.features.insert(
                // Use the absolute path so devcon's `canonicalize()` can find
                // the directory regardless of the process working directory.
                lf_dir.to_str().unwrap().to_string(),
                serde_json::Value::Object(lf.opts.clone()),
            );
        }

        if !self.features.is_empty() {
            config["features"] = serde_json::Value::Object(self.features.into_iter().collect());
        }

        if let Some(cmd) = self.on_create {
            config["onCreateCommand"] = cmd;
        }
        if let Some(cmd) = self.post_create {
            config["postCreateCommand"] = cmd;
        }
        if !self.container_env.is_empty() {
            config["containerEnv"] = serde_json::Value::Object(
                self.container_env
                    .into_iter()
                    .map(|(k, v)| (k, serde_json::Value::String(v)))
                    .collect(),
            );
        }
        if !self.remote_env.is_empty() {
            config["remoteEnv"] = serde_json::Value::Object(
                self.remote_env
                    .into_iter()
                    .map(|(k, v)| (k, serde_json::Value::String(v)))
                    .collect(),
            );
        }

        let json =
            serde_json::to_string_pretty(&config).expect("Failed to serialise devcontainer.json");
        std::fs::write(dc_path.join("devcontainer.json"), json)
            .expect("Failed to write devcontainer.json");

        dir
    }
}

// ─── DevconOutput ─────────────────────────────────────────────────────────────

/// The result of a `devcon` invocation.  Panics with full stdout/stderr on assertion failures.
pub struct DevconOutput {
    pub status: std::process::ExitStatus,
    pub stdout: String,
    pub stderr: String,
}

impl DevconOutput {
    /// Assert the command exited successfully, printing full output on failure.
    #[track_caller]
    pub fn assert_success(&self) {
        assert!(
            self.status.success(),
            "devcon command failed.\nStdout:\n{}\nStderr:\n{}",
            self.stdout,
            self.stderr
        );
    }

    /// Assert the command failed (non-zero exit).
    #[track_caller]
    pub fn assert_failure(&self) {
        assert!(
            !self.status.success(),
            "devcon command unexpectedly succeeded.\nStdout:\n{}\nStderr:\n{}",
            self.stdout,
            self.stderr
        );
    }

    /// Assert that either stdout or stderr contains `needle`.
    #[track_caller]
    pub fn assert_output_contains(&self, needle: &str) {
        let combined = format!("{}\n{}", self.stdout, self.stderr);
        assert!(
            combined.contains(needle),
            "Expected output to contain {needle:?}.\nStdout:\n{}\nStderr:\n{}",
            self.stdout,
            self.stderr
        );
    }

    /// Assert that stderr contains `needle`.
    #[track_caller]
    pub fn assert_stderr_contains(&self, needle: &str) {
        assert!(
            self.stderr.contains(needle),
            "Expected stderr to contain {needle:?}.\nStderr:\n{}",
            self.stderr
        );
    }

    /// Parse stdout as JSON.  Panics with full output if parsing fails.
    #[track_caller]
    pub fn json(&self) -> serde_json::Value {
        // The agent inside the container may emit terminal escape sequences (e.g.
        // OSC title-set `]0;...{...}`) before the JSON object.  These contain
        // '{' characters that confuse a naive first-'{' search.  The actual JSON
        // object always starts with '{' at the beginning of a new line, so look
        // for '\n{' first; fall back to the first '{' if the output has no
        // preceding newline (e.g. bare JSON output).
        let trimmed = self.stdout.trim();
        let json_start = trimmed
            .find("\n{")
            .map(|i| i + 1)
            .unwrap_or_else(|| trimmed.find('{').unwrap_or(0));
        serde_json::from_str(&trimmed[json_start..]).unwrap_or_else(|err| {
            panic!(
                "devcon output is not valid JSON: {err}\nStdout:\n{}\nStderr:\n{}",
                self.stdout, self.stderr
            )
        })
    }

    /// Extract the `container_id` field from JSON stdout.
    #[track_caller]
    pub fn container_id(&self) -> String {
        let v = self.json();
        v["container_id"]
            .as_str()
            .unwrap_or_else(|| {
                panic!(
                    "JSON output does not contain container_id.\nStdout:\n{}\nStderr:\n{}",
                    self.stdout, self.stderr
                )
            })
            .to_string()
    }
}

// ─── DevconRun ────────────────────────────────────────────────────────────────

/// Runs `devcon` subcommands against a workspace directory.
///
/// ```ignore
/// let out = DevconRun::build(workspace.path(), &config);
/// out.assert_success();
/// ```
pub struct DevconRun;

impl DevconRun {
    fn run(args: &[&str]) -> DevconOutput {
        use assert_cmd::cargo::cargo_bin_cmd;
        let mut cmd = cargo_bin_cmd!("devcon");
        for a in args {
            cmd.arg(a);
        }
        let output = cmd.output().expect("Failed to spawn devcon");
        DevconOutput {
            status: output.status,
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }

    /// Run `devcon build <workspace>` with the given config.
    pub fn build(workspace: &std::path::Path, config: &TestConfig) -> DevconOutput {
        Self::run(&[
            "--config",
            config.path.to_str().unwrap(),
            "build",
            workspace.to_str().unwrap(),
        ])
    }

    /// Run `devcon up --output json <workspace>` with the given config.
    pub fn up(workspace: &std::path::Path, config: &TestConfig) -> DevconOutput {
        Self::run(&[
            "--config",
            config.path.to_str().unwrap(),
            "--output",
            "json",
            "up",
            workspace.to_str().unwrap(),
        ])
    }

    /// Run `devcon up --output json --force-rebuild <workspace>`.
    pub fn up_force_rebuild(workspace: &std::path::Path, config: &TestConfig) -> DevconOutput {
        Self::run(&[
            "--config",
            config.path.to_str().unwrap(),
            "--output",
            "json",
            "up",
            "--force-rebuild",
            workspace.to_str().unwrap(),
        ])
    }

    /// Run `devcon up --output json -ddddd <workspace>` (verbose, for Dockerfile tests).
    pub fn up_verbose(workspace: &std::path::Path, config: &TestConfig) -> DevconOutput {
        Self::run(&[
            "--config",
            config.path.to_str().unwrap(),
            "--output",
            "json",
            "-ddddd",
            "up",
            workspace.to_str().unwrap(),
        ])
    }

    /// Run `devcon start --output json <workspace>`.
    pub fn start(workspace: &std::path::Path, config: &TestConfig) -> DevconOutput {
        Self::run(&[
            "--config",
            config.path.to_str().unwrap(),
            "--output",
            "json",
            "start",
            workspace.to_str().unwrap(),
        ])
    }

    /// Run `devcon ssh connect --proxy <workspace>`.
    pub fn ssh_proxy(workspace: &std::path::Path, config: &TestConfig) -> DevconOutput {
        Self::run(&[
            "--config",
            config.path.to_str().unwrap(),
            "ssh",
            "connect",
            workspace.to_str().unwrap(),
            "--proxy",
        ])
    }

    /// Spawn `devcon serve` on an unused port in the background.
    ///
    /// Returns a [`ServeGuard`] (kills the process on drop) and the port it is
    /// listening on.  Sleeps briefly after spawning to give the server time to bind.
    pub fn serve_in_background(config: &TestConfig) -> (ServeGuard, u16) {
        let port = openport::pick_unused_port(15001..=u16::MAX)
            .expect("No free port available for test devcon serve");
        let bin_path = assert_cmd::cargo::cargo_bin("devcon");
        let child = std::process::Command::new(&bin_path)
            .arg("--config")
            .arg(config.path.to_str().unwrap())
            .arg("serve")
            .arg("--port")
            .arg(port.to_string())
            .spawn()
            .expect("Failed to spawn devcon serve");
        // Give the server time to bind before returning.
        std::thread::sleep(std::time::Duration::from_millis(500));
        (ServeGuard(child), port)
    }
}

// ─── ServeGuard ───────────────────────────────────────────────────────────────

/// RAII guard that kills a background `devcon serve` process when dropped.
pub struct ServeGuard(std::process::Child);

impl Drop for ServeGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

// ─── ContainerHandle ─────────────────────────────────────────────────────────

/// A handle to a running container, returned from `DevconRun::up`.
pub struct ContainerHandle {
    pub id: String,
    runtime: Runtime,
}

impl ContainerHandle {
    pub fn new(id: impl Into<String>, runtime: Runtime) -> Self {
        ContainerHandle {
            id: id.into(),
            runtime,
        }
    }

    /// Execute a command inside the container.
    pub fn exec(&self, cmd: &[&str]) -> Result<String, String> {
        exec_in_container(self.runtime, &self.id, cmd)
    }

    /// Assert that a command succeeds and its stdout contains `expected`.
    #[track_caller]
    pub fn assert_exec_contains(&self, cmd: &[&str], expected: &str) {
        let out = self
            .exec(cmd)
            .unwrap_or_else(|e| panic!("exec {:?} failed: {e}", cmd));
        assert!(
            out.contains(expected),
            "exec {:?} output did not contain {expected:?}.\nGot: {out}",
            cmd
        );
    }

    /// Assert that a file path exists inside the container.
    #[track_caller]
    pub fn assert_file_exists(&self, path: &str) {
        self.exec(&["test", "-f", path])
            .unwrap_or_else(|_| panic!("Expected file {path:?} to exist in container {}", self.id));
    }

    /// Assert that an environment variable has the expected value.
    #[track_caller]
    pub fn assert_env(&self, var: &str, expected: &str) {
        let out = self
            .exec(&["printenv", var])
            .unwrap_or_else(|e| panic!("printenv {var} failed: {e}"));
        let actual = out.trim();
        assert_eq!(
            actual, expected,
            "Expected {var}={expected:?} but got {actual:?}"
        );
    }

    /// Assert that an environment variable is set and non-empty inside the container.
    #[track_caller]
    pub fn assert_env_set(&self, var: &str) {
        let out = self
            .exec(&["printenv", var])
            .unwrap_or_else(|e| panic!("{var} is not set in container {}: {e}", self.id));
        assert!(
            !out.trim().is_empty(),
            "Expected env var {var} to be set and non-empty in container {}",
            self.id
        );
    }

    /// Assert that a file at `path` inside the container contains `needle`.
    #[track_caller]
    pub fn assert_file_contains(&self, path: &str, needle: &str) {
        let out = self
            .exec(&["cat", path])
            .unwrap_or_else(|e| panic!("cat {path:?} failed in container {}: {e}", self.id));
        assert!(
            out.contains(needle),
            "Expected file {path:?} to contain {needle:?}.\nGot: {out}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_runtime_default() {
        // Default should be docker
        unsafe {
            std::env::remove_var("CONTAINER_RUNTIME");
        }
        assert_eq!(get_runtime(), Runtime::Docker);
    }

    #[test]
    fn test_runtime_cmd() {
        assert_eq!(runtime_cmd(Runtime::Docker), "docker");
        assert_eq!(runtime_cmd(Runtime::Container), "container");
    }
}
