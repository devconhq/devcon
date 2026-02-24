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

//! # Command Handlers
//!
//! This module contains command handler functions that process user commands
//! and orchestrate the execution of various DevCon operations.
//!
//! Each handler function corresponds to a CLI subcommand and is responsible for:
//! - Loading and parsing devcontainer configuration
//! - Loading user configuration from XDG directories
//! - Merging configuration settings
//! - Creating necessary driver instances
//! - Executing the requested operation
//! - Handling errors and returning results

use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

use crate::error::{Error, Result};
use crate::output::OutputFormat;
use crate::{
    config::Config,
    driver::{
        self,
        container::ContainerDriver,
        control_server,
        runtime::{apple::AppleRuntime, docker::DockerRuntime},
    },
    workspace::Workspace,
};
use comfy_table::{Cell, Color, ContentArrangement, Table, presets::UTF8_FULL};
use pidlock::Pidlock;
use serde::Serialize;
use tracing::{debug, info, trace};

/// Helper function to get runtime-specific config
fn get_runtime_specific_config(
    config: &Config,
    runtime_name: &str,
) -> Result<Box<dyn crate::driver::runtime::ContainerRuntime>> {
    let runtime_config = config.get_runtime_config();

    let runtime: Box<dyn crate::driver::runtime::ContainerRuntime> = match runtime_name {
        "docker" => {
            let docker_config = runtime_config.docker.unwrap_or_default();
            Box::new(DockerRuntime::new(docker_config))
        }
        "apple" => {
            let apple_config = runtime_config.apple.unwrap_or_default();
            Box::new(AppleRuntime::new(apple_config))
        }
        _ => return Err(Error::runtime(format!("Unknown runtime: {}", runtime_name))),
    };

    Ok(runtime)
}

/// Returns the path to the devcon serve PID file.
fn get_pid_file_path() -> std::path::PathBuf {
    dirs::runtime_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("devcon.pid")
}

/// Checks if the serve control server is running and warns the user if not.
fn warn_if_serve_not_running() {
    let pid_path = get_pid_file_path();
    let lock = match Pidlock::new_validated(&pid_path) {
        Ok(l) => l,
        Err(_) => return,
    };
    let running = lock.exists() && lock.is_active().unwrap_or(false);
    if !running {
        info!("The devcon control server is not running.");
        eprintln!(
            "⚠️  Warning: The devcon control server is not running. \
             Start it with 'devcon serve' in a seperate terminal to enable agent connections and port forwarding."
        );
        eprint!("Press Enter to continue...");
        let mut input = String::new();
        let _ = std::io::stdin().read_line(&mut input);
    }
}

// ── JSON response structs ──────────────────────────────────────────────────

#[derive(Serialize)]
pub struct ConfigShowResponse {
    pub config: serde_json::Value,
}

#[derive(Serialize)]
pub struct ConfigGetResponse {
    pub property: String,
    pub value: Option<String>,
}

#[derive(Serialize)]
pub struct ConfigSetResponse {
    pub property: String,
    pub value: String,
}

#[derive(Serialize)]
pub struct ConfigUnsetResponse {
    pub property: String,
}

#[derive(Serialize)]
pub struct ConfigValidateResponse {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Serialize)]
pub struct ConfigPathResponse {
    pub path: String,
}

#[derive(Serialize)]
pub struct ConfigPropertyEntry {
    pub property: String,
    pub r#type: String,
    pub description: String,
}

#[derive(Serialize)]
pub struct ConfigListResponse {
    pub properties: Vec<ConfigPropertyEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<String>,
}

#[derive(Serialize)]
pub struct BuildResponse {
    pub success: bool,
}

#[derive(Serialize)]
pub struct StartResponse {
    pub container_id: String,
}

#[derive(Serialize)]
pub struct UpResponse {
    pub container_id: String,
}

#[derive(Serialize)]
pub struct FeatureEntry {
    pub name: String,
    pub id: String,
    pub version: String,
}

#[derive(Serialize)]
pub struct InfoResponse {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_image: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dockerfile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub features: Option<Vec<FeatureEntry>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub features_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_exists: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_running: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_is_latest: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_id: Option<String>,
}

/// Handles the config show command to display current configuration.
///
/// This function loads the current configuration and displays it as YAML
/// with comprehensive comments showing all available options.
///
/// # Errors
///
/// Returns an error if the config cannot be loaded or serialized.
pub fn handle_config_show(config_path: Option<PathBuf>, output: OutputFormat) -> Result<()> {
    let config = Config::load(config_path)?;

    if output == OutputFormat::Json {
        let json_value = serde_json::to_value(&config)?;
        let response = ConfigShowResponse { config: json_value };
        println!("{}", serde_json::to_string_pretty(&response)?);
        return Ok(());
    }

    let yaml = yaml_serde::to_string(&config)?;

    // Add comprehensive comments header
    let documented_yaml = format!(
        r#"# DevCon Configuration File
# This file contains user-specific settings for DevCon.
# All fields are optional and will use defaults if not specified.
#
# Available properties (use 'devcon config list' to see all):
#
# General Settings:
#   dotfilesRepository: URL to dotfiles repository
#   dotfilesInstallCommand: Custom install command for dotfiles
#   defaultShell: Default shell for shell command (e.g., /bin/zsh)
#   buildPath: Default build path for container builds
#   runtime: Container runtime (auto, docker, apple) - default: auto
#
# Agent Settings (under 'agents'):
#   binaryUrl: URL to precompiled agent binary
#   gitRepository: Git repository URL for building agent from source
#   gitBranch: Git branch for agent source (default: main)
#   disable: Disable agent installation (true/false)
#
# Runtime Settings (under 'runtimeConfig'):
#   docker.buildMemory: Memory limit for Docker builds (e.g., 4g, 512m)
#   docker.buildCpu: CPU limit for Docker builds (e.g., 2, 0.5)
#   apple.buildMemory: Memory limit for Apple builds (default: 4g)
#   apple.buildCpu: CPU limit for Apple builds (e.g., 2, 0.5)
#
# Agent Forwarding Settings (under 'agentForwarding'):
#   sshEnabled: Enable SSH agent forwarding (true/false)
#   gpgEnabled: Enable GPG agent forwarding (true/false)
#   sshSocketPath: Override SSH agent socket path (auto-detected if unset)
#   gpgSocketPath: Override GPG agent socket path (auto-detected if unset)
#
# Current Configuration:

{}
"#,
        yaml
    );

    println!("{}", documented_yaml);
    Ok(())
}

/// Handles the config get command to retrieve a single property value.
///
/// # Errors
///
/// Returns an error if the config cannot be loaded or the property doesn't exist.
pub fn handle_config_get(
    property: &str,
    config_path: Option<PathBuf>,
    output: OutputFormat,
) -> Result<()> {
    let config = Config::load(config_path)?;

    let value = config.get_value(property);

    if output == OutputFormat::Json {
        let response = ConfigGetResponse {
            property: property.to_string(),
            value: value.clone(),
        };
        println!("{}", serde_json::to_string_pretty(&response)?);
        return Ok(());
    }

    match value {
        Some(value) => {
            println!("{}", value);
            Ok(())
        }
        None => {
            println!("Property '{}' is not set", property);
            Ok(())
        }
    }
}

/// Handles the config set command to set a property value.
///
/// # Errors
///
/// Returns an error if the config cannot be loaded, the property is invalid,
/// or the value fails validation.
pub fn handle_config_set(
    property: &str,
    value: &str,
    config_path: Option<PathBuf>,
    output: OutputFormat,
) -> Result<()> {
    let mut config = Config::load(config_path)?;

    config.set_value(property, value.to_string())?;
    config.save()?;

    if output == OutputFormat::Json {
        let response = ConfigSetResponse {
            property: property.to_string(),
            value: value.to_string(),
        };
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!("Set {} = {}", property, value);
    }
    Ok(())
}

/// Handles the config unset command to remove a property value.
///
/// # Errors
///
/// Returns an error if the config cannot be loaded or saved.
pub fn handle_config_unset(
    property: &str,
    config_path: Option<PathBuf>,
    output: OutputFormat,
) -> Result<()> {
    let mut config = Config::load(config_path)?;

    config.unset_value(property)?;
    config.save()?;

    if output == OutputFormat::Json {
        let response = ConfigUnsetResponse {
            property: property.to_string(),
        };
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!("Unset {}", property);
    }
    Ok(())
}

/// Handles the config validate command to check all configuration values.
///
/// # Errors
///
/// Returns an error (with exit code 1) if any configuration values are invalid.
pub fn handle_config_validate(config_path: Option<PathBuf>, output: OutputFormat) -> Result<()> {
    let config = Config::load(config_path)?;

    match config.validate() {
        Ok(()) => {
            if output == OutputFormat::Json {
                let response = ConfigValidateResponse {
                    valid: true,
                    error: None,
                };
                println!("{}", serde_json::to_string_pretty(&response)?);
            } else {
                println!("✓ Configuration is valid");
            }
            Ok(())
        }
        Err(e) => {
            if output == OutputFormat::Json {
                let response = ConfigValidateResponse {
                    valid: false,
                    error: Some(e.to_string()),
                };
                println!("{}", serde_json::to_string_pretty(&response)?);
                Ok(())
            } else {
                eprintln!("✗ Configuration validation failed:");
                eprintln!("  {}", e);
                std::process::exit(1);
            }
        }
    }
}

/// Handles the config path command to show the configuration file location.
///
/// # Errors
///
/// Returns an error if the config directory cannot be determined.
pub fn handle_config_path(output: OutputFormat) -> Result<()> {
    let config_path = Config::get_config_path()?;

    if output == OutputFormat::Json {
        let response = ConfigPathResponse {
            path: config_path.display().to_string(),
        };
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!("{}", config_path.display());
    }
    Ok(())
}

/// Handles the config list command to display all available properties.
///
/// # Errors
///
/// Returns an error if the table cannot be created or displayed.
pub fn handle_config_list(filter: Option<&str>, output: OutputFormat) -> Result<()> {
    let properties = Config::list_properties(filter);

    if output == OutputFormat::Json {
        let entries: Vec<ConfigPropertyEntry> = properties
            .iter()
            .map(|(property, prop_type, description)| ConfigPropertyEntry {
                property: property.to_string(),
                r#type: prop_type.to_string(),
                description: description.to_string(),
            })
            .collect();
        let response = ConfigListResponse {
            properties: entries,
            filter: filter.map(|f| f.to_string()),
        };
        println!("{}", serde_json::to_string_pretty(&response)?);
        return Ok(());
    }

    if properties.is_empty() {
        if let Some(f) = filter {
            println!("No properties match filter: {}", f);
        } else {
            println!("No properties available");
        }
        return Ok(());
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic);

    // Add header
    table.set_header(vec![
        Cell::new("Property").fg(Color::Green),
        Cell::new("Type").fg(Color::Green),
        Cell::new("Description").fg(Color::Green),
    ]);

    // Add rows
    for (property, prop_type, description) in properties {
        table.add_row(vec![
            Cell::new(property),
            Cell::new(prop_type),
            Cell::new(description),
        ]);
    }

    println!("{}", table);

    if let Some(f) = filter {
        println!("\nShowing properties matching: {}", f);
    }

    Ok(())
}

/// Handles the build command for creating a development container.
///
/// This function:
/// 1. Loads the user configuration from XDG directories
/// 2. Loads the devcontainer configuration from the specified path
/// 3. Merges additional features from user config
/// 4. Creates a `ContainerDriver` instance
/// 5. Builds the container image with all configured features
///
/// # Arguments
///
/// * `path` - The path to the project directory containing `.devcontainer/devcontainer.json`
/// * `build_path` - Optional path to the build directory
///
/// # Errors
///
/// Returns an error if:
/// - The devcontainer configuration cannot be found or parsed
/// - Additional features cannot be merged
/// - The container build process fails
/// - Required dependencies are missing
///
/// # Examples
///
/// ```no_run
/// use std::path::PathBuf;
/// # use devcon::command::handle_build_command;
///
/// let project_path = PathBuf::from("/path/to/project");
/// handle_build_command(project_path, None, None, devcon::output::OutputFormat::Text)?;
/// # Ok::<(), devcon::error::Error>(())
/// ```
pub fn handle_build_command(
    path: PathBuf,
    build_path: Option<PathBuf>,
    config_path: Option<PathBuf>,
    output: OutputFormat,
) -> Result<()> {
    let config = Config::load(config_path)?;

    trace!("Config loaded {:?}", config);
    let devcontainer_workspace = Workspace::try_from(path)?;

    // Resolve build_path: CLI argument takes precedence over config
    let effective_build_path = build_path.or_else(|| config.build_path.as_ref().map(PathBuf::from));

    // Create runtime based on config
    let runtime_name = config.resolve_runtime()?;
    debug!("Using runtime {:?}", runtime_name);
    let runtime = get_runtime_specific_config(&config, &runtime_name)?;

    let driver = ContainerDriver::new_silent(config, runtime, output == OutputFormat::Json);

    let result = driver.build(devcontainer_workspace, &[], effective_build_path);

    if result.is_err() {
        return Err(Error::new(format!(
            "Failed to build the development container. Error: {:?}",
            result.err()
        )));
    }

    if output == OutputFormat::Json {
        let response = BuildResponse { success: true };
        println!("{}", serde_json::to_string_pretty(&response)?);
    }

    Ok(())
}

/// Handles the start command for launching a development container.
///
/// This function:
/// 1. Loads the user configuration from XDG directories
/// 2. Loads the devcontainer configuration from the specified path
/// 3. Resolves the canonical path to the project directory
/// 4. Creates a `ContainerDriver` instance
/// 5. Starts the container with the project mounted as a volume and env variables
///
/// # Arguments
///
/// * `path` - The path to the project directory containing `.devcontainer/devcontainer.json`
///
/// # Errors
///
/// Returns an error if:
/// - The devcontainer configuration cannot be found or parsed
/// - The path cannot be canonicalized
/// - The container image doesn't exist (must be built first)
/// - The container fails to start
///
/// # Examples
///
/// ```no_run
/// use std::path::PathBuf;
/// # use devcon::command::handle_start_command;
///
/// let project_path = PathBuf::from("/path/to/project");
/// handle_start_command(project_path, None, devcon::output::OutputFormat::Text)?;
/// # Ok::<(), devcon::error::Error>(())
/// ```
pub fn handle_start_command(
    path: PathBuf,
    config_path: Option<PathBuf>,
    output: OutputFormat,
) -> Result<()> {
    warn_if_serve_not_running();
    let config = Config::load(config_path)?;
    trace!("Config loaded {:?}", config);
    let devcontainer_workspace = Workspace::try_from(path.clone())?;

    // Create runtime based on config
    let runtime_name = config.resolve_runtime()?;
    debug!("Using runtime {:?}", runtime_name);
    let runtime = get_runtime_specific_config(&config, &runtime_name)?;

    let driver = ContainerDriver::new_silent(config, runtime, output == OutputFormat::Json);
    let container_id = driver.start(devcontainer_workspace, &[])?;

    if output == OutputFormat::Json {
        let response = StartResponse { container_id };
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!(
            "Container started successfully. Container ID: {}",
            container_id
        );
    }

    Ok(())
}

/// Handles the shell command for opening a shell in a running container.
///
/// # Arguments
///
/// * `path` - Path to the project directory
/// * `_env` - Environment variables to pass to the shell (currently unused)
///
/// # Errors
///
/// Currently always returns `Ok(())` as it's not implemented.
pub fn handle_shell_command(
    path: PathBuf,
    _env: &[String],
    config_path: Option<PathBuf>,
) -> Result<()> {
    let config = Config::load(config_path)?;
    trace!("Config loaded {:?}", config);
    let devcontainer_workspace = Workspace::try_from(path.clone())?;

    // Create runtime based on config
    let runtime_name = config.resolve_runtime()?;
    debug!("Using runtime {:?}", runtime_name);
    let runtime = get_runtime_specific_config(&config, &runtime_name)?;

    let driver = ContainerDriver::new(config, runtime);
    driver.shell(devcontainer_workspace)?;
    Ok(())
}

/// Handles the ssh command for opening an SSH session to a running container.
pub fn handle_ssh_command(
    path: PathBuf,
    config_path: Option<PathBuf>,
    proxy_mode: bool,
) -> Result<()> {
    let config = Config::load(config_path)?;
    trace!("Config loaded {:?}", config);
    let devcontainer_workspace = Workspace::try_from(path.clone())?;

    let runtime_name = config.resolve_runtime()?;
    debug!("Using runtime {:?}", runtime_name);
    let runtime = get_runtime_specific_config(&config, &runtime_name)?;

    let driver = ContainerDriver::new(config.clone(), runtime);
    let container_id = driver.resolve_running_container_id(
        &devcontainer_workspace,
        "Multiple containers running — select one to connect via SSH",
    )?;

    let shell = config.default_shell.as_deref().unwrap_or("zsh").to_string();
    let proxy = driver::ssh_proxy::SshProxyServer::start(&runtime_name, &container_id, &shell)?;

    if proxy_mode {
        let status = Command::new("nc")
            .arg("127.0.0.1")
            .arg(proxy.port().to_string())
            .status()?;

        if !status.success() {
            return Err(Error::runtime(format!(
                "proxy mode failed with status: {}",
                status
            )));
        }

        return Ok(());
    }

    let status = Command::new("ssh")
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg("-o")
        .arg("UserKnownHostsFile=/dev/null")
        .arg("-o")
        .arg("LogLevel=ERROR")
        .arg("-tt")
        .arg("-p")
        .arg(proxy.port().to_string())
        .arg("devcon@127.0.0.1")
        .status()?;

    if !status.success() {
        return Err(Error::runtime(format!(
            "ssh command failed with status: {}",
            status
        )));
    }

    Ok(())
}

/// Handles the up command for building and starting a development container.
///
/// This function:
/// 1. Loads the user configuration from XDG directories
/// 2. Loads the devcontainer configuration from the specified path
/// 3. Processes features once (avoiding redundant processing)
/// 4. Builds the container image with all configured features
/// 5. Starts the container with the project mounted as a volume
///
/// This is more efficient than running build then start separately, as it
/// processes features only once.
///
/// # Arguments
///
/// * `path` - The path to the project directory containing `.devcontainer/devcontainer.json`
/// * `build_path` - Optional path to the build directory
///
/// # Errors
///
/// Returns an error if:
/// - The devcontainer configuration cannot be found or parsed
/// - Feature processing fails
/// - The container build process fails
/// - The container fails to start
///
/// # Examples
///
/// ```no_run
/// use std::path::PathBuf;
/// # use devcon::command::handle_up_command;
///
/// let project_path = PathBuf::from("/path/to/project");
/// handle_up_command(project_path, None, None, devcon::output::OutputFormat::Text)?;
/// # Ok::<(), devcon::error::Error>(())
/// ```
pub fn handle_up_command(
    path: PathBuf,
    build_path: Option<PathBuf>,
    config_path: Option<PathBuf>,
    output: OutputFormat,
) -> Result<()> {
    warn_if_serve_not_running();
    let config = Config::load(config_path)?;
    trace!("Config loaded {:?}", config);
    let devcontainer_workspace = Workspace::try_from(path)?;

    // Resolve build_path: CLI argument takes precedence over config
    let effective_build_path = build_path.or_else(|| config.build_path.as_ref().map(PathBuf::from));

    // Create runtime based on config
    let runtime_name = config.resolve_runtime()?;
    debug!("Using runtime {:?}", runtime_name);
    let runtime = get_runtime_specific_config(&config, &runtime_name)?;

    let driver = ContainerDriver::new_silent(config, runtime, output == OutputFormat::Json);

    // Process features once
    let (processed_features, _) = driver.prepare_features(&devcontainer_workspace)?;

    // Build with pre-processed features
    driver.build_with_features(
        devcontainer_workspace.clone(),
        &[],
        Some(processed_features.clone()),
        effective_build_path,
    )?;

    // Start the container with pre-processed features
    let container_id =
        driver.start_with_features(devcontainer_workspace, &[], Some(processed_features))?;

    if output == OutputFormat::Json {
        let response = UpResponse { container_id };
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!(
            "Container built and started. Container ID: {}",
            container_id
        );
    }

    Ok(())
}

/// Handles the serve command to start the control server.
///
/// This function starts a TCP server that listens for connections from
/// container agents and manages port forwarding requests.
///
/// # Arguments
///
/// * `port` - The port number to listen on for agent connections
///
/// # Errors
///
/// Returns an error if the server fails to start or bind to the port.
///
/// # Examples
///
/// ```no_run
/// # use devcon::command::handle_serve_command;
/// handle_serve_command(15000, None)?;
/// # Ok::<(), devcon::error::Error>(())
/// ```
pub fn handle_serve_command(
    port: u16,
    config_path: Option<PathBuf>,
    status_mode: Option<crate::StatusMode>,
) -> Result<()> {
    let config = Config::load(config_path)?;
    trace!("Config loaded {:?}", config);

    let pid_path = get_pid_file_path();
    let mut pid_lock = Pidlock::new_validated(&pid_path)
        .map_err(|e| Error::runtime(format!("Failed to create PID file: {e}")))?;
    pid_lock.acquire().map_err(|e| {
        Error::runtime(format!(
            "Failed to acquire PID lock (is serve already running?): {e}"
        ))
    })?;

    // Create runtime based on config
    let runtime_name = config.resolve_runtime()?;
    debug!("Using runtime {:?}", runtime_name);

    if runtime_name == "apple" {
        println!(
            "⚠️  Warning: For the connection to work, you have to register the dns entry 'host.container.internal' for localhost."
        );
        println!("   You can do this by invoking following command with sudo: ");
        println!(
            "     sudo container system dns create --localhost 192.168.2.10 host.container.internal"
        );
        println!(
            "   More info: https://github.com/apple/container/blob/main/docs/how-to.md#access-a-host-service-from-a-container"
        );
    }

    // Create status callback based on mode
    let status_callback: Option<driver::control_server::StatusCallback> = status_mode.map(|mode| {
        use crate::StatusMode;
        let callback: driver::control_server::StatusCallback = match mode {
            StatusMode::Inline => Arc::new(|forwards| {
                driver::control_server::display_forwards_inline(forwards);
            }),
            StatusMode::Fullscreen => Arc::new(|forwards| {
                driver::control_server::display_forwards_fullscreen(forwards);
            }),
        };
        callback
    });

    control_server::start_control_server(port, status_callback)
}

/// Handles the info command to display devcontainer information.
///
/// This function displays:
/// - Devcontainer configuration validation status
/// - Features that will be installed
/// - Whether a container image exists for this project
/// - Whether a container is currently running for this project
///
/// # Arguments
///
/// * `path` - The path to the project directory containing `.devcontainer/devcontainer.json`
/// * `config_path` - Optional path to the config file
///
/// # Errors
///
/// Returns an error if the devcontainer configuration cannot be loaded or parsed.
///
/// # Examples
///
/// ```no_run
/// use std::path::PathBuf;
/// # use devcon::command::handle_info_command;
///
/// let project_path = PathBuf::from("/path/to/project");
/// handle_info_command(project_path, None, devcon::output::OutputFormat::Text)?;
/// # Ok::<(), devcon::error::Error>(())
/// ```
pub fn handle_info_command(
    path: PathBuf,
    config_path: Option<PathBuf>,
    output: OutputFormat,
) -> Result<()> {
    let config = Config::load(config_path)?;
    trace!("Config loaded {:?}", config);

    // Try to load the devcontainer configuration
    let devcontainer_workspace = match Workspace::try_from(path.clone()) {
        Ok(workspace) => workspace,
        Err(e) => {
            if output == OutputFormat::Json {
                let response = InfoResponse {
                    valid: false,
                    error: Some(e.to_string()),
                    name: None,
                    path: None,
                    base_image: None,
                    dockerfile: None,
                    features: None,
                    features_error: None,
                    image_exists: None,
                    image_tag: None,
                    container_running: None,
                    container_is_latest: None,
                    container_name: None,
                    container_id: None,
                };
                println!("{}", serde_json::to_string_pretty(&response)?);
            } else {
                println!("❌ Invalid devcontainer configuration");
                println!("\nError: {}", e);
            }
            return Ok(());
        }
    };

    if output == OutputFormat::Json {
        return handle_info_json(&config, &devcontainer_workspace);
    }

    println!("✓ Valid devcontainer configuration");
    println!();

    // Display basic information
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic);

    table.set_header(vec![
        Cell::new("Property").fg(Color::Green),
        Cell::new("Value").fg(Color::Green),
    ]);

    table.add_row(vec![
        Cell::new("Name"),
        Cell::new(devcontainer_workspace.get_name()),
    ]);

    table.add_row(vec![
        Cell::new("Path"),
        Cell::new(devcontainer_workspace.path.display().to_string()),
    ]);

    if let Some(ref image) = devcontainer_workspace.devcontainer.image {
        table.add_row(vec![Cell::new("Base Image"), Cell::new(image)]);
    }

    if let Some(ref build) = devcontainer_workspace.devcontainer.build
        && let Some(ref dockerfile) = build.dockerfile
    {
        table.add_row(vec![Cell::new("Dockerfile"), Cell::new(dockerfile)]);
    }

    println!("{}", table);
    println!();

    // Display features
    println!("Features to be installed:");
    println!();

    // Create runtime based on config
    let runtime_name = config.resolve_runtime()?;
    debug!("Using runtime {:?}", runtime_name);
    let runtime = get_runtime_specific_config(&config, &runtime_name)?;

    let driver = ContainerDriver::new(config, runtime);

    match driver.prepare_features(&devcontainer_workspace) {
        Ok((processed_features, _)) => {
            if processed_features.is_empty() {
                println!("  No features configured");
            } else {
                let mut features_table = Table::new();
                features_table
                    .load_preset(UTF8_FULL)
                    .set_content_arrangement(ContentArrangement::Dynamic);

                features_table.set_header(vec![
                    Cell::new("#").fg(Color::Green),
                    Cell::new("Feature").fg(Color::Green),
                    Cell::new("ID").fg(Color::Green),
                    Cell::new("Version").fg(Color::Green),
                ]);

                for (idx, feature) in processed_features.iter().enumerate() {
                    features_table.add_row(vec![
                        Cell::new((idx + 1).to_string()),
                        Cell::new(feature.name()),
                        Cell::new(&feature.feature.id),
                        Cell::new(&feature.feature.version),
                    ]);
                }

                println!("{}", features_table);
            }
        }
        Err(e) => {
            println!("  ⚠️  Failed to process features: {}", e);
        }
    }

    println!();

    // Check for existing image
    let base_image_name = format!("devcon-{}", devcontainer_workspace.get_sanitized_name());
    let latest_tag = format!("{}:latest", base_image_name);

    match driver.runtime.images() {
        Ok(images) => {
            let image_exists = images.iter().any(|img| img == &latest_tag);
            if image_exists {
                println!("✓ Container image exists: {}", latest_tag);
                // Show all build tags for this image
                let build_tags: Vec<&String> = images
                    .iter()
                    .filter(|img| img.starts_with(&format!("{}:build-", base_image_name)))
                    .collect();
                if !build_tags.is_empty() {
                    println!("  Build tags:");
                    for tag in &build_tags {
                        println!("    - {}", tag);
                    }
                }
            } else {
                println!("❌ Container image not found: {}", latest_tag);
                println!("   Run 'devcon build' to create the image");
            }
        }
        Err(e) => {
            println!("⚠️  Failed to check for images: {}", e);
        }
    }

    // Check for running container(s)
    let container_name = format!("devcon.{}", devcontainer_workspace.get_sanitized_name());
    let latest_id = driver.runtime.image_id(&latest_tag).unwrap_or(None);

    match driver.runtime.list() {
        Ok(containers) => {
            let running: Vec<_> = containers
                .iter()
                .filter(|(name, _, _)| name == &container_name)
                .collect();
            if running.is_empty() {
                println!("❌ No running container found");
                println!("   Run 'devcon start' or 'devcon up' to start the container");
            } else {
                for (_, img, handle) in &running {
                    let running_id = driver.runtime.image_id(img).unwrap_or(None);
                    let is_current = match (&latest_id, &running_id) {
                        (Some(l), Some(r)) => l == r,
                        _ => img == &latest_tag,
                    };
                    let status = if is_current { "latest" } else { "stale" };
                    println!(
                        "✓ Container is running: {} (ID: {}, image: {}, {})",
                        container_name,
                        handle.id(),
                        img,
                        status,
                    );
                }
            }
        }
        Err(e) => {
            println!("⚠️  Failed to check for running containers: {}", e);
        }
    }

    Ok(())
}

/// JSON output helper for the info command.
/// Collects all information into a single `InfoResponse` and prints it.
fn handle_info_json(config: &Config, devcontainer_workspace: &Workspace) -> Result<()> {
    let name = devcontainer_workspace.get_name().to_string();
    let path = devcontainer_workspace.path.display().to_string();
    let base_image = devcontainer_workspace.devcontainer.image.clone();
    let dockerfile = devcontainer_workspace
        .devcontainer
        .build
        .as_ref()
        .and_then(|b| b.dockerfile.clone());

    // Create runtime based on config
    let runtime_name = config.resolve_runtime()?;
    let runtime = get_runtime_specific_config(config, &runtime_name)?;
    let driver = ContainerDriver::new_silent(config.clone(), runtime, true);

    // Features
    let (features, features_error) = match driver.prepare_features(devcontainer_workspace) {
        Ok((processed_features, _)) => {
            let entries: Vec<FeatureEntry> = processed_features
                .iter()
                .map(|f| FeatureEntry {
                    name: f.name().to_string(),
                    id: f.feature.id.clone(),
                    version: f.feature.version.clone(),
                })
                .collect();
            (Some(entries), None)
        }
        Err(e) => (None, Some(e.to_string())),
    };

    // Image check
    let image_tag = format!(
        "devcon-{}:latest",
        devcontainer_workspace.get_sanitized_name()
    );
    let image_exists = driver
        .runtime
        .images()
        .ok()
        .map(|images| images.iter().any(|img| img == &image_tag));

    // Container check
    let container_name = format!("devcon.{}", devcontainer_workspace.get_sanitized_name());
    let latest_id = driver.runtime.image_id(&image_tag).unwrap_or(None);
    let (container_running, container_is_latest, container_id) = match driver.runtime.list() {
        Ok(containers) => {
            let found = containers
                .iter()
                .find(|(name, _, _)| name == &container_name);
            match found {
                Some((_, img, handle)) => {
                    let running_id = driver.runtime.image_id(img).unwrap_or(None);
                    let is_current = match (&latest_id, &running_id) {
                        (Some(l), Some(r)) => l == r,
                        _ => img == &image_tag,
                    };
                    (Some(true), Some(is_current), Some(handle.id().to_string()))
                }
                None => (Some(false), None, None),
            }
        }
        Err(_) => (None, None, None),
    };

    let response = InfoResponse {
        valid: true,
        error: None,
        name: Some(name),
        path: Some(path),
        base_image,
        dockerfile,
        features,
        features_error,
        image_exists,
        image_tag: Some(image_tag),
        container_running,
        container_is_latest,
        container_name: Some(container_name),
        container_id,
    };

    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_handle_config_command() {
        let result = handle_config_path(OutputFormat::Text);
        assert!(result.is_ok());
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_handle_simple_build_command() {
        let temp_dir = tempfile::tempdir().unwrap();
        let container_content = r#"
        {
            "name": "devcontainer",
            "image": "mcr.microsoft.com/devcontainers/base:ubuntu",
            "features": {
               "ghcr.io/shyim/devcontainers-features/php": {}
            }
        }
        "#;

        let devcontainer_path = temp_dir.path().join(".devcontainer");
        std::fs::create_dir_all(&devcontainer_path).unwrap();
        std::fs::write(
            devcontainer_path.join("devcontainer.json"),
            container_content,
        )
        .unwrap();

        let result = handle_build_command(
            temp_dir.path().to_path_buf(),
            None,
            None,
            OutputFormat::Text,
        );
        assert!(result.is_ok(), "Build command failed: {:?}", result.err());
    }
}
