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

use crate::error::{Error, Result};
use crate::{
    config::Config,
    driver::{
        container::ContainerDriver,
        control_server,
        runtime::{apple::AppleRuntime, docker::DockerRuntime},
    },
    workspace::Workspace,
};
use comfy_table::{Cell, Color, ContentArrangement, Table, presets::UTF8_FULL};
use tracing::{debug, trace};

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

/// Handles the config show command to display current configuration.
///
/// This function loads the current configuration and displays it as YAML
/// with comprehensive comments showing all available options.
///
/// # Errors
///
/// Returns an error if the config cannot be loaded or serialized.
pub fn handle_config_show(config_path: Option<PathBuf>) -> Result<()> {
    let config = Config::load(config_path)?;

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
pub fn handle_config_get(property: &str, config_path: Option<PathBuf>) -> Result<()> {
    let config = Config::load(config_path)?;

    match config.get_value(property) {
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
pub fn handle_config_set(property: &str, value: &str, config_path: Option<PathBuf>) -> Result<()> {
    let mut config = Config::load(config_path)?;

    config.set_value(property, value.to_string())?;
    config.save()?;

    println!("Set {} = {}", property, value);
    Ok(())
}

/// Handles the config unset command to remove a property value.
///
/// # Errors
///
/// Returns an error if the config cannot be loaded or saved.
pub fn handle_config_unset(property: &str, config_path: Option<PathBuf>) -> Result<()> {
    let mut config = Config::load(config_path)?;

    config.unset_value(property)?;
    config.save()?;

    println!("Unset {}", property);
    Ok(())
}

/// Handles the config validate command to check all configuration values.
///
/// # Errors
///
/// Returns an error (with exit code 1) if any configuration values are invalid.
pub fn handle_config_validate(config_path: Option<PathBuf>) -> Result<()> {
    let config = Config::load(config_path)?;

    match config.validate() {
        Ok(()) => {
            println!("✓ Configuration is valid");
            Ok(())
        }
        Err(e) => {
            eprintln!("✗ Configuration validation failed:");
            eprintln!("  {}", e);
            std::process::exit(1);
        }
    }
}

/// Handles the config path command to show the configuration file location.
///
/// # Errors
///
/// Returns an error if the config directory cannot be determined.
pub fn handle_config_path() -> Result<()> {
    let config_path = Config::get_config_path()?;
    println!("{}", config_path.display());
    Ok(())
}

/// Handles the config list command to display all available properties.
///
/// # Errors
///
/// Returns an error if the table cannot be created or displayed.
pub fn handle_config_list(filter: Option<&str>) -> Result<()> {
    let properties = Config::list_properties(filter);

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
/// handle_build_command(project_path, None)?;
/// # Ok::<(), devcon::error::Error>(())
/// ```
pub fn handle_build_command(
    path: PathBuf,
    build_path: Option<PathBuf>,
    config_path: Option<PathBuf>,
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

    let driver = ContainerDriver::new(config, runtime);

    let result = driver.build(devcontainer_workspace, &[], effective_build_path);

    if result.is_err() {
        return Err(Error::new(format!(
            "Failed to build the development container. Error: {:?}",
            result.err()
        )));
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
/// handle_start_command(project_path)?;
/// # Ok::<(), devcon::error::Error>(())
/// ```
pub fn handle_start_command(path: PathBuf, config_path: Option<PathBuf>) -> Result<()> {
    let config = Config::load(config_path)?;
    trace!("Config loaded {:?}", config);
    let devcontainer_workspace = Workspace::try_from(path.clone())?;

    // Create runtime based on config
    let runtime_name = config.resolve_runtime()?;
    debug!("Using runtime {:?}", runtime_name);
    let runtime = get_runtime_specific_config(&config, &runtime_name)?;

    let driver = ContainerDriver::new(config, runtime);
    driver.start(devcontainer_workspace, &[])?;

    println!("Container started. Agent listener running. Press Ctrl+C to stop.");

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
/// handle_up_command(project_path, None)?;
/// # Ok::<(), devcon::error::Error>(())
/// ```
pub fn handle_up_command(
    path: PathBuf,
    build_path: Option<PathBuf>,
    config_path: Option<PathBuf>,
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

    let driver = ContainerDriver::new(config, runtime);

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
    driver.start_with_features(devcontainer_workspace, &[], Some(processed_features))?;

    println!("Container built and started. Agent listener running. Press Ctrl+C to stop.");

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
/// handle_serve_command(15000)?;
/// # Ok::<(), devcon::error::Error>(())
/// ```
pub fn handle_serve_command(port: u16, config_path: Option<PathBuf>) -> Result<()> {
    let config = Config::load(config_path)?;
    trace!("Config loaded {:?}", config);

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
    control_server::start_control_server(port)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_handle_config_command() {
        let result = handle_config_path();
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

        let result = handle_build_command(temp_dir.path().to_path_buf());
        assert!(result.is_ok(), "Build command failed: {:?}", result.err());
    }
}
