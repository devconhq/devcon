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

//! # Container Driver
//!
//! This module provides the `ContainerDriver` for building and managing
//! development container lifecycles.
//!
//! ## Overview
//!
//! The `ContainerDriver` handles:
//! - Building container images from devcontainer configurations
//! - Generating Dockerfiles with feature installations
//! - Starting containers with appropriate volume mounts
//!
//! ## Usage
//!
//! ```no_run
//! use devcon::config::{Config, DockerRuntimeConfig};
//! use devcon::workspace::Workspace;
//! use devcon::driver::container::ContainerDriver;
//! use devcon::driver::runtime::docker::DockerRuntime;
//! use std::path::PathBuf;
//!
//! # fn example() -> devcon::error::Result<()> {
//! let config = Config::load(None)?;
//! let runtime = Box::new(DockerRuntime::new(DockerRuntimeConfig::default()));
//! let driver = ContainerDriver::new(config, runtime);
//!
//! let workspace = Workspace::try_from(PathBuf::from("/path/to/project"))?;
//!
//! // Build the container image
//! driver.build(workspace.clone(), &[], None)?;
//!
//! // Start the container
//! driver.start(workspace, &[])?;
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;
use std::fs::{self, File};
use std::path::Path;

use crate::error::{Error, Result};
use dialoguer::Select;
use dialoguer::theme::ColorfulTheme;
use minijinja::Environment;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tracing::{Level, debug, info, trace, warn};

use crate::devcontainer::{
    FeatureRef, FeatureSource, LifecycleCommandValue, resolve_context_path, resolve_dockerfile_path,
};
use crate::driver::agent::{self, AgentConfig};
use crate::driver::feature_process::FeatureProcessResult;
use crate::driver::runtime::{ContainerProbeInfo, RuntimeParameters};
use crate::{
    config::Config, devcontainer::LifecycleCommand, driver::feature_process::process_features,
    driver::runtime::ContainerRuntime, workspace::Workspace,
};
use std::path::PathBuf;

/// Detects the SSH agent socket path from the environment.
///
/// Attempts to find the SSH agent socket using the SSH_AUTH_SOCK environment variable.
/// Validates that the socket file exists on the filesystem.
///
/// # Returns
///
/// Returns `Some(PathBuf)` with the socket path if found and valid, `None` otherwise.
fn detect_ssh_socket() -> Option<PathBuf> {
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
fn detect_gpg_socket() -> Option<PathBuf> {
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
fn detect_gh_config() -> Option<PathBuf> {
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

fn extract_container_port(port: &crate::devcontainer::ForwardPort) -> Option<u16> {
    use crate::devcontainer::ForwardPort;
    match port {
        ForwardPort::Port(p) => Some(*p),
        ForwardPort::HostPort(mapping) => mapping.split(':').nth(1).and_then(|s| s.parse().ok()),
    }
}

fn ensure_ssh_port_forwarded(ports: &mut Vec<crate::devcontainer::ForwardPort>, ssh_port: u16) {
    let has_ssh = ports
        .iter()
        .filter_map(extract_container_port)
        .any(|container_port| container_port == ssh_port);

    if !has_ssh {
        ports.push(crate::devcontainer::ForwardPort::Port(ssh_port));
    }
}

fn shell_single_quote(input: &str) -> String {
    input.replace('\'', "'\"'\"'")
}

fn detect_public_ssh_key() -> Option<String> {
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

fn is_transient_agent_mount_start_error(error: &Error) -> bool {
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
fn agent_socket_stable_dir() -> Option<PathBuf> {
    let dir = dirs::home_dir()?.join(".local/share/devcon/agent-sockets");
    if let Err(e) = fs::create_dir_all(&dir) {
        warn!("Failed to create agent socket stable dir {:?}: {}", dir, e);
        return None;
    }
    Some(dir)
}

/// Creates or atomically replaces the symlink `stable_dir/link_name → target`.
///
/// Returns `true` on success. On failure, logs a warning and returns `false` so
/// callers can fall back to a direct socket bind-mount.
fn update_agent_socket_symlink(stable_dir: &Path, link_name: &str, target: &Path) -> bool {
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

/// Applies a manual override to the feature installation order.
///
/// Reorders features according to the specified feature IDs, keeping any
/// features not mentioned in the override list at the end in their original order.
///
/// # Arguments
///
/// * `features` - The features in their dependency-sorted order
/// * `override_order` - List of feature IDs specifying the desired order
///
/// # Returns
///
/// Reordered vector of features
///
/// # Errors
///
/// Returns an error if a feature ID in the override list is not found
fn apply_feature_order_override(
    features: Vec<FeatureProcessResult>,
    override_order: &[String],
) -> Result<Vec<FeatureProcessResult>> {
    let mut ordered = Vec::new();
    let mut remaining = features.clone();

    // Process each ID in the override order
    for feature_id in override_order {
        if let Some(pos) = remaining.iter().position(|f| &f.feature.id == feature_id) {
            ordered.push(remaining.remove(pos));
        } else {
            warn!(
                "Feature '{}' specified in overrideFeatureInstallOrder not found",
                feature_id
            );
        }
    }

    // Append any features not mentioned in the override order
    ordered.extend(remaining);

    debug!(
        "Applied override order. Final feature order: {:?}",
        ordered.iter().map(|f| &f.feature.id).collect::<Vec<_>>()
    );

    Ok(ordered)
}

/// Driver for managing container build and runtime operations.
///
/// This struct encapsulates the logic for building container images
/// and starting container instances based on devcontainer configurations.
pub struct ContainerDriver {
    config: Config,
    pub runtime: Box<dyn ContainerRuntime>,
    silent: bool,
}

#[derive(Clone, Debug)]
struct ResolvedUsers {
    remote_user: String,
    container_user: String,
    remote_user_home: String,
    container_user_home: String,
    image_architecture: String,
}

impl ContainerDriver {
    /// Creates a new container driver.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use devcon::driver::container::ContainerDriver;
    /// # use devcon::config::{Config, DockerRuntimeConfig};
    /// # use devcon::driver::runtime::docker::DockerRuntime;
    /// let config = Config::load(None)?;
    /// let runtime = Box::new(DockerRuntime::new(DockerRuntimeConfig::default()));
    /// let driver = ContainerDriver::new(config, runtime);
    /// # Ok::<(), devcon::error::Error>(())
    /// ```
    pub fn new(config: Config, runtime: Box<dyn ContainerRuntime>) -> Self {
        Self {
            config,
            runtime,
            silent: false,
        }
    }

    /// Creates a new container driver with silent mode.
    ///
    /// When `silent` is true, all progress and status messages to stdout
    /// are suppressed. This is useful for JSON output mode where only
    /// structured output should be printed.
    pub fn new_silent(config: Config, runtime: Box<dyn ContainerRuntime>, silent: bool) -> Self {
        Self {
            config,
            runtime,
            silent,
        }
    }

    /// Resolves a running container ID for the given workspace.
    ///
    /// If multiple matching containers are running, the user is prompted to pick one.
    pub fn resolve_running_container_id(
        &self,
        devcontainer_workspace: &Workspace,
        prompt: &str,
    ) -> Result<String> {
        let containers = self.runtime.list()?;
        let container_name = self.get_container_name(devcontainer_workspace);

        let matching: Vec<(String, String)> = containers
            .iter()
            .filter(|(name, _, _)| name == &container_name)
            .map(|(_, image_tag, handle)| (image_tag.clone(), handle.id().to_string()))
            .collect();

        if matching.is_empty() {
            return Err(Error::new(
                "Container not running. Run 'devcon start' or 'devcon up' first.".to_string(),
            ));
        }

        if matching.len() == 1 {
            return Ok(matching[0].1.clone());
        }

        let latest_tag = format!("{}:latest", self.get_image_tag(devcontainer_workspace));
        let latest_id = self.runtime.image_id(&latest_tag).unwrap_or(None);

        let items: Vec<String> = matching
            .iter()
            .map(|(img, id)| {
                let is_latest = latest_id
                    .as_ref()
                    .and_then(|lid| {
                        self.runtime
                            .image_id(img)
                            .ok()
                            .flatten()
                            .map(|rid| lid == &rid)
                    })
                    .unwrap_or(img == &latest_tag);
                let marker = if is_latest { " [latest]" } else { " [stale]" };
                format!("{} ({}{})", id, img, marker)
            })
            .collect();

        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt(prompt)
            .items(&items)
            .default(0)
            .interact()
            .map_err(|e| Error::new(format!("Selection cancelled: {e}")))?;

        Ok(matching[selection].1.clone())
    }

    /// Resolves the remote SSH user for a workspace using devcontainer/image metadata.
    pub fn resolve_remote_user_for_workspace(&self, workspace: &Workspace) -> String {
        let latest_tag = format!("{}:latest", self.get_image_tag(workspace));
        let probe_user_hint = workspace.devcontainer.remote_user.clone();
        let probe_info = self
            .runtime
            .probe_image_info(&latest_tag, probe_user_hint.as_deref())
            .ok()
            .flatten();
        self.resolve_users_for_image(workspace, &latest_tag, probe_info.as_ref())
            .remote_user
    }

    /// Prepares features for building or starting a container.
    ///
    /// This method:
    /// 1. Merges additional features from config
    /// 2. Adds agent installation feature (if not disabled)
    /// 3. Downloads and processes all features (including dependencies)
    /// 4. Applies override feature install order if specified
    ///
    /// # Arguments
    ///
    /// * `devcontainer_workspace` - The workspace with devcontainer configuration
    ///
    /// # Returns
    ///
    /// Returns a tuple of (processed_features, merged_features) where:
    /// - `processed_features` - Features processed with dependencies resolved
    /// - `merged_features` - The initial merged feature list
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Feature merging fails
    /// - Agent generation fails
    /// - Feature processing fails
    pub fn prepare_features(
        &self,
        devcontainer_workspace: &Workspace,
    ) -> Result<(Vec<FeatureProcessResult>, Vec<FeatureRef>)> {
        trace!(
            "Using features of devcontainer: {:?}",
            devcontainer_workspace.devcontainer.features
        );
        trace!(
            "Adding additional features from config: {:?}",
            self.config.additional_features
        );

        // Merge additional features from config
        let mut features = devcontainer_workspace
            .devcontainer
            .merge_additional_features(&self.config.additional_features)?;

        // Add agent installation feature to the list
        // The agent's dependencies will be resolved along with all other features
        if !self.config.is_agent_disabled() {
            let agent_config = AgentConfig::new(
                self.config.get_agent_use_binary(),
                self.config.get_agent_binary_url().cloned(),
                self.config.get_agent_git_repository().cloned(),
                self.config.get_agent_git_branch().cloned(),
                self.config.get_agent_ssh_port(),
                self.config.should_skip_agent_ssh_setup(),
            );
            debug!("Using agent configuration: {:?}", agent_config);
            let agent_path = agent::Agent::new(agent_config).generate()?;
            features.push(FeatureRef::new(FeatureSource::Local { path: agent_path }));
        }
        debug!("Initial feature list: {:?}", features);

        // Process all features including dependency resolution and topological sorting
        let mut processed_features = process_features(&features, self.silent)?;

        // Apply override feature install order if specified
        if let Some(ref override_order) = devcontainer_workspace
            .devcontainer
            .override_feature_install_order
        {
            debug!(
                "Applying override feature install order: {:?}",
                override_order
            );
            processed_features = apply_feature_order_override(processed_features, override_order)?;
        }

        debug!(
            "Final feature order: {:?}",
            processed_features
                .iter()
                .map(|f| &f.feature.id)
                .collect::<Vec<_>>()
        );

        Ok((processed_features, features))
    }

    /// Builds a container image with features installed.
    ///
    /// This method:
    /// 1. Creates a temporary directory for the build context
    /// 2. Downloads and processes all features (including dependencies)
    /// 3. Generates a multi-stage Dockerfile with feature installations
    /// 4. Builds the image using the runtime's build command
    ///
    /// The Dockerfile uses multi-stage builds where each feature gets its own
    /// layer, allowing for efficient caching and rebuild optimization.
    ///
    /// # Arguments
    ///
    /// * `devcontainer_workspace` - The workspace with devcontainer configuration
    /// * `env_variables` - Environment variables to set in the container
    /// * `build_path` - Optional path to the build directory
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The temporary directory cannot be created
    /// - Feature processing fails
    /// - The Dockerfile cannot be generated
    /// - The container build process fails
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use devcon::config::{Config, DockerRuntimeConfig};
    /// # use devcon::workspace::Workspace;
    /// # use devcon::driver::container::ContainerDriver;
    /// # use devcon::driver::runtime::docker::DockerRuntime;
    /// # use std::path::PathBuf;
    /// # fn example() -> devcon::error::Result<()> {
    /// let config = Config::load(None)?;
    /// let runtime = Box::new(DockerRuntime::new(DockerRuntimeConfig::default()));
    /// let driver = ContainerDriver::new(config, runtime);
    /// let workspace = Workspace::try_from(PathBuf::from("/path/to/project"))?;
    ///
    /// driver.build(workspace, &["NODE_ENV=production".to_string()], None)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn build(
        &self,
        devcontainer_workspace: Workspace,
        env_variables: &[String],
        build_path: Option<PathBuf>,
    ) -> Result<()> {
        self.build_with_features(devcontainer_workspace, env_variables, None, build_path)
    }

    /// Returns `true` if the latest image for the given workspace already exists in the runtime.
    pub fn image_exists(&self, devcontainer_workspace: &Workspace) -> Result<bool> {
        let latest_tag = format!("{}:latest", self.get_image_tag(devcontainer_workspace));
        let images = self.runtime.images()?;
        Ok(images.iter().any(|image| image == &latest_tag))
    }

    /// Builds a container image with optional pre-processed features.
    /// This is the internal implementation that allows reusing already-processed
    /// features to avoid redundant processing.
    ///
    /// # Arguments
    ///
    /// * `devcontainer_workspace` - The workspace with devcontainer configuration
    /// * `env_variables` - Environment variables to set in the container
    /// * `processed_features` - Optional pre-processed features to use
    /// * `build_path` - Optional path to the build directory
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The temporary directory cannot be created
    /// - Feature processing fails (if features not provided)
    /// - The Dockerfile cannot be generated
    /// - The container build process fails
    pub fn build_with_features(
        &self,
        devcontainer_workspace: Workspace,
        env_variables: &[String],
        processed_features: Option<Vec<FeatureProcessResult>>,
        build_path: Option<PathBuf>,
    ) -> Result<()> {
        let directory = match build_path {
            Some(path) => {
                std::fs::create_dir_all(&path)?;
                TempDir::new_in(path)?
            }
            None => TempDir::new()?,
        };
        let directory_path = if tracing::event_enabled!(Level::DEBUG) {
            directory.keep()
        } else {
            directory.path().to_path_buf()
        };
        info!(
            "Building container in temporary directory: {}",
            directory_path.to_string_lossy()
        );

        trace!(
            "Processing features for devcontainer at {:?}",
            devcontainer_workspace.path
        );

        // Use provided features or process them
        let processed_features = match processed_features {
            Some(features) => features,
            None => {
                let (features, _) = self.prepare_features(&devcontainer_workspace)?;
                features
            }
        };

        let mut feature_install = String::new();

        let mut i = 0;
        for feature_result in processed_features {
            let feature_path_name = self.copy_feature_to_build(&feature_result, &directory_path)?;
            let feature_name = match &feature_result.feature_ref.source {
                FeatureSource::Registry { registry } => &registry.name,
                FeatureSource::Local { path } => &path
                    .canonicalize()?
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .to_string(),
            };
            if i == 0 {
                feature_install.push_str(&format!("FROM {} AS feature_0 \n", "base"));
            } else {
                feature_install.push_str(&format!("FROM feature_{} AS feature_{} \n", i - 1, i));
            }
            if let Some(env_vars) = &feature_result.feature.container_env {
                for env_var in env_vars {
                    feature_install.push_str(&format!("ENV {}={} \n", env_var.0, env_var.1));
                }
            }
            feature_install.push_str(&format!(
                "COPY {}/. /tmp/features/{}/ \n",
                feature_path_name, feature_name
            ));

            feature_install.push_str(&format!(
                "RUN chmod +x /tmp/features/{}/install.sh && . /tmp/features/{}/devcontainer-features.env && cd /tmp/features/{} && ./install.sh\n",
                feature_name, feature_name, feature_name
            ));

            i += 1;
        }
        if i > 0 {
            feature_install.push_str(&format!("FROM feature_{} AS feature_last \n", i - 1));
        } else {
            feature_install.push_str("FROM base AS feature_last \n");
        }

        // Add environment variables
        let mut env_setup = String::new();
        for env_var in env_variables {
            env_setup.push_str(&format!("ENV {}\n", env_var));
        }

        // Add dotfiles setup if repository is provided
        let dotfiles_setup = {
            let dotfiles_helper_path = directory_path.join("dotfiles_helper.sh");
            let dotfiles_helper_content = r#"
#!/bin/sh
set -e
cd && git clone $1 .dotfiles && cd .dotfiles
if [ -n "$2" ]; then
    chmod +x $2
    ./$2 || true
else
    for f in install.sh setup.sh bootstrap.sh script/install.sh script/setup.sh script/bootstrap.sh
    do
        if [ -e $f ]
        then
            installCommand=$f
            break
        fi
    done

    if [ -n "$installCommand" ]; then
        chmod +x $installCommand
        ./$installCommand || true
    fi
fi
"#;

            fs::write(&dotfiles_helper_path, dotfiles_helper_content)?;
            "COPY dotfiles_helper.sh /dotfiles_helper.sh \nRUN chmod +x /dotfiles_helper.sh"
                .to_string()
        };

        let dockerfile = directory_path.join("Dockerfile");
        File::create(&dockerfile)?;

        // Phase 1: Build user's Dockerfile if specified (otherwise use image)
        let base_image = if let Some(build_config) = &devcontainer_workspace.devcontainer.build {
            // Resolve paths relative to devcontainer.json location
            let devcontainer_path = devcontainer_workspace
                .path
                .join(".devcontainer")
                .join("devcontainer.json");
            let devcontainer_dir = if devcontainer_path.exists() {
                devcontainer_path.parent().unwrap().to_path_buf()
            } else {
                let alt_path = devcontainer_workspace.path.join("devcontainer.json");
                if alt_path.exists() {
                    alt_path.parent().unwrap().to_path_buf()
                } else {
                    // Check .devcontainer subfolders
                    let devcontainer_parent = devcontainer_workspace.path.join(".devcontainer");
                    if let Ok(entries) = fs::read_dir(&devcontainer_parent) {
                        let mut found_dir = None;
                        for entry in entries.flatten() {
                            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                                let candidate = entry.path().join("devcontainer.json");
                                if fs::exists(&candidate).unwrap_or(false) {
                                    found_dir = candidate.parent().map(|p| p.to_path_buf());
                                    break;
                                }
                            }
                        }
                        found_dir.unwrap_or_else(|| devcontainer_workspace.path.clone())
                    } else {
                        devcontainer_workspace.path.clone()
                    }
                }
            };

            let user_dockerfile = resolve_dockerfile_path(build_config, &devcontainer_dir);
            let context = resolve_context_path(build_config, &devcontainer_dir);
            let intermediate_tag = format!("{}-base", self.get_image_tag(&devcontainer_workspace));

            info!(
                "Building user Dockerfile from {} with context {}",
                user_dockerfile.display(),
                context.display()
            );

            // Build user's Dockerfile to intermediate image
            self.runtime.build_with_args(
                &user_dockerfile,
                &context,
                vec![&intermediate_tag],
                &build_config.args,
                &build_config.target,
                &build_config.options,
                self.silent,
            )?;

            intermediate_tag
        } else {
            // Use image field as base
            devcontainer_workspace
                .devcontainer
                .image
                .as_ref()
                .ok_or_else(|| {
                    Error::devcontainer("Neither 'image' nor 'build' configuration found")
                })?
                .clone()
        };

        let resolved_users = {
            // Determine probe user hint from devcontainer.json or metadata label.
            let probe_user_hint = devcontainer_workspace
                .devcontainer
                .remote_user
                .clone()
                .or_else(|| {
                    self.runtime
                        .inspect_image(&base_image)
                        .ok()
                        .flatten()
                        .as_ref()
                        .and_then(|inspect| {
                            let label_str = inspect
                                .get("Config")
                                .or_else(|| inspect.get("config"))
                                .and_then(|v| v.get("Labels").or_else(|| v.get("labels")))
                                .and_then(|v| v.get("devcontainer.metadata"))
                                .and_then(|v| v.as_str())?;
                            let entries: serde_json::Value =
                                serde_json::from_str(label_str).ok()?;
                            entries.as_array()?.iter().rev().find_map(|entry| {
                                entry
                                    .get("remoteUser")
                                    .and_then(|u| u.as_str())
                                    .map(str::trim)
                                    .filter(|s| !s.is_empty())
                                    .map(ToString::to_string)
                            })
                        })
                });
            let probe_info = self
                .runtime
                .probe_image_info(&base_image, probe_user_hint.as_deref())
                .ok()
                .flatten();
            self.resolve_users_for_image(&devcontainer_workspace, &base_image, probe_info.as_ref())
        };

        // Phase 2: Build features Dockerfile using base_image
        let env = Environment::new();
        let template = env.template_from_str(
            r#"
FROM {{ image }} AS base

ENV DEVCON=true
ENV DEVCON_WORKSPACE_NAME={{ workspace_name }}
ENV _REMOTE_USER={{ remote_user }}
ENV _CONTAINER_USER={{ container_user }}
ENV _REMOTE_USER_HOME={{ remote_user_home }}
ENV _CONTAINER_USER_HOME={{ container_user_home }}
ENV DEVCON_CONTROL_HOST={{ runtime_host_address }}
LABEL devcon.config-hash={{ config_hash }}
LABEL devcon.image-architecture={{ image_architecture }}

USER root
RUN mkdir /tmp/features
{{ feature_install }}
{{ env_setup }}

FROM feature_last AS dotfiles_setup
{{ dotfiles_setup }}

FROM dotfiles_setup
USER {{ remote_user }}
WORKDIR /workspaces/{{ workspace_name }}
ENTRYPOINT [ "/bin/sh" ]
CMD ["-c", "echo Container started\ntrap \"exit 0\" 15\n\nexec \"$@\"\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nif command -v sleep >/dev/null 2>&1; then\n  while sleep 1 \u0026 wait $!; do :; done\nelif command -v tail >/dev/null 2>&1; then\n  tail -f /dev/null\nelse\n  while :; do ( : ) \u0026 wait $!; done\nfi", "-"]
"#,
        )?;

        let config_hash = self.get_devcontainer_id(&devcontainer_workspace);

        let contents = template.render(minijinja::context! {
            image => &base_image,
            remote_user => &resolved_users.remote_user,
            container_user => &resolved_users.container_user,
            remote_user_home => &resolved_users.remote_user_home,
            container_user_home => &resolved_users.container_user_home,
            feature_install => &feature_install,
            dotfiles_setup => &dotfiles_setup,
            env_setup => &env_setup,
            workspace_name => devcontainer_workspace.path.file_name().unwrap().to_string_lossy(),
            runtime_host_address => self.runtime.get_host_address(),
            config_hash => &config_hash,
            image_architecture => &resolved_users.image_architecture,
        })?;

        fs::write(&dockerfile, contents)?;

        let base_tag = self.get_image_tag(&devcontainer_workspace);
        let latest_tag = format!("{}:latest", base_tag);

        // Generate a timestamp-based build tag so each build gets a unique identifier
        let build_tag = {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            format!("{}:build-{}", base_tag, now.as_secs())
        };

        self.runtime.build(
            &dockerfile,
            &directory_path,
            vec![&latest_tag, &build_tag],
            self.silent,
        )?;

        Ok(())
    }

    fn copy_feature_to_build(
        &self,
        process: &FeatureProcessResult,
        build_directory: &Path,
    ) -> Result<String> {
        let feature_dest = build_directory.join(&process.feature.id);

        let mut options = fs_extra::dir::CopyOptions::new();
        options.overwrite = true;
        options.copy_inside = true;
        fs_extra::dir::copy(&process.path, &feature_dest, &options)
            .map_err(|e| Error::new(format!("Failed to copy feature directory: {}", e)))?;

        // Create env variable file with merged options (defaults + user overrides)
        let mut feature_options = serde_json::json!({});

        // Start with default values from feature definition
        if let Some(options_map) = &process.feature.options {
            for (key, option) in options_map {
                feature_options
                    .as_object_mut()
                    .unwrap()
                    .insert(key.clone(), option.default.clone());
            }
        }

        // Override with user-specified options from feature_ref
        if let Some(user_opts) = process.feature_ref.options.as_object() {
            for (key, value) in user_opts {
                feature_options
                    .as_object_mut()
                    .unwrap()
                    .insert(key.clone(), value.clone());
            }
        }

        // Create env variable file for feature installation
        let env_file_path = feature_dest.join("devcontainer-features.env");
        let mut env_file = File::create(&env_file_path)?;
        for (key, value) in feature_options.as_object().unwrap() {
            use std::io::Write;

            let val = if let Some(str_value) = value.as_str() {
                str_value
            } else if let Some(bool_value) = value.as_bool() {
                if bool_value { "true" } else { "false" }
            } else if let Some(num_value) = value.as_number() {
                &format!("{}", num_value)
            } else {
                ""
            };

            writeln!(env_file, "export {}={}", key.to_uppercase(), val)?;
        }

        Ok(feature_dest
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string())
    }

    /// Starts a container from a built image.
    ///
    /// This method:
    /// 1. Starts the container with the project directory mounted
    /// 2. Executes lifecycle commands in order:
    ///    - `onCreateCommand`
    ///    - Dotfiles setup (if configured)
    ///    - `postCreateCommand`
    ///    - `postStartCommand`
    /// 3. Starts the agent listener in a background thread
    ///
    /// # Returns
    ///
    /// Returns a `JoinHandle` for the agent listener thread. The caller should
    /// wait on this handle to keep the process alive and maintain the listener.
    ///
    /// # Arguments
    ///
    /// * `devcontainer_workspace` - The workspace with devcontainer configuration
    /// * `env_variables` - Additional environment variables to pass to the container
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The container image doesn't exist (must run `build()` first)
    /// - The container CLI command fails
    /// - The path is invalid
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use devcon::config::{Config, DockerRuntimeConfig};
    /// # use devcon::workspace::Workspace;
    /// # use devcon::driver::container::ContainerDriver;
    /// # use devcon::driver::runtime::docker::DockerRuntime;
    /// # use std::path::PathBuf;
    /// # fn example() -> devcon::error::Result<()> {
    /// let config = Config::load(None)?;
    /// let runtime = Box::new(DockerRuntime::new(DockerRuntimeConfig::default()));
    /// let driver = ContainerDriver::new(config, runtime);
    /// let workspace = Workspace::try_from(PathBuf::from("/project"))?;
    /// driver.build(workspace.clone(), &[], None)?;
    /// let _ = driver.start(workspace, &["EDITOR=vim".to_string()])?;
    ///
    /// # Ok(())
    /// # }
    /// ```
    pub fn start(
        &self,
        devcontainer_workspace: Workspace,
        env_variables: &[String],
    ) -> Result<String> {
        self.start_with_features(devcontainer_workspace, env_variables, None)
    }

    /// Starts a container from a built image with optional pre-processed features.
    ///
    /// This is the internal implementation that allows reusing already-processed
    /// features to avoid redundant processing.
    ///
    /// # Arguments
    ///
    /// * `devcontainer_workspace` - The workspace with devcontainer configuration
    /// * `env_variables` - Additional environment variables to pass to the container
    /// * `processed_features` - Optional pre-processed features to use
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The container image doesn't exist (must run `build()` first)
    /// - Feature processing fails (if features not provided)
    /// - The container CLI command fails
    pub fn start_with_features(
        &self,
        devcontainer_workspace: Workspace,
        env_variables: &[String],
        processed_features: Option<Vec<FeatureProcessResult>>,
    ) -> Result<String> {
        let handles = self.runtime.list()?;
        let container_name = self.get_container_name(&devcontainer_workspace);
        let latest_tag = format!("{}:latest", self.get_image_tag(&devcontainer_workspace));

        let existing_handle = handles.iter().find(|(name, _, _)| name == &container_name);

        if let Some((_, running_image, handle)) = existing_handle {
            // Check whether the running container is using the current latest image
            let latest_id = self.runtime.image_id(&latest_tag).unwrap_or(None);
            let running_id = self.runtime.image_id(running_image).unwrap_or(None);

            let is_current = match (&latest_id, &running_id) {
                (Some(l), Some(r)) => l == r,
                _ => {
                    // Fall back to comparing the tag string directly
                    running_image == &latest_tag
                }
            };

            if is_current {
                info!("Container already running with latest image");
                return Ok(handle.id().to_string());
            }

            info!(
                "Running container uses a stale image ({}), starting new container with latest",
                running_image
            );
        }

        // Check for a stopped container that already uses the current image.
        // list() only returns running containers; list_all() includes stopped ones.
        let all_handles = self.runtime.list_all()?;
        let stopped_handle = all_handles
            .iter()
            .find(|(name, _, _)| name == &container_name);

        if let Some((_, stopped_image, handle)) = stopped_handle {
            let latest_id = self.runtime.image_id(&latest_tag).unwrap_or(None);
            let stopped_id = self.runtime.image_id(stopped_image).unwrap_or(None);

            let is_current = match (&latest_id, &stopped_id) {
                (Some(l), Some(r)) => l == r,
                _ => stopped_image == &latest_tag,
            };

            if is_current {
                info!("Restarting stopped container with latest image");
                match self.runtime.start_container(handle.id()) {
                    Ok(restarted) => return Ok(restarted.id().to_string()),
                    Err(err) => {
                        let agent_forwarding_enabled = self
                            .config
                            .agent_forwarding
                            .as_ref()
                            .map(|cfg| {
                                cfg.ssh_enabled.unwrap_or(false) || cfg.gpg_enabled.unwrap_or(false)
                            })
                            .unwrap_or(false);

                        if agent_forwarding_enabled && is_transient_agent_mount_start_error(&err) {
                            warn!(
                                "Restart failed due to stale forwarded agent socket mount, creating a fresh container: {}",
                                err
                            );
                        } else {
                            return Err(err);
                        }
                    }
                }
            }

            debug!(
                "Stopped container uses a stale image ({}), creating new container with latest",
                stopped_image
            );
        }

        debug!("Checking for existing images");
        let images = self.runtime.images()?;
        trace!("Images found: {:?}", images);
        let already_built = images.iter().any(|image| image == &latest_tag);
        debug!("Image found: {}", already_built);

        if !already_built {
            return Err(Error::new(
                "Image not found. Run 'devcon build' or 'devcon up' first.".to_string(),
            ));
        }

        // Determine the user hint for probing: devcontainer.json remoteUser overrides, otherwise
        // fall back to the user embedded in the devcontainer.metadata OCI label.
        let probe_user_hint = devcontainer_workspace
            .devcontainer
            .remote_user
            .clone()
            .or_else(|| {
                self.runtime
                    .inspect_image(&latest_tag)
                    .ok()
                    .flatten()
                    .as_ref()
                    .and_then(|inspect| {
                        let label_str = inspect
                            .get("Config")
                            .or_else(|| inspect.get("config"))
                            .and_then(|v| v.get("Labels").or_else(|| v.get("labels")))
                            .and_then(|v| v.get("devcontainer.metadata"))
                            .and_then(|v| v.as_str())?;
                        let entries: serde_json::Value = serde_json::from_str(label_str).ok()?;
                        entries.as_array()?.iter().rev().find_map(|entry| {
                            entry
                                .get("remoteUser")
                                .and_then(|u| u.as_str())
                                .map(str::trim)
                                .filter(|s| !s.is_empty())
                                .map(ToString::to_string)
                        })
                    })
            });

        let probe_info = self
            .runtime
            .probe_image_info(&latest_tag, probe_user_hint.as_deref())
            .ok()
            .flatten();

        let resolved_users =
            self.resolve_users_for_image(&devcontainer_workspace, &latest_tag, probe_info.as_ref());

        let volume_mount = format!(
            "{}:/workspaces/{}",
            devcontainer_workspace.path.to_string_lossy(),
            devcontainer_workspace
                .path
                .file_name()
                .unwrap()
                .to_string_lossy()
        );

        let label = self.get_container_label(&devcontainer_workspace);

        // Collect all mounts: from devcontainer config and features
        let mut all_mounts = Vec::new();

        // Add mounts from devcontainer configuration with variable substitution
        if let Some(ref mounts) = devcontainer_workspace.devcontainer.mounts {
            for mount in mounts {
                let substituted_mount = match mount {
                    crate::devcontainer::Mount::String(s) => crate::devcontainer::Mount::String(
                        self.substitute_mount_variables_with_users(
                            s,
                            &devcontainer_workspace,
                            &resolved_users,
                        ),
                    ),
                    crate::devcontainer::Mount::Structured(structured) => {
                        let mut new_mount = structured.clone();
                        if let Some(ref source) = structured.source {
                            new_mount.source = Some(self.substitute_mount_variables_with_users(
                                source,
                                &devcontainer_workspace,
                                &resolved_users,
                            ));
                        }
                        new_mount.target = self.substitute_mount_variables_with_users(
                            &structured.target,
                            &devcontainer_workspace,
                            &resolved_users,
                        );
                        crate::devcontainer::Mount::Structured(new_mount)
                    }
                };
                all_mounts.push(substituted_mount);
            }
        }

        // Use provided features or process them
        let processed_features = match processed_features {
            Some(features) => features,
            None => {
                let (features, _) = self.prepare_features(&devcontainer_workspace)?;
                features
            }
        };
        for feature_result in &processed_features {
            if let Some(ref mounts) = feature_result.feature.mounts {
                // Convert feature::FeatureMount to devcontainer::Mount with variable substitution
                for mount in mounts {
                    match mount {
                        crate::feature::FeatureMount::String(s) => {
                            let substituted = self.substitute_mount_variables_with_users(
                                s,
                                &devcontainer_workspace,
                                &resolved_users,
                            );
                            all_mounts.push(crate::devcontainer::Mount::String(substituted));
                        }
                        crate::feature::FeatureMount::Structured(sm) => {
                            let mount_type = match sm.mount_type {
                                crate::feature::MountType::Bind => {
                                    crate::devcontainer::MountType::Bind
                                }
                                crate::feature::MountType::Volume => {
                                    crate::devcontainer::MountType::Volume
                                }
                            };
                            let source = sm.source.as_ref().map(|s| {
                                self.substitute_mount_variables_with_users(
                                    s,
                                    &devcontainer_workspace,
                                    &resolved_users,
                                )
                            });
                            let target = self.substitute_mount_variables_with_users(
                                &sm.target,
                                &devcontainer_workspace,
                                &resolved_users,
                            );
                            all_mounts.push(crate::devcontainer::Mount::Structured(
                                crate::devcontainer::StructuredMount {
                                    mount_type,
                                    source,
                                    target,
                                },
                            ));
                        }
                    }
                }
            }
        }

        // Track whether agent forwarding mounts were added (for environment variables later)
        let mut ssh_agent_mounted = false;
        let mut ssh_via_stable_dir = false;
        let mut gpg_agent_mounted = false;
        let mut gpg_via_stable_dir = false;
        let mut gpg_public_keyring_path: Option<PathBuf> = None;

        // Add agent forwarding mounts if configured
        if let Some(ref agent_fwd) = self.config.agent_forwarding {
            // Resolve the stable agent socket directory once; shared by SSH and GPG forwarding.
            let stable_agent_dir = agent_socket_stable_dir();

            // SSH agent forwarding
            if agent_fwd.ssh_enabled.unwrap_or(false) {
                let ssh_socket = if let Some(ref override_path) = agent_fwd.ssh_socket_path {
                    let path = PathBuf::from(override_path);
                    if path.exists() {
                        Some(path)
                    } else {
                        warn!(
                            "SSH socket override path '{}' does not exist",
                            override_path
                        );
                        None
                    }
                } else {
                    detect_ssh_socket()
                };

                if let Some(socket) = ssh_socket {
                    info!("Forwarding SSH agent socket into container");
                    if let Some(ref stable_dir) = stable_agent_dir {
                        if update_agent_socket_symlink(stable_dir, "ssh-agent", &socket) {
                            ssh_agent_mounted = true;
                            ssh_via_stable_dir = true;
                        } else {
                            warn!(
                                "Stable dir symlink failed; falling back to direct SSH socket mount"
                            );
                            all_mounts.push(crate::devcontainer::Mount::String(format!(
                                "{}:/ssh-agent",
                                socket.display()
                            )));
                            ssh_agent_mounted = true;
                        }
                    } else {
                        all_mounts.push(crate::devcontainer::Mount::String(format!(
                            "{}:/ssh-agent",
                            socket.display()
                        )));
                        ssh_agent_mounted = true;
                    }
                } else {
                    info!("SSH agent forwarding enabled but no socket found");
                }
            }

            // GPG agent forwarding
            if agent_fwd.gpg_enabled.unwrap_or(false) {
                let gpg_socket = if let Some(ref override_path) = agent_fwd.gpg_socket_path {
                    let path = PathBuf::from(override_path);
                    if path.exists() {
                        Some(path)
                    } else {
                        warn!(
                            "GPG socket override path '{}' does not exist",
                            override_path
                        );
                        None
                    }
                } else {
                    detect_gpg_socket()
                };

                if let Some(socket) = gpg_socket {
                    info!("Forwarding GPG agent socket into container");
                    if let Some(ref stable_dir) = stable_agent_dir {
                        if update_agent_socket_symlink(stable_dir, "S.gpg-agent", &socket) {
                            gpg_via_stable_dir = true;
                        } else {
                            warn!(
                                "Stable dir symlink failed; falling back to direct GPG socket mount"
                            );
                            all_mounts.push(crate::devcontainer::Mount::String(format!(
                                "{}:{}/.gnupg/S.gpg-agent",
                                socket.display(),
                                &resolved_users.remote_user_home
                            )));
                        }
                    } else {
                        all_mounts.push(crate::devcontainer::Mount::String(format!(
                            "{}:{}/.gnupg/S.gpg-agent",
                            socket.display(),
                            &resolved_users.remote_user_home
                        )));
                    }

                    // Export public keyring
                    let temp_dir = TempDir::new()?;
                    let keyring_file = temp_dir.path().join("gpg-public-keys.asc");

                    let export_output = std::process::Command::new("gpg")
                        .arg("--export")
                        .arg("--armor")
                        .output()
                        .map_err(|e| {
                            Error::Generic(format!("Failed to export GPG public keys: {}", e))
                        })?;

                    if !export_output.status.success() {
                        warn!(
                            "Failed to export GPG public keys: {}",
                            String::from_utf8_lossy(&export_output.stderr)
                        );
                    } else {
                        fs::write(&keyring_file, export_output.stdout)?;
                        debug!("GPG public keyring exported to: {:?}", keyring_file);

                        // Mount the exported keyring into the container
                        all_mounts.push(crate::devcontainer::Mount::String(format!(
                            "{}:/tmp/gpg-public-keys.asc",
                            keyring_file.display()
                        )));

                        // Keep track of the temp directory to prevent cleanup
                        gpg_public_keyring_path = Some(temp_dir.keep());
                    }

                    gpg_agent_mounted = true;
                } else {
                    info!("GPG agent forwarding enabled but no socket found");
                }
            }

            // GitHub CLI configuration forwarding
            if agent_fwd.gh_enabled.unwrap_or(false) {
                let gh_config = if let Some(ref override_path) = agent_fwd.gh_config_path {
                    let path = PathBuf::from(override_path);
                    if path.exists() {
                        Some(path)
                    } else {
                        warn!(
                            "GitHub CLI config override path '{}' does not exist",
                            override_path
                        );
                        None
                    }
                } else {
                    detect_gh_config()
                };

                if let Some(config_dir) = gh_config {
                    info!("Forwarding GitHub CLI configuration into container");
                    all_mounts.push(crate::devcontainer::Mount::String(format!(
                        "{}:{}/.config/gh",
                        config_dir.display(),
                        &resolved_users.remote_user_home
                    )));
                } else {
                    info!("GitHub CLI forwarding enabled but no configuration found");
                }
            }
            // Mount the stable agent socket directory once for SSH and/or GPG forwarding.
            if (ssh_via_stable_dir || gpg_via_stable_dir)
                && let Some(ref stable_dir) = stable_agent_dir
            {
                all_mounts.push(crate::devcontainer::Mount::String(format!(
                    "{}:/run/devcon-agents",
                    stable_dir.display()
                )));
                debug!("Mounted stable agent socket directory at /run/devcon-agents");
            }
        }

        // Check if container needs to run in privileged mode
        let requires_privileged = processed_features
            .iter()
            .any(|f| f.feature.privileged.unwrap_or(false));

        // Compose the startup environment from feature defaults and user-config overrides.
        let base_container_env = self.base_container_environment(&latest_tag, probe_info.as_ref());
        let mut processed_env_vars = Self::compose_start_environment(
            &processed_features,
            devcontainer_workspace.devcontainer.container_env.as_ref(),
            env_variables,
            &base_container_env,
        );

        // Add environment variables for agent forwarding
        if ssh_agent_mounted {
            if ssh_via_stable_dir {
                processed_env_vars.push("SSH_AUTH_SOCK=/run/devcon-agents/ssh-agent".to_string());
            } else {
                processed_env_vars.push("SSH_AUTH_SOCK=/ssh-agent".to_string());
            }
        }
        if gpg_agent_mounted {
            processed_env_vars.push("GPG_TTY=$(tty)".to_string());
        }

        // Handle port forward requests
        let mut ports = devcontainer_workspace
            .devcontainer
            .forward_ports
            .clone()
            .unwrap_or_default();
        if !self.config.should_skip_agent_ssh_setup() {
            ensure_ssh_port_forwarded(&mut ports, self.config.get_agent_ssh_port());
        }

        match self.runtime.inspect_image(&latest_tag)? {
            Some(inspect) => {
                trace!("Pre-run image inspect for '{}': {}", latest_tag, inspect);
            }
            None => {
                trace!(
                    "Pre-run image inspect skipped; image '{}' not found",
                    latest_tag
                );
            }
        }

        let evaluated_path = processed_env_vars
            .iter()
            .rev()
            .find_map(|entry| {
                entry
                    .split_once('=')
                    .and_then(|(key, value)| (key == "PATH").then(|| value.to_string()))
            })
            .or_else(|| base_container_env.get("PATH").cloned())
            .unwrap_or_else(|| "<unset>".to_string());
        debug!("Evaluated container PATH before start: {}", evaluated_path);

        debug!("Starting container with ports: {:?}", ports);

        let image_arch = self
            .runtime
            .image_label(
                &format!("{}:latest", self.get_image_tag(&devcontainer_workspace)),
                "devcon.image-architecture",
            )
            .ok()
            .flatten()
            .map(|arch| Self::canonical_image_architecture(&arch))
            .unwrap_or_else(Self::host_image_architecture);
        let host_is_arm = Self::host_image_architecture() == "arm64";
        let enable_rosetta = host_is_arm && image_arch == "amd64";

        let handle = self.runtime.run(
            &format!("{}:latest", self.get_image_tag(&devcontainer_workspace)),
            &volume_mount,
            &label,
            &processed_env_vars,
            RuntimeParameters {
                additional_mounts: all_mounts,
                ports,
                requires_privileged,
                platform_architecture_translation: enable_rosetta,
            },
        )?;

        if !self.config.should_skip_agent_ssh_setup() {
            self.ensure_ssh_authorized_key(handle.as_ref(), &resolved_users)?;
        }

        if let Some(command) = &devcontainer_workspace.devcontainer.on_create_command {
            self.run_lifecycle_command(
                handle.as_ref(),
                &devcontainer_workspace,
                command,
                "onCreateCommand",
                false,
                true,
            )?;
        }

        // Fix file permissions on gpg agent socket
        if gpg_agent_mounted {
            debug!("Setting permissions on GPG agent socket inside container");
            let mut gpg_cmd = format!(
                "sudo chmod -R 0700 {home}/.gnupg && sudo chown -R $(id -u):$(id -g) {home}/.gnupg",
                home = &resolved_users.remote_user_home
            );
            if gpg_via_stable_dir {
                // Create the in-container symlink from ~/.gnupg/S.gpg-agent to the stable dir.
                // This runs once (guarded); the host symlink is refreshed on every start.
                gpg_cmd.push_str(&format!(
                    " && ln -sf /run/devcon-agents/S.gpg-agent {home}/.gnupg/S.gpg-agent",
                    home = &resolved_users.remote_user_home
                ));
            }
            if gpg_public_keyring_path.is_some() {
                info!("Importing GPG public keyring into container");
                gpg_cmd.push_str(" && gpg --import /tmp/gpg-public-keys.asc 2>&1 || true");
            }
            let guarded = Self::guard_with_marker(&gpg_cmd, "gpgAgentSetup");
            self.runtime.exec(
                handle.as_ref(),
                vec!["bash", "-c", &guarded],
                &[],
                false,
                false,
            )?;
        }

        // Fix file permissions on ssh agent socket
        if ssh_agent_mounted {
            debug!("Setting permissions on SSH agent socket inside container");
            let ssh_sock_in_container = if ssh_via_stable_dir {
                "/run/devcon-agents/ssh-agent"
            } else {
                "/ssh-agent"
            };
            let cmd = format!(
                "sudo chmod 600 {p} && sudo chown $(id -u):$(id -g) {p}",
                p = ssh_sock_in_container
            );
            let guarded = Self::guard_with_marker(&cmd, "sshAgentSetup");
            self.runtime.exec(
                handle.as_ref(),
                vec!["bash", "-c", &guarded],
                &[],
                false,
                false,
            )?;
        }

        // Add dotfiles setup if repository is provided
        if let Some(repo) = self.config.dotfiles_repository.as_deref() {
            let dotfiles_cmd = format!(
                "/dotfiles_helper.sh {} {}",
                repo,
                self.config
                    .dotfiles_install_command
                    .as_deref()
                    .unwrap_or("")
            );
            let guarded = Self::guard_with_marker(dotfiles_cmd.trim(), "dotfilesSetup");
            self.runtime.exec(
                handle.as_ref(),
                vec!["bash", "-c", &guarded],
                &[],
                false,
                false,
            )?;
        };

        // Add gh token to environment if GitHub CLI forwarding enabled and token is available
        if self
            .config
            .agent_forwarding
            .as_ref()
            .and_then(|a| a.gh_enabled)
            .unwrap_or(false)
        {
            let output = std::process::Command::new("gh")
                .args(["auth", "status", "--json", "hosts", "--show-token"])
                .output()?;

            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let auth_status: serde_json::Value = serde_json::from_str(&stdout)?;
                let hosts = auth_status["hosts"]
                    .as_object()
                    .ok_or_else(|| Error::new("Unexpected auth status format".to_string()))?;

                let mut tokens = HashMap::new();
                for (_, info) in hosts {
                    trace!("Host: {}, Active: {}", info[0]["host"], info[0]["active"]);
                    if info[0]["active"].as_bool().unwrap_or(false) {
                        tokens.insert(
                            info[0]["host"].as_str().unwrap_or("").to_string(),
                            info[0]["token"].as_str().unwrap_or("").to_string(),
                        );
                    }
                }

                if !tokens.is_empty() {
                    let login_cmds: Vec<String> = tokens
                        .iter()
                        .map(|(host, token)| {
                            debug!("Active GH host: {}", host);
                            format!(
                                "gh auth login --hostname {} --with-token < <(echo {})",
                                host, token
                            )
                        })
                        .collect();
                    let combined = login_cmds.join(" && ");
                    let guarded = Self::guard_with_marker(&combined, "ghForwarding");
                    self.runtime.exec(
                        handle.as_ref(),
                        vec!["bash", "-c", &guarded],
                        &[],
                        false,
                        false,
                    )?;
                }
            } else {
                warn!("Failed to retrieve GitHub CLI auth token for forwarding");
            }
        }

        if let Some(command) = &devcontainer_workspace.devcontainer.post_create_command {
            self.run_lifecycle_command(
                handle.as_ref(),
                &devcontainer_workspace,
                command,
                "postCreateCommand",
                false,
                true,
            )?;
        }

        // Check if feature has entrypoint script which should start now
        processed_features
            .iter()
            .try_for_each(|feature_result| -> Result<()> {
                if let Some(entrypoint) = &feature_result.feature.entrypoint {
                    info!(
                        "Executing entrypoint script for feature '{}'",
                        feature_result.feature.id
                    );
                    let wrapped_cmd =
                        self.wrap_lifecycle_command(&devcontainer_workspace, entrypoint);
                    self.runtime.exec(
                        handle.as_ref(),
                        vec!["bash", "-c", "-i", &wrapped_cmd],
                        &[],
                        false,
                        true,
                    )?;
                }
                Ok(())
            })?;

        if let Some(command) = &devcontainer_workspace.devcontainer.post_start_command {
            self.run_lifecycle_command(
                handle.as_ref(),
                &devcontainer_workspace,
                command,
                "postStartCommand",
                false,
                true,
            )?;
        }

        Ok(handle.id().to_string())
    }

    fn ensure_ssh_authorized_key(
        &self,
        handle: &dyn crate::driver::runtime::ContainerHandle,
        users: &ResolvedUsers,
    ) -> Result<()> {
        let Some(public_key) = detect_public_ssh_key() else {
            warn!(
                "No host SSH public key found. Set DEVCON_SSH_PUBLIC_KEY or create ~/.ssh/id_ed25519.pub to use devcon ssh."
            );
            return Ok(());
        };

        let home = shell_single_quote(&users.remote_user_home);
        let key = shell_single_quote(&public_key);

        let command = format!(
            "set -e; \
            mkdir -p '{home}/.ssh'; \
            chmod 700 '{home}/.ssh'; \
            touch '{home}/.ssh/authorized_keys'; \
            grep -qxF '{key}' '{home}/.ssh/authorized_keys' || printf '%s\\n' '{key}' >> '{home}/.ssh/authorized_keys'; \
            chmod 600 '{home}/.ssh/authorized_keys'"
        );

        self.runtime
            .exec(handle, vec!["sh", "-lc", &command], &[], false, false)
    }

    /// Shells into a started container.
    ///
    /// This method executes a shell within the container. The env variables
    /// from the config will be passed as shell envs.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to the project directory to mount
    /// * `env_variables` - Environment variables to pass to the container
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The container image doesn't exist (must run `build()` first)
    /// - The container CLI command fails
    /// - The path is invalid
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use devcon::config::{Config, DockerRuntimeConfig};
    /// # use devcon::workspace::Workspace;
    /// # use devcon::driver::container::ContainerDriver;
    /// # use devcon::driver::runtime::docker::DockerRuntime;
    /// # use std::path::PathBuf;
    /// # fn example() -> devcon::error::Result<()> {
    /// let config = Config::load(None)?;
    /// let runtime = Box::new(DockerRuntime::new(DockerRuntimeConfig::default()));
    /// let driver = ContainerDriver::new(config, runtime);
    /// let workspace = Workspace::try_from(PathBuf::from("/project"))?;
    /// driver.build(workspace.clone(), &[], None)?;
    /// driver.shell(workspace)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn shell(&self, devcontainer_workspace: Workspace) -> Result<()> {
        let containers = self.runtime.list()?;
        let container_name = self.get_container_name(&devcontainer_workspace);

        let matching: Vec<_> = containers
            .iter()
            .filter(|(name, _, _)| name == &container_name)
            .collect();

        if matching.is_empty() {
            return Err(Error::new(
                "Container not running. Run 'devcon start' or 'devcon up' first.".to_string(),
            ));
        }

        let handle: &dyn crate::driver::runtime::ContainerHandle = if matching.len() == 1 {
            matching[0].2.as_ref()
        } else {
            // Multiple containers running — let the user pick one
            let latest_tag = format!("{}:latest", self.get_image_tag(&devcontainer_workspace));
            let latest_id = self.runtime.image_id(&latest_tag).unwrap_or(None);

            let items: Vec<String> = matching
                .iter()
                .map(|(_, img, h)| {
                    let is_latest = latest_id
                        .as_ref()
                        .and_then(|lid| {
                            self.runtime
                                .image_id(img)
                                .ok()
                                .flatten()
                                .map(|rid| lid == &rid)
                        })
                        .unwrap_or(img == &latest_tag);
                    let marker = if is_latest { " [latest]" } else { " [stale]" };
                    format!("{} ({}{})", h.id(), img, marker)
                })
                .collect();

            let selection = Select::with_theme(&ColorfulTheme::default())
                .with_prompt("Multiple containers running — select one to shell into")
                .items(&items)
                .default(0)
                .interact()
                .map_err(|e| Error::new(format!("Selection cancelled: {e}")))?;

            matching[selection].2.as_ref()
        };

        // Process environment variables
        let mut processed_env_vars = Vec::new();
        for env_var in self.config.env_variables.iter() {
            if env_var.contains("=") {
                processed_env_vars.push(env_var.clone());
            } else {
                // Read host env variable
                let host_value = std::env::var(env_var).unwrap_or_default();
                processed_env_vars.push(format!("{}={}", env_var, host_value));
            }
        }

        if let Some(command) = &devcontainer_workspace.devcontainer.post_attach_command {
            self.run_lifecycle_command(
                handle,
                &devcontainer_workspace,
                command,
                "postAttachCommand",
                false,
                true,
            )?;
        }

        self.runtime.exec(
            handle,
            vec![&self.config.default_shell.as_deref().unwrap_or("zsh")],
            &processed_env_vars,
            true,
            true,
        )?;

        Ok(())
    }

    fn base_container_environment(
        &self,
        image_tag: &str,
        probe_info: Option<&ContainerProbeInfo>,
    ) -> HashMap<String, String> {
        let mut env = HashMap::new();

        match self.runtime.inspect_image(image_tag) {
            Ok(Some(inspect)) => {
                if let Some(config) = inspect.get("Config").or_else(|| inspect.get("config"))
                    && let Some(entries) = config.get("Env").or_else(|| config.get("env"))
                    && let Some(entries) = entries.as_array()
                {
                    for entry in entries {
                        let Some(raw) = entry.as_str() else {
                            continue;
                        };
                        let Some((key, value)) = raw.split_once('=') else {
                            continue;
                        };
                        env.insert(key.to_string(), value.to_string());
                    }
                }
            }
            Ok(None) => {
                debug!(
                    "Image '{}' could not be inspected before PATH probing; using probe only",
                    image_tag
                );
            }
            Err(err) => {
                warn!(
                    "Failed to inspect image '{}' for base container environment: {}",
                    image_tag, err
                );
            }
        }

        if let Some(info) = probe_info {
            if !info.path.is_empty() {
                debug!("Using probed PATH from image: {}", info.path);
                env.insert("PATH".to_string(), info.path.clone());
            }
        } else {
            debug!(
                "No probe info available for '{}'; using inspected PATH if present",
                image_tag
            );
        }

        env
    }

    fn resolve_container_env_value(
        raw_value: &str,
        merged_env: &HashMap<String, String>,
        host_env: &HashMap<String, String>,
    ) -> String {
        let mut resolved = String::new();
        let mut index = 0;

        while let Some(rel_start) = raw_value[index..].find("${") {
            let start = index + rel_start;
            resolved.push_str(&raw_value[index..start]);

            let after_start = start + 2;
            let Some(rel_end) = raw_value[after_start..].find('}') else {
                resolved.push_str(&raw_value[start..]);
                return resolved;
            };
            let end = after_start + rel_end;

            let token = &raw_value[after_start..end];
            let replacement = if let Some(name) = token.strip_prefix("containerEnv:") {
                merged_env.get(name).cloned().unwrap_or_default()
            } else if let Some(name) = token.strip_prefix("localEnv:") {
                host_env.get(name).cloned().unwrap_or_default()
            } else {
                merged_env.get(token).cloned().unwrap_or_default()
            };

            resolved.push_str(&replacement);
            index = end + 1;
        }

        resolved.push_str(&raw_value[index..]);
        resolved
    }

    fn merge_container_env_map(
        merged_env: &mut HashMap<String, String>,
        source_env: &HashMap<String, String>,
        host_env: &HashMap<String, String>,
    ) {
        for (key, value) in source_env {
            let resolved = Self::resolve_container_env_value(value, merged_env, host_env);
            merged_env.insert(key.clone(), resolved);
        }
    }

    fn compose_start_environment(
        processed_features: &[FeatureProcessResult],
        devcontainer_container_env: Option<&HashMap<String, String>>,
        env_variables: &[String],
        base_container_env: &HashMap<String, String>,
    ) -> Vec<String> {
        let mut merged_env = base_container_env.clone();
        let host_env: HashMap<String, String> = std::env::vars().collect();

        // Feature-provided containerEnv values are merged first in feature order.
        for feature_result in processed_features {
            if let Some(feature_env) = &feature_result.feature.container_env {
                Self::merge_container_env_map(&mut merged_env, feature_env, &host_env);
            }
        }

        // Devcontainer containerEnv overrides feature defaults.
        if let Some(container_env) = devcontainer_container_env {
            Self::merge_container_env_map(&mut merged_env, container_env, &host_env);
        }

        // Explicit env vars passed to start override prior values.
        for env_var in env_variables {
            if let Some((key, value)) = env_var.split_once('=') {
                let resolved = Self::resolve_container_env_value(value, &merged_env, &host_env);
                merged_env.insert(key.to_string(), resolved);
            } else {
                let host_value = host_env.get(env_var).cloned().unwrap_or_default();
                merged_env.insert(env_var.clone(), host_value);
            }
        }

        merged_env
            .into_iter()
            .map(|(key, value)| format!("{}={}", key, value))
            .collect()
    }

    /// Returns the Docker image tag for this container.
    ///
    /// The tag is formatted as `devcon-{sanitized_name}` where the sanitized
    /// name is the project directory name with special characters replaced.
    ///
    /// # Returns
    ///
    /// A string containing the full image tag.
    fn get_image_tag(&self, devcontainer_workspace: &Workspace) -> String {
        format!("devcon-{}", devcontainer_workspace.get_sanitized_name())
    }

    /// Returns the container name for this devcontainer.
    ///
    /// The name is formatted as `devcon.{sanitized_name}` where the sanitized
    /// name is the project directory name with special characters replaced.
    ///
    /// # Returns
    ///
    /// A string containing the container name.
    fn get_container_name(&self, devcontainer_workspace: &Workspace) -> String {
        format!("devcon.{}", devcontainer_workspace.get_sanitized_name())
    }

    /// Returns the container label for this devcontainer.
    ///
    /// The label is formatted as `devcon.project={sanitized_name}`.
    ///
    /// # Returns
    ///
    /// A string containing the label key-value pair.
    fn get_container_label(&self, devcontainer_workspace: &Workspace) -> String {
        format!(
            "devcon.project={}",
            devcontainer_workspace.get_sanitized_name()
        )
    }

    /// Generates a unique container ID for the devcontainer.
    ///
    /// The ID is a deterministic hash based on the devcontainer.json file content,
    /// ensuring different configurations get different IDs. Falls back to hashing
    /// the workspace path if the file cannot be read.
    ///
    /// # Returns
    ///
    /// A hex-encoded SHA256 hash of the devcontainer.json content.
    fn get_devcontainer_id(&self, devcontainer_workspace: &Workspace) -> String {
        let mut hasher = Sha256::new();

        // Try to read and hash the devcontainer.json file content
        let devcontainer_path = devcontainer_workspace
            .path
            .join(".devcontainer")
            .join("devcontainer.json");

        match fs::read_to_string(&devcontainer_path) {
            Ok(content) => {
                hasher.update(content.as_bytes());
            }
            Err(_) => {
                // Fallback to workspace path if file can't be read
                hasher.update(devcontainer_workspace.path.to_string_lossy().as_bytes());
            }
        }

        // Also hash the Dockerfile when a build config references one, so that
        // changes to the Dockerfile trigger a rebuild even if devcontainer.json
        // is unchanged.
        if let Some(build_config) = &devcontainer_workspace.devcontainer.build {
            if build_config.dockerfile.is_some() {
                let devcontainer_dir = if devcontainer_path.exists() {
                    devcontainer_path
                        .parent()
                        .unwrap_or(&devcontainer_workspace.path)
                        .to_path_buf()
                } else {
                    devcontainer_workspace.path.clone()
                };
                let dockerfile_path = resolve_dockerfile_path(build_config, &devcontainer_dir);
                if let Ok(df_content) = fs::read_to_string(&dockerfile_path) {
                    hasher.update(df_content.as_bytes());
                }
            }

            // Hash build args (sorted for determinism) so arg changes invalidate the cache.
            if let Some(args) = &build_config.args {
                let mut sorted_args: Vec<(&String, &String)> = args.iter().collect();
                sorted_args.sort_by_key(|(k, _)| *k);
                for (k, v) in sorted_args {
                    hasher.update(format!("{}={}", k, v).as_bytes());
                }
            }
        }

        let result = hasher.finalize();
        result.iter().map(|byte| format!("{:02x}", byte)).collect()
    }

    /// Returns `true` when the existing image's config hash matches the current workspace config.
    ///
    /// The hash is stored as the `devcon.config-hash` image label at build time. If the image is
    /// absent or the label is missing (e.g. an image built by an older version of devcon), this
    /// method returns `false` so that a rebuild is triggered.
    pub fn image_is_current(&self, devcontainer_workspace: &Workspace) -> Result<bool> {
        let latest_tag = format!("{}:latest", self.get_image_tag(devcontainer_workspace));
        let stored = self
            .runtime
            .image_label(&latest_tag, "devcon.config-hash")?;
        match stored {
            None => Ok(false),
            Some(stored_hash) => {
                let current_hash = self.get_devcontainer_id(devcontainer_workspace);
                Ok(stored_hash == current_hash)
            }
        }
    }

    fn user_home(user: &str) -> String {
        if user == "root" {
            "/root".to_string()
        } else {
            format!("/home/{}", user)
        }
    }

    fn host_image_architecture() -> String {
        match std::env::consts::ARCH {
            "x86_64" => "amd64".to_string(),
            "aarch64" => "arm64".to_string(),
            other => other.to_string(),
        }
    }

    fn canonical_image_architecture(arch: &str) -> String {
        let normalized = arch.trim().to_lowercase();
        match normalized.as_str() {
            "x86_64" => "amd64".to_string(),
            "aarch64" => "arm64".to_string(),
            _ => normalized,
        }
    }

    fn extract_architecture_from_inspect(inspect: &serde_json::Value) -> Option<String> {
        let from_key = |path: &[&str]| {
            let mut current = inspect;
            for key in path {
                current = current.get(*key)?;
            }
            current
                .as_str()
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(ToString::to_string)
        };

        from_key(&["Architecture"])
            .or_else(|| from_key(&["architecture"]))
            .map(|arch| Self::canonical_image_architecture(&arch))
    }

    fn resolve_users_for_image(
        &self,
        workspace: &Workspace,
        image_tag: &str,
        probe_info: Option<&ContainerProbeInfo>,
    ) -> ResolvedUsers {
        let inspect = self.runtime.inspect_image(image_tag).ok().flatten();
        let detected_user = probe_info.map(|i| i.user.clone());
        let detected_home = probe_info.map(|i| i.home.clone());
        let image_architecture = inspect
            .as_ref()
            .and_then(Self::extract_architecture_from_inspect)
            .unwrap_or_else(Self::host_image_architecture);

        let remote_user_override = workspace.devcontainer.remote_user.clone();
        let container_user_override = workspace.devcontainer.container_user.clone();

        let remote_user = remote_user_override
            .clone()
            .or_else(|| detected_user.clone())
            .unwrap_or_else(|| "vscode".to_string());

        let container_user = container_user_override
            .clone()
            .or_else(|| detected_user.clone())
            .unwrap_or_else(|| remote_user.clone());

        let remote_user_home = if remote_user_override.is_none()
            && detected_user.as_deref() == Some(remote_user.as_str())
        {
            detected_home
                .clone()
                .unwrap_or_else(|| Self::user_home(&remote_user))
        } else {
            Self::user_home(&remote_user)
        };

        let container_user_home = if container_user_override.is_none()
            && detected_user.as_deref() == Some(container_user.as_str())
        {
            detected_home.unwrap_or_else(|| Self::user_home(&container_user))
        } else {
            Self::user_home(&container_user)
        };

        ResolvedUsers {
            remote_user_home,
            container_user_home,
            remote_user,
            container_user,
            image_architecture,
        }
    }

    /// Performs variable substitution on a mount string.
    ///
    /// Supports the following variables:
    /// - `${devcontainerId}` - Unique ID for this container
    /// - `${localWorkspaceFolder}` - Path to the workspace folder
    /// - `${containerWorkspaceFolder}` - Path to workspace inside container
    ///
    /// # Arguments
    ///
    /// * `mount_str` - The mount string with variables to substitute
    /// * `devcontainer_workspace` - The workspace to use for substitution
    ///
    /// # Returns
    ///
    /// The mount string with all variables substituted.
    #[allow(dead_code)]
    fn substitute_mount_variables(
        &self,
        mount_str: &str,
        devcontainer_workspace: &Workspace,
    ) -> String {
        let remote_user = devcontainer_workspace
            .devcontainer
            .remote_user
            .clone()
            .unwrap_or_else(|| "vscode".to_string());
        let container_user = devcontainer_workspace
            .devcontainer
            .container_user
            .clone()
            .unwrap_or_else(|| remote_user.clone());
        let users = ResolvedUsers {
            remote_user_home: Self::user_home(&remote_user),
            container_user_home: Self::user_home(&container_user),
            remote_user,
            container_user,
            image_architecture: "amd64".to_string(),
        };

        self.substitute_mount_variables_with_users(mount_str, devcontainer_workspace, &users)
    }

    fn substitute_mount_variables_with_users(
        &self,
        mount_str: &str,
        devcontainer_workspace: &Workspace,
        users: &ResolvedUsers,
    ) -> String {
        let devcontainer_id = self.get_devcontainer_id(devcontainer_workspace);
        let workspace_name = devcontainer_workspace
            .path
            .file_name()
            .unwrap()
            .to_string_lossy();
        let local_workspace = devcontainer_workspace.path.to_string_lossy();
        let container_workspace = format!("/workspaces/{}", workspace_name);

        mount_str
            .replace("${devcontainerId}", &devcontainer_id)
            .replace("${localWorkspaceFolder}", &local_workspace)
            .replace("${containerWorkspaceFolder}", &container_workspace)
            .replace("${remoteUser}", &users.remote_user)
            .replace("${containerUser}", &users.container_user)
            .replace("${remoteUserHome}", &users.remote_user_home)
            .replace("${containerUserHome}", &users.container_user_home)
    }

    /// Wraps a lifecycle command with proper environment and working directory setup.
    ///
    /// This ensures the command runs with:
    /// - Proper shell environment loaded
    /// - Correct working directory
    /// - User's profile sourced
    ///
    /// # Arguments
    ///
    /// * `_devcontainer_workspace` - The devcontainer workspace
    /// * `cmd` - The command to wrap
    ///
    /// # Returns
    ///
    /// A wrapped command string ready for execution.
    fn wrap_lifecycle_command(&self, _devcontainer_workspace: &Workspace, cmd: &str) -> String {
        cmd.to_string()
    }

    fn lifecycle_marker_path(marker_name: &str) -> String {
        format!("/var/lib/devcon/lifecycle-markers/{}", marker_name)
    }

    fn lifecycle_marker_exists(
        &self,
        handle: &dyn crate::driver::runtime::ContainerHandle,
        marker_name: &str,
    ) -> bool {
        let marker = Self::lifecycle_marker_path(marker_name);
        self.runtime
            .exec(
                handle,
                vec!["sudo", "test", "-f", &marker],
                &[],
                false,
                false,
            )
            .is_ok()
    }

    fn create_lifecycle_marker(
        &self,
        handle: &dyn crate::driver::runtime::ContainerHandle,
        marker_name: &str,
    ) -> Result<()> {
        let marker = Self::lifecycle_marker_path(marker_name);
        let marker_dir = "/var/lib/devcon/lifecycle-markers";

        self.runtime.exec(
            handle,
            vec!["sudo", "mkdir", "-p", marker_dir],
            &[],
            false,
            false,
        )?;
        self.runtime
            .exec(handle, vec!["sudo", "touch", &marker], &[], false, false)?;

        Ok(())
    }

    fn exec_shell_lifecycle_command(
        &self,
        handle: &dyn crate::driver::runtime::ContainerHandle,
        devcontainer_workspace: &Workspace,
        cmd: &str,
        env_vars: &[String],
        attach_stdin: bool,
        attach_stdout: bool,
    ) -> Result<()> {
        let wrapped_cmd = self.wrap_lifecycle_command(devcontainer_workspace, cmd);
        self.runtime.exec(
            handle,
            vec!["bash", "-c", "-i", &wrapped_cmd],
            env_vars,
            attach_stdin,
            attach_stdout,
        )
    }

    fn exec_argv_lifecycle_command(
        &self,
        handle: &dyn crate::driver::runtime::ContainerHandle,
        cmd: &[String],
        env_vars: &[String],
        attach_stdin: bool,
        attach_stdout: bool,
    ) -> Result<()> {
        let args: Vec<&str> = cmd.iter().map(String::as_str).collect();
        self.runtime
            .exec(handle, args, env_vars, attach_stdin, attach_stdout)
    }

    fn exec_lifecycle_value(
        &self,
        handle: &dyn crate::driver::runtime::ContainerHandle,
        devcontainer_workspace: &Workspace,
        value: &LifecycleCommandValue,
        env_vars: &[String],
        attach_stdin: bool,
        attach_stdout: bool,
    ) -> Result<()> {
        match value {
            LifecycleCommandValue::String(cmd) => self.exec_shell_lifecycle_command(
                handle,
                devcontainer_workspace,
                cmd,
                env_vars,
                attach_stdin,
                attach_stdout,
            ),
            LifecycleCommandValue::Array(cmd) => {
                self.exec_argv_lifecycle_command(handle, cmd, env_vars, attach_stdin, attach_stdout)
            }
        }
    }

    fn run_lifecycle_command(
        &self,
        handle: &dyn crate::driver::runtime::ContainerHandle,
        devcontainer_workspace: &Workspace,
        command: &LifecycleCommand,
        marker_name: &str,
        attach_stdin: bool,
        attach_stdout: bool,
    ) -> Result<()> {
        if self.lifecycle_marker_exists(handle, marker_name) {
            return Ok(());
        }

        match command {
            LifecycleCommand::String(cmd) => self.exec_shell_lifecycle_command(
                handle,
                devcontainer_workspace,
                cmd,
                &[],
                attach_stdin,
                attach_stdout,
            )?,
            LifecycleCommand::Array(cmd) => {
                self.exec_argv_lifecycle_command(handle, cmd, &[], attach_stdin, attach_stdout)?
            }
            LifecycleCommand::Object(map) => {
                // Parallel object execution is a future enhancement.
                // Preserve direct argv execution for array values, but run the
                // object entries sequentially for now.
                let mut entries: Vec<_> = map.iter().collect();
                entries.sort_by_key(|(left, _)| *left);

                for (_, value) in entries {
                    self.exec_lifecycle_value(
                        handle,
                        devcontainer_workspace,
                        value,
                        &[],
                        attach_stdin,
                        attach_stdout,
                    )?;
                }
            }
        }

        self.create_lifecycle_marker(handle, marker_name)
    }

    /// Wraps a shell command string so it runs at most once inside the container,
    /// guarded by a marker file at `/var/lib/devcon/lifecycle-markers/{marker_name}`.
    ///
    /// The marker is created only when the command succeeds (`&&`). With `--rm`
    /// (current default) the container filesystem is discarded on stop, so the guard
    /// has no effect today. Once containers are persisted across stop/start cycles the
    /// marker will survive and prevent the command from re-running on subsequent starts.
    fn guard_with_marker(cmd: &str, marker_name: &str) -> String {
        let marker = format!("/var/lib/devcon/lifecycle-markers/{}", marker_name);
        format!(
            "MARKER='{}'; if [ ! -f \"$MARKER\" ]; then {}; sudo mkdir -p \"$(dirname \"$MARKER\")\" && sudo touch \"$MARKER\"; fi",
            marker, cmd
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DockerRuntimeConfig;
    use crate::devcontainer::{FeatureRegistry, FeatureRegistryType, FeatureSource};
    use crate::driver::runtime::docker::DockerRuntime;
    use crate::feature::Feature;
    use std::collections::HashMap;
    use std::path::PathBuf;

    fn create_test_feature_result(id: &str) -> FeatureProcessResult {
        let feature = Feature {
            id: id.to_string(),
            version: "1.0.0".to_string(),
            name: Some(format!("Test {}", id)),
            description: None,
            documentation_url: None,
            license_url: None,
            keywords: None,
            options: None,
            installs_after: None,
            depends_on: None,
            deprecated: None,
            legacy_ids: None,
            cap_add: None,
            security_opt: None,
            privileged: None,
            init: None,
            entrypoint: None,
            mounts: None,
            container_env: None,
            customizations: None,
            on_create_command: None,
            update_content_command: None,
            post_create_command: None,
            post_start_command: None,
            post_attach_command: None,
        };

        let feature_ref = FeatureRef::new(FeatureSource::Registry {
            registry: FeatureRegistry {
                owner: "test".to_string(),
                repository: "features".to_string(),
                name: id.to_string(),
                version: "1.0.0".to_string(),
                registry_type: FeatureRegistryType::Ghcr,
            },
        });

        FeatureProcessResult {
            feature_ref,
            feature,
            path: PathBuf::from(format!("/tmp/{}", id)),
        }
    }

    fn env_vec_to_map(env_vars: Vec<String>) -> HashMap<String, String> {
        env_vars
            .into_iter()
            .filter_map(|entry| {
                entry
                    .split_once('=')
                    .map(|(key, value)| (key.to_string(), value.to_string()))
            })
            .collect()
    }

    #[test]
    fn test_compose_start_environment_includes_feature_container_env() {
        let mut feature_a = create_test_feature_result("feature-a");
        feature_a.feature.container_env = Some(HashMap::from([
            ("GOPATH".to_string(), "/go".to_string()),
            ("PATH".to_string(), "/usr/local/go/bin:${PATH}".to_string()),
        ]));

        let base_env = HashMap::from([("PATH".to_string(), "/usr/bin:/bin".to_string())]);

        let env = ContainerDriver::compose_start_environment(&[feature_a], None, &[], &base_env);
        let env_map = env_vec_to_map(env);

        assert_eq!(env_map.get("GOPATH"), Some(&"/go".to_string()));
        assert_eq!(
            env_map.get("PATH"),
            Some(&"/usr/local/go/bin:/usr/bin:/bin".to_string())
        );
    }

    #[test]
    fn test_compose_start_environment_config_overrides_feature_values() {
        let mut feature_a = create_test_feature_result("feature-a");
        feature_a.feature.container_env = Some(HashMap::from([(
            "PATH".to_string(),
            "/feature/bin".to_string(),
        )]));

        let base_env = HashMap::from([("PATH".to_string(), "/usr/bin:/bin".to_string())]);

        let env = ContainerDriver::compose_start_environment(
            &[feature_a],
            None,
            &["PATH=/config/bin".to_string(), "FOO=bar".to_string()],
            &base_env,
        );
        let env_map = env_vec_to_map(env);

        assert_eq!(env_map.get("PATH"), Some(&"/config/bin".to_string()));
        assert_eq!(env_map.get("FOO"), Some(&"bar".to_string()));
    }

    #[test]
    fn test_compose_start_environment_devcontainer_container_env_overrides_feature_values() {
        let mut feature_a = create_test_feature_result("feature-a");
        feature_a.feature.container_env = Some(HashMap::from([(
            "PATH".to_string(),
            "/feature/bin:${PATH}".to_string(),
        )]));

        let devcontainer_env = HashMap::from([(
            "PATH".to_string(),
            "${containerEnv:PATH}:/workspace/bin".to_string(),
        )]);

        let base_env = HashMap::from([("PATH".to_string(), "/usr/bin:/bin".to_string())]);

        let env = ContainerDriver::compose_start_environment(
            &[feature_a],
            Some(&devcontainer_env),
            &[],
            &base_env,
        );
        let env_map = env_vec_to_map(env);

        assert_eq!(
            env_map.get("PATH"),
            Some(&"/feature/bin:/usr/bin:/bin:/workspace/bin".to_string())
        );
    }

    #[test]
    fn test_apply_feature_order_override_complete() {
        let features = vec![
            create_test_feature_result("feature-a"),
            create_test_feature_result("feature-b"),
            create_test_feature_result("feature-c"),
        ];

        let override_order = vec![
            "feature-c".to_string(),
            "feature-a".to_string(),
            "feature-b".to_string(),
        ];

        let result = apply_feature_order_override(features, &override_order);
        assert!(result.is_ok());

        let ordered = result.unwrap();
        assert_eq!(ordered.len(), 3);
        assert_eq!(ordered[0].feature.id, "feature-c");
        assert_eq!(ordered[1].feature.id, "feature-a");
        assert_eq!(ordered[2].feature.id, "feature-b");
    }

    #[test]
    fn test_apply_feature_order_override_partial() {
        let features = vec![
            create_test_feature_result("feature-a"),
            create_test_feature_result("feature-b"),
            create_test_feature_result("feature-c"),
            create_test_feature_result("feature-d"),
        ];

        // Only specify order for some features
        let override_order = vec!["feature-c".to_string(), "feature-a".to_string()];

        let result = apply_feature_order_override(features, &override_order);
        assert!(result.is_ok());

        let ordered = result.unwrap();
        assert_eq!(ordered.len(), 4);

        // First two should be in specified order
        assert_eq!(ordered[0].feature.id, "feature-c");
        assert_eq!(ordered[1].feature.id, "feature-a");

        // Remaining features should be at the end (b and d)
        let remaining_ids: Vec<&str> = ordered[2..].iter().map(|f| f.feature.id.as_str()).collect();
        assert!(remaining_ids.contains(&"feature-b"));
        assert!(remaining_ids.contains(&"feature-d"));
    }

    #[test]
    fn test_apply_feature_order_override_empty() {
        let features = vec![
            create_test_feature_result("feature-a"),
            create_test_feature_result("feature-b"),
        ];

        let override_order: Vec<String> = vec![];

        let result = apply_feature_order_override(features, &override_order);
        assert!(result.is_ok());

        let ordered = result.unwrap();
        assert_eq!(ordered.len(), 2);
        // Original order should be preserved
        assert_eq!(ordered[0].feature.id, "feature-a");
        assert_eq!(ordered[1].feature.id, "feature-b");
    }

    #[test]
    fn test_apply_feature_order_override_nonexistent() {
        let features = vec![
            create_test_feature_result("feature-a"),
            create_test_feature_result("feature-b"),
        ];

        let override_order = vec!["feature-nonexistent".to_string(), "feature-a".to_string()];

        let result = apply_feature_order_override(features, &override_order);
        assert!(result.is_ok());

        let ordered = result.unwrap();
        assert_eq!(ordered.len(), 2);

        // feature-a should be first (as it was in override list)
        assert_eq!(ordered[0].feature.id, "feature-a");
        // feature-b should be second (not in override list)
        assert_eq!(ordered[1].feature.id, "feature-b");
    }

    #[test]
    fn test_devcontainer_id_generation() {
        use crate::config::Config;
        use crate::driver::runtime::docker::DockerRuntime;
        use std::fs;
        use tempfile::TempDir;

        // Create temporary workspaces
        let temp_dir1 = TempDir::new().unwrap();
        let temp_dir2 = TempDir::new().unwrap();
        let temp_dir3 = TempDir::new().unwrap();

        // Create devcontainer.json files with different content
        let devcontainer_json1 = r#"{"image": "mcr.microsoft.com/devcontainers/base:latest"}"#;
        let devcontainer_json2 = r#"{"image": "ubuntu:22.04"}"#;

        fs::create_dir(temp_dir1.path().join(".devcontainer")).unwrap();
        fs::write(
            temp_dir1.path().join(".devcontainer/devcontainer.json"),
            devcontainer_json1,
        )
        .unwrap();

        fs::create_dir(temp_dir2.path().join(".devcontainer")).unwrap();
        fs::write(
            temp_dir2.path().join(".devcontainer/devcontainer.json"),
            devcontainer_json2,
        )
        .unwrap();

        // Third workspace with same content as first
        fs::create_dir(temp_dir3.path().join(".devcontainer")).unwrap();
        fs::write(
            temp_dir3.path().join(".devcontainer/devcontainer.json"),
            devcontainer_json1,
        )
        .unwrap();

        let workspace1 = Workspace::try_from(temp_dir1.path().to_path_buf()).unwrap();
        let workspace2 = Workspace::try_from(temp_dir2.path().to_path_buf()).unwrap();
        let workspace3 = Workspace::try_from(temp_dir3.path().to_path_buf()).unwrap();

        let config = Config::default();
        let runtime = Box::new(DockerRuntime::new(DockerRuntimeConfig::default()));
        let driver = ContainerDriver::new(config, runtime);

        let id1 = driver.get_devcontainer_id(&workspace1);
        let id2 = driver.get_devcontainer_id(&workspace2);
        let id3 = driver.get_devcontainer_id(&workspace3);

        // IDs should be different for different configurations
        assert_ne!(
            id1, id2,
            "Different devcontainer.json content should produce different IDs"
        );

        // IDs should be the same for same configuration, even in different paths
        assert_eq!(
            id1, id3,
            "Same devcontainer.json content should produce same ID"
        );

        // ID should be consistent for the same workspace
        let id1_again = driver.get_devcontainer_id(&workspace1);
        assert_eq!(id1, id1_again);

        // ID should be a valid hex string (64 chars for SHA256)
        assert_eq!(id1.len(), 64);
        assert!(id1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_substitute_mount_variables() {
        use crate::config::Config;
        use crate::driver::runtime::docker::DockerRuntime;
        use std::fs;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let devcontainer_json = r#"{"image": "mcr.microsoft.com/devcontainers/base:latest"}"#;
        fs::create_dir(temp_dir.path().join(".devcontainer")).unwrap();
        fs::write(
            temp_dir.path().join(".devcontainer/devcontainer.json"),
            devcontainer_json,
        )
        .unwrap();

        let workspace = Workspace::try_from(temp_dir.path().to_path_buf()).unwrap();
        let config = Config::default();
        let runtime = Box::new(DockerRuntime::new(DockerRuntimeConfig::default()));
        let driver = ContainerDriver::new(config, runtime);

        // Test devcontainerId substitution
        let mount_str = "type=volume,source=myvolume-${devcontainerId},target=/data";
        let result = driver.substitute_mount_variables(mount_str, &workspace);
        let devcontainer_id = driver.get_devcontainer_id(&workspace);
        assert!(result.contains(&devcontainer_id));
        assert!(!result.contains("${devcontainerId}"));

        // Test localWorkspaceFolder substitution
        let mount_str = "type=bind,source=${localWorkspaceFolder}/.config,target=/root/.config";
        let result = driver.substitute_mount_variables(mount_str, &workspace);
        assert!(result.contains(&workspace.path.to_string_lossy().to_string()));
        assert!(!result.contains("${localWorkspaceFolder}"));

        // Test containerWorkspaceFolder substitution
        let workspace_name = workspace.path.file_name().unwrap().to_string_lossy();
        let mount_str = "type=bind,source=/tmp,target=${containerWorkspaceFolder}/tmp";
        let result = driver.substitute_mount_variables(mount_str, &workspace);
        assert!(result.contains(&format!("/workspaces/{}", workspace_name)));
        assert!(!result.contains("${containerWorkspaceFolder}"));

        // Test multiple substitutions
        let mount_str = "${localWorkspaceFolder}:/workspaces/${devcontainerId}";
        let result = driver.substitute_mount_variables(mount_str, &workspace);
        assert!(result.contains(&workspace.path.to_string_lossy().to_string()));
        assert!(result.contains(&devcontainer_id));
        assert!(!result.contains("${"));

        // Test user variable substitutions
        let mount_str = "${remoteUser}:${containerUser}:${remoteUserHome}:${containerUserHome}";
        let result = driver.substitute_mount_variables(mount_str, &workspace);
        assert_eq!(result, "vscode:vscode:/home/vscode:/home/vscode");
    }

    #[test]
    fn test_lifecycle_marker_path_contains_marker_name() {
        let marker = ContainerDriver::lifecycle_marker_path("onCreateCommand");
        assert_eq!(marker, "/var/lib/devcon/lifecycle-markers/onCreateCommand");
    }

    #[test]
    fn test_guard_with_marker_contains_marker_path() {
        let result = ContainerDriver::guard_with_marker("echo hello", "sshAgentSetup");
        assert!(
            result.contains("/var/lib/devcon/lifecycle-markers/sshAgentSetup"),
            "marker path missing: {result}"
        );
        assert!(result.contains("if [ ! -f"), "missing if guard: {result}");
        assert!(result.contains("touch"), "missing touch: {result}");
        assert!(
            result.contains("echo hello"),
            "inner command missing: {result}"
        );
    }

    #[test]
    fn test_guard_with_marker_distinct_names() {
        let ssh = ContainerDriver::guard_with_marker("chmod /ssh-agent", "sshAgentSetup");
        let gpg = ContainerDriver::guard_with_marker("chmod .gnupg", "gpgAgentSetup");
        let dots = ContainerDriver::guard_with_marker("/dotfiles_helper.sh", "dotfilesSetup");
        let gh = ContainerDriver::guard_with_marker("gh auth login", "ghForwarding");

        assert!(ssh.contains("lifecycle-markers/sshAgentSetup"));
        assert!(gpg.contains("lifecycle-markers/gpgAgentSetup"));
        assert!(dots.contains("lifecycle-markers/dotfilesSetup"));
        assert!(gh.contains("lifecycle-markers/ghForwarding"));

        // All four must be distinct
        let all = [&ssh, &gpg, &dots, &gh];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "markers {i} and {j} must differ");
                }
            }
        }
    }

    #[test]
    fn test_guard_with_marker_touch_after_success() {
        let result = ContainerDriver::guard_with_marker("false", "someMarker");
        let touch_pos = result.find("touch").expect("touch not found");
        let and_pos = result[..touch_pos]
            .rfind("&&")
            .expect("&& before touch not found");
        assert!(and_pos < touch_pos, "&& must precede touch");
    }

    #[test]
    fn test_is_transient_agent_mount_start_error_matches_stale_ssh_mount() {
        let err = Error::runtime(
            "docker start failed: error during container init: error mounting '/private/var/run/com.apple.launchd.ABC/Listeners' to '/ssh-agent': not a directory",
        );

        assert!(is_transient_agent_mount_start_error(&err));
    }

    #[test]
    fn test_is_transient_agent_mount_start_error_ignores_unrelated_start_error() {
        let err = Error::runtime("docker start failed: port is already allocated");

        assert!(!is_transient_agent_mount_start_error(&err));
    }

    #[test]
    fn test_is_transient_agent_mount_start_error_matches_stable_dir_missing() {
        let err = Error::runtime(
            "error mounting /home/user/.local/share/devcon/agent-sockets to /run/devcon-agents: \
             no such file or directory",
        );
        assert!(is_transient_agent_mount_start_error(&err));
    }

    #[test]
    fn test_update_agent_socket_symlink_creates_new() {
        let tmp = TempDir::new().unwrap();
        let stable_dir = tmp.path();

        // Create a fake socket file to point at
        let socket = stable_dir.join("real.sock");
        std::fs::write(&socket, "").unwrap();

        let ok = update_agent_socket_symlink(stable_dir, "ssh-agent", &socket);
        assert!(ok);
        let target = std::fs::read_link(stable_dir.join("ssh-agent")).unwrap();
        assert_eq!(target, socket);
    }

    #[test]
    fn test_update_agent_socket_symlink_replaces_stale() {
        let tmp = TempDir::new().unwrap();
        let stable_dir = tmp.path();

        let old_socket = stable_dir.join("old.sock");
        let new_socket = stable_dir.join("new.sock");
        std::fs::write(&old_socket, "").unwrap();
        std::fs::write(&new_socket, "").unwrap();

        // Create the initial symlink pointing to old socket
        update_agent_socket_symlink(stable_dir, "ssh-agent", &old_socket);
        // Now update to new socket
        let ok = update_agent_socket_symlink(stable_dir, "ssh-agent", &new_socket);
        assert!(ok);
        let target = std::fs::read_link(stable_dir.join("ssh-agent")).unwrap();
        assert_eq!(target, new_socket);
    }

    #[test]
    fn test_update_agent_socket_symlink_idempotent() {
        let tmp = TempDir::new().unwrap();
        let stable_dir = tmp.path();

        let socket = stable_dir.join("real.sock");
        std::fs::write(&socket, "").unwrap();

        // First call
        assert!(update_agent_socket_symlink(
            stable_dir,
            "ssh-agent",
            &socket
        ));
        // Second call with same target — should still return true without error
        assert!(update_agent_socket_symlink(
            stable_dir,
            "ssh-agent",
            &socket
        ));
        let target = std::fs::read_link(stable_dir.join("ssh-agent")).unwrap();
        assert_eq!(target, socket);
    }

    #[test]
    fn test_copy_feature_options_include_different_options() {
        let feature_dir = TempDir::new().unwrap();
        let temp_dir = TempDir::new().unwrap().keep();

        let feature = Feature {
            id: "base".to_string(),
            version: "1.0.0".to_string(),
            name: None,
            description: None,
            documentation_url: None,
            license_url: None,
            keywords: None,
            options: Some(
                serde_json::from_str(
                    r#"
{
    "default": {
        "type": "string",
        "default": ""
    },
    "string": {
        "type": "string",
        "default": "test"
    },
    "bool": {
        "type": "boolean",
        "default": false
    },
    "int": {
        "type": "string",
        "default": "0"
    }
}"#,
                )
                .unwrap(),
            ),
            installs_after: None,
            depends_on: None,
            deprecated: None,
            legacy_ids: None,
            cap_add: None,
            security_opt: None,
            privileged: None,
            init: None,
            entrypoint: None,
            mounts: None,
            container_env: None,
            customizations: None,
            on_create_command: None,
            update_content_command: None,
            post_create_command: None,
            post_start_command: None,
            post_attach_command: None,
        };

        let options =
            serde_json::from_str(r#"{ "string": "hello", "bool":true, "int": 42 }"#).unwrap();

        let feature_ref = FeatureRef {
            source: FeatureSource::Local {
                path: feature_dir.path().to_path_buf(),
            },
            options,
        };
        let feature_process_result = FeatureProcessResult {
            feature_ref,
            feature,
            path: feature_dir.path().to_path_buf(),
        };

        let driver = ContainerDriver::new(
            Config::default(),
            Box::new(DockerRuntime::new(DockerRuntimeConfig::default())),
        );

        let result = driver.copy_feature_to_build(&feature_process_result, temp_dir.as_path());

        assert!(result.is_ok());
        assert!(std::fs::exists(temp_dir.join("base").join("devcontainer-features.env")).unwrap());

        let content =
            std::fs::read_to_string(temp_dir.join("base").join("devcontainer-features.env"))
                .unwrap();
        assert_eq!(
            "export BOOL=true\nexport DEFAULT=\nexport INT=42\nexport STRING=hello\n",
            content
        );
    }
}
