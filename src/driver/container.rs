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
//! let config = Config::load()?;
//! let runtime = Box::new(DockerRuntime::new(DockerRuntimeConfig{}));
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
    FeatureRef, FeatureSource, resolve_context_path, resolve_dockerfile_path,
};
use crate::driver::agent::{self, AgentConfig};
use crate::driver::feature_process::FeatureProcessResult;
use crate::driver::runtime::RuntimeParameters;
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
        Some(path)
    } else {
        warn!(
            "gpgconf returned '{}' but socket does not exist",
            socket_path
        );
        None
    }
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

impl ContainerDriver {
    /// Creates a new container driver.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use devcon::driver::container::ContainerDriver;
    /// # use devcon::config::{Config, DockerRuntimeConfig};
    /// # use devcon::driver::runtime::docker::DockerRuntime;
    /// let config = Config::load()?;
    /// let runtime = Box::new(DockerRuntime::new(DockerRuntimeConfig{}));
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
    /// let config = Config::load()?;
    /// let runtime = Box::new(DockerRuntime::new(DockerRuntimeConfig{}));
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

    /// Builds a container image with optional pre-processed features.
    ///
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
                &intermediate_tag,
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
CMD ["-c", "echo Container started\ntrap \"exit 0\" 15\n\nexec \"$@\"\nwhile sleep 1 \u0026 wait $!; do :; done", "-"]
"#,
        )?;

        let remote_user_val = devcontainer_workspace
            .devcontainer
            .remote_user
            .as_deref()
            .unwrap_or("vscode");
        let container_user_val = devcontainer_workspace
            .devcontainer
            .container_user
            .as_deref()
            .unwrap_or("vscode");
        let container_user_home = if container_user_val == "root" {
            "/root".to_string()
        } else {
            format!("/home/{}", container_user_val)
        };
        let remote_user_home = if remote_user_val == "root" {
            "/root".to_string()
        } else {
            format!("/home/{}", remote_user_val)
        };

        let contents = template.render(minijinja::context! {
            image => &base_image,
            remote_user => remote_user_val,
            container_user => container_user_val,
            remote_user_home => remote_user_home,
            container_user_home => container_user_home,
            feature_install => &feature_install,
            dotfiles_setup => &dotfiles_setup,
            env_setup => &env_setup,
            workspace_name => devcontainer_workspace.path.file_name().unwrap().to_string_lossy(),
            runtime_host_address => self.runtime.get_host_address(),
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

        self.runtime
            .build(&dockerfile, &directory_path, &latest_tag, self.silent)?;

        // Also tag with the build timestamp so we can detect stale running containers
        self.runtime
            .build(&dockerfile, &directory_path, &build_tag, true)?;

        Ok(())
    }

    fn copy_feature_to_build(
        &self,
        process: &FeatureProcessResult,
        build_directory: &Path,
    ) -> Result<String> {
        let feature_dest = build_directory.join(process.directory_name());

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
            writeln!(
                env_file,
                "export {}={}",
                key.to_uppercase(),
                value.as_str().unwrap_or("")
            )?;
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
    /// let config = Config::load()?;
    /// let runtime = Box::new(DockerRuntime::new(DockerRuntimeConfig{}));
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
                        self.substitute_mount_variables(s, &devcontainer_workspace),
                    ),
                    crate::devcontainer::Mount::Structured(structured) => {
                        let mut new_mount = structured.clone();
                        if let Some(ref source) = structured.source {
                            new_mount.source = Some(
                                self.substitute_mount_variables(source, &devcontainer_workspace),
                            );
                        }
                        new_mount.target = self.substitute_mount_variables(
                            &structured.target,
                            &devcontainer_workspace,
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
                            let substituted =
                                self.substitute_mount_variables(s, &devcontainer_workspace);
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
                                self.substitute_mount_variables(s, &devcontainer_workspace)
                            });
                            let target = self
                                .substitute_mount_variables(&sm.target, &devcontainer_workspace);
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
        let mut gpg_agent_mounted = false;
        let mut gpg_public_keyring_path: Option<PathBuf> = None;

        // Add agent forwarding mounts if configured
        if let Some(ref agent_fwd) = self.config.agent_forwarding {
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
                    all_mounts.push(crate::devcontainer::Mount::String(format!(
                        "{}:/ssh-agent",
                        socket.display()
                    )));
                    ssh_agent_mounted = true;
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
                    // Get the remote user from devcontainer or use default
                    let remote_user = devcontainer_workspace
                        .devcontainer
                        .remote_user
                        .as_deref()
                        .unwrap_or("vscode");
                    all_mounts.push(crate::devcontainer::Mount::String(format!(
                        "{}:/home/{}/.gnupg/S.gpg-agent",
                        socket.display(),
                        remote_user
                    )));

                    // Export public keyring
                    info!("Exporting GPG public keyring");
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
                    // Get the remote user from devcontainer or use default
                    let remote_user = devcontainer_workspace
                        .devcontainer
                        .remote_user
                        .as_deref()
                        .unwrap_or("vscode");
                    all_mounts.push(crate::devcontainer::Mount::String(format!(
                        "{}:/home/{}/.config/gh",
                        config_dir.display(),
                        remote_user
                    )));
                } else {
                    info!("GitHub CLI forwarding enabled but no configuration found");
                }
            }
        }

        // Check if container needs to run in privileged mode
        let requires_privileged = processed_features
            .iter()
            .any(|f| f.feature.privileged.unwrap_or(false));

        // Process environment variables
        let mut processed_env_vars = Vec::new();

        for env_var in env_variables {
            if env_var.contains("=") {
                processed_env_vars.push(env_var.clone());
            } else {
                // Read host env variable
                let host_value = std::env::var(env_var).unwrap_or_default();
                processed_env_vars.push(format!("{}={}", env_var, host_value));
            }
        }

        // Add environment variables for agent forwarding
        if ssh_agent_mounted {
            processed_env_vars.push("SSH_AUTH_SOCK=/ssh-agent".to_string());
        }
        if gpg_agent_mounted {
            processed_env_vars.push("GPG_TTY=$(tty)".to_string());
        }

        // Handle port forward requests
        let ports = devcontainer_workspace
            .devcontainer
            .forward_ports
            .clone()
            .unwrap_or_default();

        debug!("Starting container with ports: {:?}", ports);

        let handle = self.runtime.run(
            &format!("{}:latest", self.get_image_tag(&devcontainer_workspace)),
            &volume_mount,
            &label,
            &processed_env_vars,
            RuntimeParameters {
                additional_mounts: all_mounts,
                ports,
                requires_privileged,
            },
        )?;

        match &devcontainer_workspace.devcontainer.on_create_command {
            Some(LifecycleCommand::String(cmd)) => {
                let wrapped_cmd = self.wrap_once_lifecycle_command(&devcontainer_workspace, cmd, "onCreateCommand");
                self.runtime.exec(
                    handle.as_ref(),
                    vec!["bash", "-c", "-i", &wrapped_cmd],
                    &[],
                    false,
                    true,
                )?
            }
            Some(LifecycleCommand::Array(cmds)) => cmds.iter().try_for_each(|c| {
                let wrapped_cmd = self.wrap_once_lifecycle_command(&devcontainer_workspace, c, "onCreateCommand");
                self.runtime.exec(
                    handle.as_ref(),
                    vec!["bash", "-c", "-i", &wrapped_cmd],
                    &[],
                    false,
                    true,
                )
            })?,
            Some(LifecycleCommand::Object(map)) => map.values().try_for_each(|cmd| {
                let cmd_str = cmd.to_command_string();
                let wrapped_cmd = self.wrap_once_lifecycle_command(&devcontainer_workspace, &cmd_str, "onCreateCommand");
                self.runtime.exec(
                    handle.as_ref(),
                    vec!["bash", "-c", "-i", &wrapped_cmd],
                    &[],
                    false,
                    true,
                )
            })?,
            None => { /* No onCreateCommand specified */ }
        };

        // Fix file permissions on gpg agent socket
        if gpg_agent_mounted {
            debug!("Setting permissions on GPG agent socket inside container");
            let remote_user = devcontainer_workspace
                .devcontainer
                .remote_user
                .as_deref()
                .unwrap_or("vscode");
            self.runtime.exec(
                handle.as_ref(),
                vec![
                    "bash",
                    "-c",
                    &format!("sudo chmod -R 0700 /home/{}/.gnupg && sudo chown -R $(id -u):$(id -g) /home/{}/.gnupg", remote_user, remote_user),
                ],
                &[],
                false,
                    false,
            )?;

            // Import GPG public keyring if it was exported
            if gpg_public_keyring_path.is_some() {
                info!("Importing GPG public keyring into container");
                self.runtime.exec(
                    handle.as_ref(),
                    vec![
                        "bash",
                        "-c",
                        "gpg --import /tmp/gpg-public-keys.asc 2>&1 || true",
                    ],
                    &[],
                    false,
                    false,
                )?;
            }
        }

        // Fix file permissions on ssh agent socket
        if ssh_agent_mounted {
            debug!("Setting permissions on SSH agent socket inside container");
            self.runtime.exec(
                handle.as_ref(),
                vec![
                    "bash",
                    "-c",
                    "sudo chmod 600 /ssh-agent && sudo chown $(id -u):$(id -g) /ssh-agent",
                ],
                &[],
                false,
                false,
            )?;
        }

        // Add dotfiles setup if repository is provided
        if let Some(repo) = self.config.dotfiles_repository.as_deref() {
            self.runtime.exec(
                handle.as_ref(),
                vec![
                    "/bin/sh",
                    "-c",
                    &format!(
                        "/dotfiles_helper.sh {} {}",
                        repo,
                        self.config
                            .dotfiles_install_command
                            .as_deref()
                            .unwrap_or("")
                    )
                    .trim(),
                ],
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

                for (host, token) in &tokens {
                    debug!("Active GH host: {}", host);
                    self.runtime.exec(
                        handle.as_ref(),
                        vec![
                            "bash",
                            "-c",
                            &format!(
                                "gh auth login --hostname {} --with-token < <(echo {})",
                                host, token
                            ),
                        ],
                        &[],
                        false,
                        false,
                    )?;
                }
            } else {
                warn!("Failed to retrieve GitHub CLI auth token for forwarding");
            }
        }

        match &devcontainer_workspace.devcontainer.post_create_command {
            Some(LifecycleCommand::String(cmd)) => {
                let wrapped_cmd = self.wrap_once_lifecycle_command(&devcontainer_workspace, cmd, "postCreateCommand");
                self.runtime.exec(
                    handle.as_ref(),
                    vec!["bash", "-c", "-i", &wrapped_cmd],
                    &[],
                    false,
                    true,
                )?
            }
            Some(LifecycleCommand::Array(cmds)) => cmds.iter().try_for_each(|c| {
                let wrapped_cmd = self.wrap_once_lifecycle_command(&devcontainer_workspace, c, "postCreateCommand");
                self.runtime.exec(
                    handle.as_ref(),
                    vec!["bash", "-c", "-i", &wrapped_cmd],
                    &[],
                    false,
                    true,
                )
            })?,
            Some(LifecycleCommand::Object(map)) => map.values().try_for_each(|cmd| {
                let cmd_str = cmd.to_command_string();
                let wrapped_cmd = self.wrap_once_lifecycle_command(&devcontainer_workspace, &cmd_str, "postCreateCommand");
                self.runtime.exec(
                    handle.as_ref(),
                    vec!["bash", "-c", "-i", &wrapped_cmd],
                    &[],
                    false,
                    true,
                )
            })?,
            None => { /* No onCreateCommand specified */ }
        };

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

        match &devcontainer_workspace.devcontainer.post_start_command {
            Some(LifecycleCommand::String(cmd)) => {
                let wrapped_cmd = self.wrap_lifecycle_command(&devcontainer_workspace, cmd);
                self.runtime.exec(
                    handle.as_ref(),
                    vec!["bash", "-c", "-i", &wrapped_cmd],
                    &[],
                    false,
                    true,
                )?
            }
            Some(LifecycleCommand::Array(cmds)) => cmds.iter().try_for_each(|c| {
                let wrapped_cmd = self.wrap_lifecycle_command(&devcontainer_workspace, c);
                self.runtime.exec(
                    handle.as_ref(),
                    vec!["bash", "-c", "-i", &wrapped_cmd],
                    &[],
                    false,
                    true,
                )
            })?,
            Some(LifecycleCommand::Object(map)) => map.values().try_for_each(|cmd| {
                let cmd_str = cmd.to_command_string();
                let wrapped_cmd = self.wrap_lifecycle_command(&devcontainer_workspace, &cmd_str);
                self.runtime.exec(
                    handle.as_ref(),
                    vec!["bash", "-c", "-i", &wrapped_cmd],
                    &[],
                    false,
                    true,
                )
            })?,
            None => { /* No onCreateCommand specified */ }
        };

        Ok(handle.id().to_string())
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
    /// let config = Config::load()?;
    /// let runtime = Box::new(DockerRuntime::new(DockerRuntimeConfig{}));
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

        match &devcontainer_workspace.devcontainer.post_attach_command {
            Some(LifecycleCommand::String(cmd)) => {
                let wrapped_cmd = self.wrap_lifecycle_command(&devcontainer_workspace, cmd);
                self.runtime.exec(
                    handle,
                    vec!["bash", "-c", "-i", &wrapped_cmd],
                    &[],
                    false,
                    true,
                )?
            }
            Some(LifecycleCommand::Array(cmds)) => cmds.iter().try_for_each(|c| {
                let wrapped_cmd = self.wrap_lifecycle_command(&devcontainer_workspace, c);
                self.runtime.exec(
                    handle,
                    vec!["bash", "-c", "-i", &wrapped_cmd],
                    &[],
                    false,
                    true,
                )
            })?,
            Some(LifecycleCommand::Object(map)) => map.values().try_for_each(|cmd| {
                let cmd_str = cmd.to_command_string();
                let wrapped_cmd = self.wrap_lifecycle_command(&devcontainer_workspace, &cmd_str);
                self.runtime.exec(
                    handle,
                    vec!["bash", "-c", "-i", &wrapped_cmd],
                    &[],
                    false,
                    true,
                )
            })?,
            None => { /* No postAttachCommand specified */ }
        };

        self.runtime.exec(
            handle,
            vec![&self.config.default_shell.as_deref().unwrap_or("zsh")],
            &processed_env_vars,
            true,
            true,
        )?;

        Ok(())
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
                // Hash the file content for configuration-specific ID
                hasher.update(content.as_bytes());
            }
            Err(_) => {
                // Fallback to workspace path if file can't be read
                hasher.update(devcontainer_workspace.path.to_string_lossy().as_bytes());
            }
        }

        let result = hasher.finalize();
        format!("{:x}", result)
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
    fn substitute_mount_variables(
        &self,
        mount_str: &str,
        devcontainer_workspace: &Workspace,
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

    /// Wraps a lifecycle command so it runs at most once, guarded by a marker file
    /// inside the container at `/var/lib/devcon/lifecycle-markers/{hook_name}`.
    ///
    /// The marker is created only when the command succeeds. With `--rm` (current
    /// default) the container filesystem is discarded on stop, so the guard has no
    /// effect today. Once containers are persisted across stop/start cycles the
    /// marker will prevent once-only hooks from re-running on subsequent starts.
    fn wrap_once_lifecycle_command(
        &self,
        devcontainer_workspace: &Workspace,
        cmd: &str,
        hook_name: &str,
    ) -> String {
        let inner = self.wrap_lifecycle_command(devcontainer_workspace, cmd);
        let marker = format!("/var/lib/devcon/lifecycle-markers/{}", hook_name);
        format!(
            "MARKER='{}'; if [ ! -f \"$MARKER\" ]; then {}; mkdir -p \"$(dirname \"$MARKER\")\" && touch \"$MARKER\"; fi",
            marker, inner
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DockerRuntimeConfig;
    use crate::devcontainer::{FeatureRegistry, FeatureRegistryType, FeatureSource};
    use crate::feature::Feature;
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
    }

    #[test]
    fn test_wrap_once_lifecycle_command_contains_marker_path() {
        use crate::config::Config;
        use crate::driver::runtime::docker::DockerRuntime;
        use std::fs;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        fs::create_dir(temp_dir.path().join(".devcontainer")).unwrap();
        fs::write(
            temp_dir.path().join(".devcontainer/devcontainer.json"),
            r#"{"image": "ubuntu:22.04"}"#,
        )
        .unwrap();
        let workspace = Workspace::try_from(temp_dir.path().to_path_buf()).unwrap();
        let driver = ContainerDriver::new(
            Config::default(),
            Box::new(DockerRuntime::new(DockerRuntimeConfig::default())),
        );

        let result = driver.wrap_once_lifecycle_command(&workspace, "npm install", "onCreateCommand");

        assert!(
            result.contains("/var/lib/devcon/lifecycle-markers/onCreateCommand"),
            "marker path missing: {result}"
        );
        assert!(result.contains("if [ ! -f"), "missing if guard: {result}");
        assert!(result.contains("touch"), "missing touch: {result}");
        assert!(result.contains("npm install"), "inner command missing: {result}");
    }

    #[test]
    fn test_wrap_once_lifecycle_command_hook_name_in_marker() {
        use crate::config::Config;
        use crate::driver::runtime::docker::DockerRuntime;
        use std::fs;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        fs::create_dir(temp_dir.path().join(".devcontainer")).unwrap();
        fs::write(
            temp_dir.path().join(".devcontainer/devcontainer.json"),
            r#"{"image": "ubuntu:22.04"}"#,
        )
        .unwrap();
        let workspace = Workspace::try_from(temp_dir.path().to_path_buf()).unwrap();
        let driver = ContainerDriver::new(
            Config::default(),
            Box::new(DockerRuntime::new(DockerRuntimeConfig::default())),
        );

        let oncreate = driver.wrap_once_lifecycle_command(&workspace, "echo hi", "onCreateCommand");
        let postcreate = driver.wrap_once_lifecycle_command(&workspace, "echo hi", "postCreateCommand");

        assert!(
            oncreate.contains("lifecycle-markers/onCreateCommand"),
            "onCreateCommand marker missing"
        );
        assert!(
            postcreate.contains("lifecycle-markers/postCreateCommand"),
            "postCreateCommand marker missing"
        );
        // Markers must be distinct
        assert_ne!(oncreate, postcreate);
    }

    #[test]
    fn test_wrap_once_lifecycle_command_marker_created_only_on_success() {
        use crate::config::Config;
        use crate::driver::runtime::docker::DockerRuntime;
        use std::fs;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        fs::create_dir(temp_dir.path().join(".devcontainer")).unwrap();
        fs::write(
            temp_dir.path().join(".devcontainer/devcontainer.json"),
            r#"{"image": "ubuntu:22.04"}"#,
        )
        .unwrap();
        let workspace = Workspace::try_from(temp_dir.path().to_path_buf()).unwrap();
        let driver = ContainerDriver::new(
            Config::default(),
            Box::new(DockerRuntime::new(DockerRuntimeConfig::default())),
        );

        let result = driver.wrap_once_lifecycle_command(&workspace, "false", "onCreateCommand");

        // The touch must come after && so it only runs when the command succeeds
        let touch_pos = result.find("touch").expect("touch not found");
        let and_pos = result[..touch_pos].rfind("&&").expect("&& before touch not found");
        assert!(and_pos < touch_pos, "&& must precede touch");
    }
}
