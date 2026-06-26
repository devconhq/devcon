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
//! This module provides the `ContainerOrchestrator` for building and managing
//! development container lifecycles.
//!
//! ## Overview
//!
//! The `ContainerOrchestrator` handles:
//! - Building container images from devcontainer configurations
//! - Generating Dockerfiles with feature installations
//! - Starting containers with appropriate volume mounts
//!
//! ## Usage
//!
//! ```no_run
//! use devcon::config::{Config, DockerRuntimeConfig};
//! use devcon::workspace::Workspace;
//! use devcon::driver::container::ContainerOrchestrator;
//! use devcon::driver::runtime::docker::DockerRuntime;
//! use std::path::PathBuf;
//!
//! # fn example() -> devcon::error::Result<()> {
//! let config = Config::load(None)?;
//! let runtime = Box::new(DockerRuntime::new(DockerRuntimeConfig::default()));
//! let driver = ContainerOrchestrator::new(config, runtime);
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

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;

use crate::error::{Error, Result};
use dialoguer::Select;
use dialoguer::theme::ColorfulTheme;
use pidlock::Pidlock;
use sha2::{Digest, Sha256};
use tracing::{debug, info, trace, warn};

use crate::devcontainer::{
    FeatureRef, FeatureSource, resolve_context_path, resolve_dockerfile_path,
};
use crate::driver::agent::{self, AgentConfig};
use crate::driver::agent_socket::{
    detect_gh_config, detect_gpg_homedir, detect_gpg_keyboxd_socket, detect_gpg_socket,
    detect_public_ssh_key, detect_ssh_socket, ensure_ssh_port_forwarded,
    ensure_stable_ssh_agent_socket, shell_single_quote,
};
use crate::driver::dockerfile::{BuildContext, DockerfileParams, apply_feature_order_override};
use crate::driver::environment::{
    base_container_environment, compose_ssh_environment, compose_start_environment,
};
use crate::driver::feature_process::{
    FeatureLockContext, FeatureProcessResult, LockMode, build_lockfile_from_features,
};
use crate::driver::lifecycle::{
    guard_with_marker, run_lifecycle_command_always, run_lifecycle_command_once,
};
use crate::driver::runtime::{
    ContainerImageInfo, ContainerProbeInfo, FeatureProgressItem, RuntimeParameters,
};
use crate::{
    config::Config, driver::feature_process::process_features, driver::runtime::ContainerRuntime,
    workspace::Workspace,
};
use schema::{DevcontainerLockfile, resolve_lockfile_path};

/// Driver for managing container build and runtime operations.
///
/// This struct encapsulates the logic for building container images
/// and starting container instances based on devcontainer configurations.
pub struct ContainerOrchestrator {
    config: Config,
    pub runtime: Box<dyn ContainerRuntime>,
    silent: bool,
    verbose: bool,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct FeatureLockOptions {
    pub frozen_lockfile: bool,
}

#[derive(Clone, Debug)]
struct ResolvedUsers {
    remote_user: String,
    container_user: String,
    remote_user_home: String,
    container_user_home: String,
}

impl ContainerOrchestrator {
    /// Creates a new container driver.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use devcon::driver::container::ContainerOrchestrator;
    /// # use devcon::config::{Config, DockerRuntimeConfig};
    /// # use devcon::driver::runtime::docker::DockerRuntime;
    /// let config = Config::load(None)?;
    /// let runtime = Box::new(DockerRuntime::new(DockerRuntimeConfig::default()));
    /// let driver = ContainerOrchestrator::new(config, runtime);
    /// # Ok::<(), devcon::error::Error>(())
    /// ```
    pub fn new(config: Config, runtime: Box<dyn ContainerRuntime>) -> Self {
        Self {
            config,
            runtime,
            silent: false,
            verbose: false,
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
            verbose: false,
        }
    }

    /// Enables or disables verbose metadata output.
    pub fn with_verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
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
        let probe_user_hint = self.resolve_probe_user_hint(workspace, &latest_tag);
        let probe_info = self
            .runtime
            .probe_image_info(&latest_tag, probe_user_hint.as_deref())
            .ok()
            .flatten();
        self.resolve_users_for_image(workspace, &latest_tag, probe_info.as_ref())
            .remote_user
    }

    /// Refreshes the in-container SSH session environment file for a running container.
    ///
    /// This keeps dynamic host-passthrough config vars (`envVariables` entries without `=`)
    /// up to date for each SSH connection attempt.
    pub fn refresh_ssh_session_environment_for_connection(
        &self,
        workspace: &Workspace,
        container_id: &str,
    ) -> Result<()> {
        if self.config.should_skip_agent_ssh_setup() {
            return Ok(());
        }

        let handle = self
            .runtime
            .list()?
            .into_iter()
            .find_map(|(_, _, handle)| (handle.id() == container_id).then_some(handle))
            .ok_or_else(|| {
                Error::runtime(format!(
                    "Container '{}' is not running; cannot refresh SSH session environment.",
                    container_id
                ))
            })?;

        let latest_tag = format!("{}:latest", self.get_image_tag(workspace));
        let probe_user_hint = self.resolve_probe_user_hint(workspace, &latest_tag);
        let probe_info = self
            .runtime
            .probe_image_info(&latest_tag, probe_user_hint.as_deref())
            .ok()
            .flatten();
        let users = self.resolve_users_for_image(workspace, &latest_tag, probe_info.as_ref());

        let ssh_session_env = self
            .build_ssh_session_environment_entries(workspace)
            .unwrap_or_else(|err| {
                warn!(
                    "Failed to resolve SSH session environment for refresh: {}",
                    err
                );
                Vec::new()
            });

        self.ensure_ssh_session_environment_file(handle.as_ref(), &users, &ssh_session_env)?;
        self.ensure_ssh_session_profile_loader_files(handle.as_ref(), &users)?;
        self.refresh_gpg_public_keys_for_connection(handle.as_ref())
    }

    /// Resolves environment variables that should be forwarded into SSH sessions.
    ///
    /// Merge order:
    /// 1. Base image environment
    /// 2. Feature `containerEnv`
    /// 3. `devcontainer.json` `containerEnv`
    /// 4. Config `envVariables`
    /// 5. `devcontainer.json` `remoteEnv`
    pub fn resolve_ssh_session_environment(
        &self,
        workspace: &Workspace,
    ) -> Result<Vec<(String, String)>> {
        let mut features = workspace
            .devcontainer
            .merge_additional_features(&self.config.additional_features)?;

        if !self.config.is_agent_disabled() {
            let agent_config = AgentConfig::new(
                self.config.get_agent_use_binary(),
                self.config.get_agent_binary_url().cloned(),
                self.config.get_agent_git_repository().cloned(),
                self.config.get_agent_git_branch().cloned(),
                self.config.get_agent_ssh_port(),
                self.config.should_skip_agent_ssh_setup(),
            );
            let agent_path = agent::Agent::new(agent_config).generate()?;
            features.push(FeatureRef::new(FeatureSource::Local { path: agent_path }));
        }

        let lock_context = FeatureLockContext::update(self.read_lockfile(workspace)?);
        let processed_features = match process_features(&features, true, &lock_context) {
            Ok(results) => results,
            Err(err) => {
                warn!(
                    "Failed to resolve features for SSH environment composition, falling back to non-feature env: {}",
                    err
                );
                Vec::new()
            }
        };

        let latest_tag = format!("{}:latest", self.get_image_tag(workspace));
        let probe_user_hint = self.resolve_probe_user_hint(workspace, &latest_tag);

        let probe_info = self
            .runtime
            .probe_image_info(&latest_tag, probe_user_hint.as_deref())
            .ok()
            .flatten();
        let base_env =
            base_container_environment(self.runtime.as_ref(), &latest_tag, probe_info.as_ref());

        let ssh_env = compose_ssh_environment(
            &processed_features,
            workspace.devcontainer.container_env.as_ref(),
            workspace.devcontainer.remote_env.as_ref(),
            &self.config.env_variables,
            &base_env,
        );

        let mut sorted = ssh_env.into_iter().collect::<Vec<_>>();
        sorted.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(sorted)
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
        lock_options: &FeatureLockOptions,
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

        let lockfile = self.read_lockfile(devcontainer_workspace)?;
        let lock_context = match (lock_options.frozen_lockfile, lockfile) {
            (true, Some(lockfile)) => FeatureLockContext::frozen(lockfile),
            (true, None) => {
                let lock_path =
                    resolve_lockfile_path(&devcontainer_workspace.path).ok_or_else(|| {
                        Error::feature("Could not resolve devcontainer-lock.json path")
                    })?;
                return Err(Error::feature(format!(
                    "Lockfile mode enabled but no lockfile was found at {}",
                    lock_path.display()
                )));
            }
            (false, lockfile) => FeatureLockContext::update(lockfile),
        };

        // Process all features including dependency resolution and topological sorting
        let mut processed_features = process_features(&features, self.silent, &lock_context)?;

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

        if lock_context.mode == LockMode::Update {
            self.write_lockfile(
                devcontainer_workspace,
                &build_lockfile_from_features(&processed_features),
            )?;
        }

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
    /// # use devcon::driver::container::ContainerOrchestrator;
    /// # use devcon::driver::runtime::docker::DockerRuntime;
    /// # use std::path::PathBuf;
    /// # fn example() -> devcon::error::Result<()> {
    /// let config = Config::load(None)?;
    /// let runtime = Box::new(DockerRuntime::new(DockerRuntimeConfig::default()));
    /// let driver = ContainerOrchestrator::new(config, runtime);
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
        self.build_with_features(
            devcontainer_workspace,
            env_variables,
            None,
            build_path,
            FeatureLockOptions::default(),
        )
        .map(|_| ())
    }

    pub fn build_with_lock_options(
        &self,
        devcontainer_workspace: Workspace,
        env_variables: &[String],
        build_path: Option<PathBuf>,
        lock_options: FeatureLockOptions,
    ) -> Result<schema::MergedImageMetadata> {
        self.build_with_features(
            devcontainer_workspace,
            env_variables,
            None,
            build_path,
            lock_options,
        )
    }

    /// Returns `true` if the latest image for the given workspace already exists in the runtime.
    pub fn image_exists(&self, devcontainer_workspace: &Workspace) -> Result<bool> {
        let latest_tag = format!("{}:latest", self.get_image_tag(devcontainer_workspace));
        Ok(self.runtime.image_id(&latest_tag)?.is_some())
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
        lock_options: FeatureLockOptions,
    ) -> Result<schema::MergedImageMetadata> {
        let ctx = BuildContext::new(build_path)?;
        info!(
            "Building container in temporary directory: {}",
            ctx.path().to_string_lossy()
        );

        trace!(
            "Processing features for devcontainer at {:?}",
            devcontainer_workspace.path
        );

        // Use provided features or process them
        let processed_features = match processed_features {
            Some(features) => features,
            None => {
                let (features, _) =
                    self.prepare_features(&devcontainer_workspace, &lock_options)?;
                features
            }
        };

        let feature_progress = self.build_feature_progress_items(&processed_features);

        if !self.silent && self.verbose {
            self.print_feature_evaluation_order(&feature_progress);
        }

        let feature_install = ctx.generate_feature_install_snippet(&processed_features)?;

        // Add environment variables
        let mut env_setup = String::new();
        for env_var in env_variables {
            env_setup.push_str(&format!("ENV {}\n", env_var));
        }

        let dotfiles_setup = ctx.write_dotfiles_helper()?;

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
                Some("Building base image from Dockerfile"),
                None,
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

        // Determine probe user hint from devcontainer.json or existing metadata label.
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
                    .and_then(Self::remote_user_from_metadata)
            });

        let probe_info = self
            .runtime
            .probe_image_info(&base_image, probe_user_hint.as_deref())
            .ok()
            .flatten();

        let resolved_users =
            self.resolve_users_for_image(&devcontainer_workspace, &base_image, probe_info.as_ref());

        let base_env =
            base_container_environment(self.runtime.as_ref(), &base_image, probe_info.as_ref());
        let evaluated_env = compose_start_environment(
            &processed_features,
            devcontainer_workspace.devcontainer.container_env.as_ref(),
            env_variables,
            &base_env,
        );

        if !self.silent && self.verbose {
            self.print_build_environment_summary(
                &evaluated_env,
                &base_env,
                &resolved_users,
                probe_info.as_ref(),
            );
            println!("Building Image");
        }

        // Build the devcontainer.metadata label:
        // 1. Prepend any entries already present on the base image.
        // 2. Append one entry per feature.
        // 3. Append one entry for devcontainer.json.
        let mut metadata_entries: Vec<schema::ImageMetadataEntry> = self
            .runtime
            .inspect_image(&base_image)
            .ok()
            .flatten()
            .as_ref()
            .and_then(|inspect| {
                inspect
                    .config
                    .labels
                    .get("devcontainer.metadata")
                    .map(|s| schema::parse_metadata_label(s))
            })
            .unwrap_or_default();

        for feature_result in &processed_features {
            let f = &feature_result.feature;
            let mounts = f.mounts.as_ref().map(|ms| {
                ms.iter()
                    .filter_map(|m| serde_json::to_value(m).ok())
                    .collect::<Vec<_>>()
            });
            metadata_entries.push(schema::ImageMetadataEntry {
                id: Some(f.id.clone()),
                init: f.init,
                privileged: f.privileged,
                cap_add: f.cap_add.clone(),
                security_opt: f.security_opt.clone(),
                entrypoint: f.entrypoint.clone(),
                mounts,
                container_env: f.container_env.clone(),
                on_create_command: f.on_create_command.clone(),
                update_content_command: f.update_content_command.clone(),
                post_create_command: f.post_create_command.clone(),
                post_start_command: f.post_start_command.clone(),
                post_attach_command: f.post_attach_command.clone(),
                ..Default::default()
            });
        }

        // devcontainer.json entry (no id)
        {
            let dc = &devcontainer_workspace.devcontainer;
            let mounts = dc.mounts.as_ref().map(|ms| {
                ms.iter()
                    .filter_map(|m| serde_json::to_value(m).ok())
                    .collect::<Vec<_>>()
            });
            let forward_ports = dc.forward_ports.as_ref().map(|ps| {
                ps.iter()
                    .filter_map(|p| serde_json::to_value(p).ok())
                    .collect::<Vec<_>>()
            });
            let remote_env = dc.remote_env.clone();
            metadata_entries.push(schema::ImageMetadataEntry {
                remote_user: dc.remote_user.clone(),
                container_user: dc.container_user.clone(),
                container_env: dc.container_env.clone(),
                remote_env,
                mounts,
                forward_ports,
                init: dc.init,
                privileged: dc.privileged,
                cap_add: dc.cap_add.clone(),
                security_opt: dc.security_opt.clone(),
                on_create_command: dc.on_create_command.clone(),
                update_content_command: dc.update_content_command.clone(),
                post_create_command: dc.post_create_command.clone(),
                post_start_command: dc.post_start_command.clone(),
                post_attach_command: dc.post_attach_command.clone(),
                override_command: dc.override_command,
                update_remote_user_uid: dc.update_remote_user_uid,
                ..Default::default()
            });
        }

        let metadata_label =
            serde_json::to_string(&metadata_entries).unwrap_or_else(|_| "[]".to_string());

        // Phase 2: Build features Dockerfile using base_image
        let config_hash = self.get_devcontainer_id(&devcontainer_workspace);
        let workspace_name = devcontainer_workspace
            .path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();
        let dockerfile = ctx.write_dockerfile(&DockerfileParams {
            base_image: &base_image,
            remote_user: &resolved_users.remote_user,
            container_user: &resolved_users.container_user,
            remote_user_home: &resolved_users.remote_user_home,
            container_user_home: &resolved_users.container_user_home,
            workspace_name: &workspace_name,
            runtime_host_address: &self.runtime.get_host_address(),
            config_hash: &config_hash,
            metadata_label: &metadata_label,
            feature_install: &feature_install,
            env_setup: &env_setup,
            dotfiles_setup: &dotfiles_setup,
        })?;

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
            ctx.path(),
            vec![&latest_tag, &build_tag],
            Some("Building Image"),
            (!feature_progress.is_empty()).then_some(feature_progress.as_slice()),
            self.silent,
        )?;

        // Read back the metadata label from the built image and merge.
        let merged = self
            .runtime
            .inspect_image(&latest_tag)
            .ok()
            .flatten()
            .as_ref()
            .and_then(|inspect| {
                inspect
                    .config
                    .labels
                    .get("devcontainer.metadata")
                    .map(|s| schema::merge_metadata_entries(&schema::parse_metadata_label(s)))
            })
            .unwrap_or_default();

        Ok(merged)
    }

    /// Reads the `devcontainer.metadata` label from the latest built image for
    /// the given workspace and returns the merged metadata.  Returns an empty
    /// [`MergedImageMetadata`] when the image does not exist or has no label.
    pub fn read_image_metadata(
        &self,
        devcontainer_workspace: &Workspace,
    ) -> schema::MergedImageMetadata {
        let latest_tag = format!("{}:latest", self.get_image_tag(devcontainer_workspace));
        self.runtime
            .inspect_image(&latest_tag)
            .ok()
            .flatten()
            .as_ref()
            .and_then(|inspect| {
                inspect
                    .config
                    .labels
                    .get("devcontainer.metadata")
                    .map(|s| schema::merge_metadata_entries(&schema::parse_metadata_label(s)))
            })
            .unwrap_or_default()
    }

    /// Extracts `remoteUser` from the `devcontainer.metadata` label of an
    /// already-inspected image, using the last entry that specifies the field.
    fn remote_user_from_metadata(inspect: &ContainerImageInfo) -> Option<String> {
        let label_str = inspect
            .config
            .labels
            .get("devcontainer.metadata")
            .map(String::as_str)?;
        schema::parse_metadata_label(label_str)
            .into_iter()
            .rev()
            .find_map(|e| e.remote_user.filter(|u| !u.trim().is_empty()))
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
    /// # use devcon::driver::container::ContainerOrchestrator;
    /// # use devcon::driver::runtime::docker::DockerRuntime;
    /// # use std::path::PathBuf;
    /// # fn example() -> devcon::error::Result<()> {
    /// let config = Config::load(None)?;
    /// let runtime = Box::new(DockerRuntime::new(DockerRuntimeConfig::default()));
    /// let driver = ContainerOrchestrator::new(config, runtime);
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
        self.start_with_features(
            devcontainer_workspace,
            env_variables,
            None,
            FeatureLockOptions::default(),
        )
    }

    pub fn start_with_lock_options(
        &self,
        devcontainer_workspace: Workspace,
        env_variables: &[String],
        lock_options: FeatureLockOptions,
    ) -> Result<String> {
        self.start_with_features(devcontainer_workspace, env_variables, None, lock_options)
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
        lock_options: FeatureLockOptions,
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

                // Before attempting to start the container, refresh any agent
                // socket bridges that may have gone away during a host reboot.
                // The stable SSH socket is backed by a socat process; if the
                // host was rebooted the socat is gone and the socket file has
                // been cleaned up, which causes Docker to reject the bind-mount.
                // Re-running ensure_stable_ssh_agent_socket respawns socat and
                // recreates the socket at the same stable path, so the existing
                // container can be started without removing/recreating it.
                if let Some(ref agent_fwd) = self.config.agent_forwarding
                    && agent_fwd.ssh_enabled.unwrap_or(false)
                {
                    let ssh_socket = if let Some(ref override_path) = agent_fwd.ssh_socket_path {
                        PathBuf::from(override_path)
                            .exists()
                            .then(|| PathBuf::from(override_path))
                    } else {
                        detect_ssh_socket()
                    };
                    if let Some(socket) = ssh_socket {
                        debug!("Refreshing stable SSH agent socket before container restart");
                        ensure_stable_ssh_agent_socket(&socket);
                    }
                }

                match self.runtime.start_container(handle.id()) {
                    Ok(restarted) => {
                        if let Some(command) =
                            &devcontainer_workspace.devcontainer.post_start_command
                        {
                            run_lifecycle_command_always(
                                self.runtime.as_ref(),
                                restarted.as_ref(),
                                &devcontainer_workspace,
                                command,
                                false,
                                true,
                            )?;
                        }

                        return Ok(restarted.id().to_string());
                    }
                    Err(e) => {
                        // start_container can still fail for other reasons (e.g. GPG socket
                        // path moved, other stale mounts, or runtime error). Remove the stale
                        // container so it doesn't accumulate and fall through to create a
                        // fresh one.
                        warn!(
                            "Failed to restart stopped container (stale mounts after reboot?): {}. \
                             Removing stale container and creating a new one.",
                            e
                        );
                        if let Err(rm_err) = self.runtime.remove_container(handle.id()) {
                            debug!(
                                "Failed to remove stale container {}: {}",
                                handle.id(),
                                rm_err
                            );
                        }
                    }
                }
            }

            debug!(
                "Stopped container uses a stale image ({}), creating new container with latest",
                stopped_image
            );
        }

        debug!("Checking for existing image tag");
        let already_built = self.runtime.image_id(&latest_tag)?.is_some();
        debug!("Image found: {}", already_built);
        trace!(
            "Image existence check for latest tag '{}' returned {}",
            latest_tag, already_built
        );

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
                    .and_then(Self::remote_user_from_metadata)
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
                let (features, _) =
                    self.prepare_features(&devcontainer_workspace, &lock_options)?;
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

        // Track agent forwarding availability for bind-mount setup.
        let mut ssh_agent_available = false;
        let mut gpg_agent_available = false;
        let mut ssh_socket_in_container: Option<String> = None;

        // Configure agent forwarding via direct bind mounts.
        if let Some(ref agent_fwd) = self.config.agent_forwarding {
            // SSH agent forwarding — use socat to bridge the ephemeral host socket
            // to a stable persistent path, then bind-mount that stable path.
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
                    match ensure_stable_ssh_agent_socket(&socket) {
                        Some(stable_path) => {
                            info!("Forwarding SSH agent socket into container via bind mount");
                            all_mounts.push(crate::devcontainer::Mount::String(format!(
                                "{}:/tmp/devcon-ssh-agent",
                                stable_path.display()
                            )));
                            ssh_socket_in_container = Some("/tmp/devcon-ssh-agent".to_string());
                            ssh_agent_available = true;
                        }
                        None => {
                            info!(
                                "SSH agent forwarding skipped (socat unavailable or socket creation failed)"
                            );
                        }
                    }
                } else {
                    info!("SSH agent forwarding enabled but no socket found");
                }
            }

            // GPG agent forwarding.
            // Mount the agent socket as an individual file bind-mount directly into
            // {home}/.gnupg/S.gpg-agent so Docker Desktop's socket proxy handles it
            // correctly (directory-mount sockets appear as '?????????' and are unusable).
            // Mount the rest of the homedir read-only at a staging path for data copying.
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

                let gpg_homedir = detect_gpg_homedir();

                match (gpg_socket, gpg_homedir) {
                    (Some(socket), Some(homedir)) => {
                        info!(
                            "Forwarding GPG agent: socket={:?}, homedir={:?}",
                            socket, homedir
                        );
                        // Individual socket bind-mounts → Docker Desktop's proxy handles
                        // these correctly (unlike sockets inside a directory mount).
                        all_mounts.push(crate::devcontainer::Mount::String(format!(
                            "{}:{}/.gnupg/S.gpg-agent",
                            socket.display(),
                            &resolved_users.remote_user_home,
                        )));
                        // Also mount keyboxd socket if present — required for
                        // `gpg --list-keys` / `gpg --list-secret-keys` on modern GnuPG.
                        if let Some(keyboxd_socket) = detect_gpg_keyboxd_socket() {
                            info!("Forwarding GPG keyboxd socket: {:?}", keyboxd_socket);
                            all_mounts.push(crate::devcontainer::Mount::String(format!(
                                "{}:{}/.gnupg/S.keyboxd",
                                keyboxd_socket.display(),
                                &resolved_users.remote_user_home,
                            )));
                        }
                        // Homedir staged read-only for data file copying in post-start.
                        all_mounts.push(crate::devcontainer::Mount::String(format!(
                            "{}:/tmp/devcon-gnupg-host:ro",
                            homedir.display(),
                        )));
                        gpg_agent_available = true;
                    }
                    (None, _) => info!("GPG agent forwarding enabled but no socket found"),
                    (_, None) => info!("GPG agent forwarding enabled but homedir not found"),
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
        }

        // Aggregate runtime security requirements from devcontainer and features.
        let mut requires_privileged = devcontainer_workspace
            .devcontainer
            .privileged
            .unwrap_or(false);
        let mut cap_add: HashSet<String> = devcontainer_workspace
            .devcontainer
            .cap_add
            .clone()
            .unwrap_or_default()
            .into_iter()
            .map(|cap| normalize_capability_name(&cap))
            .collect();
        let mut security_opt: HashSet<String> = devcontainer_workspace
            .devcontainer
            .security_opt
            .clone()
            .unwrap_or_default()
            .into_iter()
            .collect();

        for feature in &processed_features {
            if feature.feature.privileged.unwrap_or(false) {
                requires_privileged = true;
            }

            if let Some(feature_caps) = &feature.feature.cap_add {
                cap_add.extend(
                    feature_caps
                        .iter()
                        .map(|cap| normalize_capability_name(cap)),
                );
            }

            if let Some(feature_security_opt) = &feature.feature.security_opt {
                security_opt.extend(feature_security_opt.iter().cloned());
            }
        }

        let mut cap_add: Vec<String> = cap_add.into_iter().collect();
        cap_add.sort_unstable();
        let mut security_opt: Vec<String> = security_opt.into_iter().collect();
        security_opt.sort_unstable();

        // Compose the startup environment from feature defaults and user-config overrides.
        let base_container_env =
            base_container_environment(self.runtime.as_ref(), &latest_tag, probe_info.as_ref());
        let mut processed_env_vars = compose_start_environment(
            &processed_features,
            devcontainer_workspace.devcontainer.container_env.as_ref(),
            env_variables,
            &base_container_env,
        );

        // Add environment variables for agent forwarding
        if let Some(ref ssh_sock_path) = ssh_socket_in_container {
            processed_env_vars.push(format!("SSH_AUTH_SOCK={}", ssh_sock_path));
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
                trace!("Pre-run image inspect for '{}': {:?}", latest_tag, inspect);
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

        let image_arch = self.resolve_image_architecture(&latest_tag, probe_info.as_ref());
        let host_is_arm = Self::host_image_architecture() == "arm64";
        let enable_rosetta = host_is_arm && image_arch == "amd64";
        debug!(
            "Runtime architecture translation decision: host_arch='{}', image_arch='{}', enable_translation={}",
            Self::host_image_architecture(),
            image_arch,
            enable_rosetta
        );
        debug!(
            "Image architecture: {}, Host architecture: {}, Rosetta enabled: {}",
            image_arch,
            Self::host_image_architecture(),
            enable_rosetta
        );

        let handle = self.runtime.run(
            &format!("{}:latest", self.get_image_tag(&devcontainer_workspace)),
            &volume_mount,
            &label,
            &processed_env_vars,
            RuntimeParameters {
                additional_mounts: all_mounts,
                ports,
                requires_privileged,
                cap_add,
                security_opt,
                platform_architecture_translation: enable_rosetta,
            },
        )?;

        if !self.config.should_skip_agent_ssh_setup() {
            self.ensure_ssh_authorized_key(handle.as_ref(), &resolved_users)?;

            let ssh_session_env = self
                .build_ssh_session_environment_entries(&devcontainer_workspace)
                .unwrap_or_else(|err| {
                    warn!(
                        "Failed to resolve SSH session environment for in-container SSH setup: {}",
                        err
                    );
                    Vec::new()
                });
            self.ensure_ssh_session_environment_file(
                handle.as_ref(),
                &resolved_users,
                &ssh_session_env,
            )?;
            self.ensure_ssh_session_profile_loader_files(handle.as_ref(), &resolved_users)?;

            let shell = self.config.default_shell.as_deref().unwrap_or("zsh");
            self.ensure_remote_user_login_shell(handle.as_ref(), &resolved_users, shell)?;
        }

        if let Some(command) = &devcontainer_workspace.devcontainer.on_create_command {
            run_lifecycle_command_once(
                self.runtime.as_ref(),
                handle.as_ref(),
                &devcontainer_workspace,
                command,
                "onCreateCommand",
                false,
                true,
            )?;
        }

        // Set up GPG inside the container: copy data files from the staged host
        // homedir (skipping socket files), then fix permissions.
        // S.gpg-agent and S.keyboxd are already bind-mounted directly at their
        // natural paths inside {home}/.gnupg.
        if gpg_agent_available {
            debug!("Setting up GPG homedir inside container from staged host copy");
            let home = &resolved_users.remote_user_home;
            let gpg_cmd = format!(
                r#"sudo mkdir -p {home}/.gnupg && sudo chmod 0700 {home}/.gnupg && sudo chown $(id -u):$(id -g) {home}/.gnupg
 for src in /tmp/devcon-gnupg-host/*; do
   name=$(basename "$src")
   case "$name" in S.*) continue ;; esac
   if [ -d "$src" ]; then
     sudo cp -rp "$src" "{home}/.gnupg/$name"
   elif [ -f "$src" ]; then
     sudo cp -p "$src" "{home}/.gnupg/$name"
   fi
 done
 sudo chown -R $(id -u):$(id -g) {home}/.gnupg
 sudo chmod -R u=rwX,go= {home}/.gnupg
 grep -qF no-autostart {home}/.gnupg/gpg.conf 2>/dev/null || printf 'no-autostart\n' >> {home}/.gnupg/gpg.conf
 grep -qF allow-loopback-pinentry {home}/.gnupg/gpg-agent.conf 2>/dev/null || printf 'allow-loopback-pinentry\n' >> {home}/.gnupg/gpg-agent.conf"#,
                home = home,
            );
            let guarded = guard_with_marker(&gpg_cmd, "gpgAgentSetup");
            self.runtime.exec(
                handle.as_ref(),
                vec!["bash", "-c", &guarded],
                &[],
                false,
                false,
            )?;
        }

        // Fix file permissions on ssh agent socket
        if ssh_agent_available {
            debug!("Setting permissions on SSH agent socket inside container");
            let ssh_sock_in_container = ssh_socket_in_container
                .as_deref()
                .unwrap_or("/tmp/devcon-ssh-agent");
            let cmd = format!(
                "if [ -S {p} ]; then sudo chmod 600 {p} && sudo chown $(id -u):$(id -g) {p}; fi",
                p = ssh_sock_in_container
            );
            let guarded = guard_with_marker(&cmd, "sshAgentSetup");
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
            let guarded = guard_with_marker(dotfiles_cmd.trim(), "dotfilesSetup");
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
                    let guarded = guard_with_marker(&combined, "ghForwarding");
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
            run_lifecycle_command_once(
                self.runtime.as_ref(),
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
                    let wrapped_cmd = entrypoint.to_string();
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
            run_lifecycle_command_always(
                self.runtime.as_ref(),
                handle.as_ref(),
                &devcontainer_workspace,
                command,
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
        let remote_user = shell_single_quote(&users.remote_user);

        let command = format!(
            "set -e; \
            mkdir -p '{home}/.ssh'; \
            chown '{remote_user}':'{remote_user}' '{home}/.ssh' 2>/dev/null || chown '{remote_user}' '{home}/.ssh'; \
            chmod 700 '{home}/.ssh'; \
            touch '{home}/.ssh/authorized_keys'; \
            grep -qxF '{key}' '{home}/.ssh/authorized_keys' || printf '%s\\n' '{key}' >> '{home}/.ssh/authorized_keys'; \
            chown '{remote_user}':'{remote_user}' '{home}/.ssh/authorized_keys' 2>/dev/null || chown '{remote_user}' '{home}/.ssh/authorized_keys'; \
            chmod 600 '{home}/.ssh/authorized_keys'"
        );

        self.runtime
            .exec(handle, vec!["sh", "-lc", &command], &[], false, false)
    }

    fn ensure_ssh_session_environment_file(
        &self,
        handle: &dyn crate::driver::runtime::ContainerHandle,
        users: &ResolvedUsers,
        ssh_env: &[(String, String)],
    ) -> Result<()> {
        let home = shell_single_quote(&users.remote_user_home);
        let env_path = shell_single_quote(&format!("{}/.ssh/environment", users.remote_user_home));
        let env_content = Self::build_ssh_environment_file_content(ssh_env);

        let command = if env_content.is_empty() {
            format!(
                "set -e; \
                mkdir -p '{home}/.ssh'; \
                chmod 700 '{home}/.ssh'; \
                chown -R {} '{home}/.ssh' 2>/dev/null || true; \
                rm -f '{env_path}'",
                shell_single_quote(&users.remote_user)
            )
        } else {
            let quoted_content = shell_single_quote(&env_content);
            format!(
                "set -e; \
                mkdir -p '{home}/.ssh'; \
                chmod 700 '{home}/.ssh'; \
                printf '%s' '{quoted_content}' > '{env_path}'; \
                chmod 600 '{env_path}'; \
                chown -R {} '{home}/.ssh' 2>/dev/null || true",
                shell_single_quote(&users.remote_user)
            )
        };

        self.runtime
            .exec(handle, vec!["sh", "-lc", &command], &[], false, false)
    }

    fn ensure_ssh_session_profile_loader_files(
        &self,
        handle: &dyn crate::driver::runtime::ContainerHandle,
        users: &ResolvedUsers,
    ) -> Result<()> {
        let home = shell_single_quote(&users.remote_user_home);
        let profile_path = shell_single_quote(&format!("{}/.profile", users.remote_user_home));
        let zprofile_path = shell_single_quote(&format!("{}/.zprofile", users.remote_user_home));
        let snippet_start = "# >>> devcon ssh session env >>>";
        let snippet_end = "# <<< devcon ssh session env <<<";
        let snippet = shell_single_quote(
            "# >>> devcon ssh session env >>>\nif [ -n \"$SSH_CONNECTION\" ]; then\n    set -a\n    [ -f \"$HOME/.ssh/environment\" ] && . \"$HOME/.ssh/environment\"\n    set +a\n    if tty >/dev/null 2>&1; then\n        export GPG_TTY=$(tty)\n    fi\nfi\n# <<< devcon ssh session env <<<\n",
        );

        let command = format!(
            "set -e; \
            mkdir -p '{home}/.ssh'; \
            for target in '{profile_path}' '{zprofile_path}'; do \
                if [ -f \"$target\" ] && grep -Fq '{snippet_start}' \"$target\"; then \
                    tmp=\"$target.devcon.tmp\"; \
                    awk '\n                        BEGIN {{ skip = 0 }}\n                        $0 == \"{snippet_start}\" {{ skip = 1; next }}\n                        $0 == \"{snippet_end}\" {{ skip = 0; next }}\n                        skip == 0 {{ print }}\n                    ' \"$target\" > \"$tmp\" && mv \"$tmp\" \"$target\"; \
                fi; \
                if [ -f \"$target\" ] && [ -s \"$target\" ] && [ \"$(tail -c 1 \"$target\" 2>/dev/null || true)\" != \"\" ]; then \
                    printf '\\n' >> \"$target\"; \
                fi; \
                printf '%s' '{snippet}' >> \"$target\"; \
                chown {user}:{user} \"$target\" 2>/dev/null || chown {user} \"$target\"; \
            done",
            user = shell_single_quote(&users.remote_user)
        );

        self.runtime
            .exec(handle, vec!["sh", "-lc", &command], &[], false, false)
    }

    fn refresh_gpg_public_keys_for_connection(
        &self,
        handle: &dyn crate::driver::runtime::ContainerHandle,
    ) -> Result<()> {
        let Some(agent_fwd) = self.config.agent_forwarding.as_ref() else {
            return Ok(());
        };

        if !agent_fwd.gpg_enabled.unwrap_or(false) {
            return Ok(());
        }

        let command = "gpgconf --reload gpg-agent >/dev/null 2>&1 || true";
        self.runtime
            .exec(handle, vec!["sh", "-lc", command], &[], false, false)
    }

    fn build_ssh_environment_file_content(ssh_env: &[(String, String)]) -> String {
        let mut lines = Vec::new();

        for (name, value) in ssh_env {
            if !Self::is_valid_ssh_env_name(name) {
                continue;
            }

            let sanitized = Self::sanitize_ssh_env_value(value);
            lines.push(format!("{}={}", name, sanitized));
        }

        lines.sort();
        if lines.is_empty() {
            String::new()
        } else {
            format!("{}\n", lines.join("\n"))
        }
    }

    fn is_valid_ssh_env_name(name: &str) -> bool {
        let mut chars = name.chars();
        let Some(first) = chars.next() else {
            return false;
        };

        if !first.is_ascii_alphabetic() && first != '_' {
            return false;
        }

        chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
    }

    fn sanitize_ssh_env_value(value: &str) -> String {
        value
            .chars()
            .filter(|c| !matches!(c, '\n' | '\r' | '\0'))
            .collect()
    }

    fn ensure_remote_user_login_shell(
        &self,
        handle: &dyn crate::driver::runtime::ContainerHandle,
        users: &ResolvedUsers,
        shell: &str,
    ) -> Result<()> {
        if users.remote_user == "root" {
            return Ok(());
        }

        let quoted_user = shell_single_quote(&users.remote_user);
        let quoted_shell = shell_single_quote(shell);
        let command = format!(
            "shell_path=$(command -v {shell} || true); \
            if [ -z \"$shell_path\" ]; then \
                echo 'Warning: requested shell {shell} is not installed; keeping existing login shell' >&2; \
                exit 0; \
            fi; \
            if command -v usermod >/dev/null 2>&1; then \
                if [ \"$(id -u)\" = \"0\" ]; then \
                    usermod -s \"$shell_path\" {user} || true; \
                elif command -v sudo >/dev/null 2>&1; then \
                    sudo -n usermod -s \"$shell_path\" {user} || true; \
                else \
                    echo 'Warning: cannot change login shell (need root or passwordless sudo)' >&2; \
                fi; \
            elif command -v chsh >/dev/null 2>&1; then \
                chsh -s \"$shell_path\" {user} || true; \
            else \
                echo 'Warning: neither usermod nor chsh is available; keeping existing login shell' >&2; \
            fi",
            shell = quoted_shell,
            user = quoted_user,
        );

        if let Err(err) = self
            .runtime
            .exec(handle, vec!["sh", "-lc", &command], &[], false, false)
        {
            warn!(
                "Failed to normalize login shell for user '{}': {}",
                users.remote_user, err
            );
        }

        Ok(())
    }

    fn build_ssh_session_environment_entries(
        &self,
        workspace: &Workspace,
    ) -> Result<Vec<(String, String)>> {
        let mut entries = self.resolve_ssh_session_environment(workspace)?;

        if self.resolve_forwarded_ssh_socket_target().is_some() {
            entries.push((
                "SSH_AUTH_SOCK".to_string(),
                "/tmp/devcon-ssh-agent".to_string(),
            ));
            // Keep backwards compatibility for tooling expecting SSH_AUTH_SOCKET.
            entries.push((
                "SSH_AUTH_SOCKET".to_string(),
                "/tmp/devcon-ssh-agent".to_string(),
            ));
        }

        entries.sort_by(|a, b| a.0.cmp(&b.0));
        entries.dedup_by(|a, b| a.0 == b.0);
        Ok(entries)
    }

    fn resolve_forwarded_ssh_socket_target(&self) -> Option<String> {
        let agent_fwd = self.config.agent_forwarding.as_ref()?;
        if !agent_fwd.ssh_enabled.unwrap_or(false) {
            return None;
        }

        if let Some(ref override_path) = agent_fwd.ssh_socket_path {
            let path = PathBuf::from(override_path);
            return path.exists().then_some(path.to_string_lossy().to_string());
        }

        detect_ssh_socket().map(|path| path.to_string_lossy().to_string())
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
    /// # use devcon::driver::container::ContainerOrchestrator;
    /// # use devcon::driver::runtime::docker::DockerRuntime;
    /// # use std::path::PathBuf;
    /// # fn example() -> devcon::error::Result<()> {
    /// let config = Config::load(None)?;
    /// let runtime = Box::new(DockerRuntime::new(DockerRuntimeConfig::default()));
    /// let driver = ContainerOrchestrator::new(config, runtime);
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
            run_lifecycle_command_always(
                self.runtime.as_ref(),
                handle,
                &devcontainer_workspace,
                command,
                false,
                true,
            )?;
        }

        let remote_user = self.resolve_remote_user_for_workspace(&devcontainer_workspace);
        let shell = self.config.default_shell.as_deref().unwrap_or("zsh");
        let shell_command: Vec<String> = if remote_user == "root" {
            vec![shell.to_string()]
        } else {
            let quoted_user = shell_single_quote(&remote_user);
            let quoted_shell = shell_single_quote(shell);
            let command = format!(
                "if [ \"$(id -un)\" = {user} ]; then exec {shell}; \
                 elif command -v sudo >/dev/null 2>&1; then exec sudo -u {user} -H sh -lc 'exec {shell}'; \
                 elif command -v su >/dev/null 2>&1; then exec su - {user} -c {shell}; \
                 else echo 'Warning: cannot switch to remote user {name}; opening shell as current user' >&2; exec {shell}; fi",
                user = quoted_user,
                shell = quoted_shell,
                name = remote_user,
            );
            vec!["sh".to_string(), "-lc".to_string(), command]
        };
        let shell_command_refs: Vec<&str> = shell_command.iter().map(String::as_str).collect();

        self.runtime
            .exec(handle, shell_command_refs, &processed_env_vars, true, true)?;

        Ok(())
    }

    fn get_image_tag(&self, devcontainer_workspace: &Workspace) -> String {
        format!("devcon-{}", devcontainer_workspace.get_sanitized_name())
    }

    fn resolve_probe_user_hint(&self, workspace: &Workspace, image_tag: &str) -> Option<String> {
        workspace
            .devcontainer
            .remote_user
            .clone()
            .or_else(|| self.remote_user_from_image_metadata(image_tag))
    }

    fn remote_user_from_image_metadata(&self, image_tag: &str) -> Option<String> {
        self.runtime
            .inspect_image(image_tag)
            .ok()
            .flatten()
            .as_ref()
            .and_then(Self::remote_user_from_metadata)
    }

    fn feature_display_label(feature: &FeatureProcessResult) -> String {
        let name = feature.name();
        if name == feature.feature.id {
            name
        } else {
            format!("{} ({})", name, feature.feature.id)
        }
    }

    fn build_feature_progress_items(
        &self,
        processed_features: &[FeatureProcessResult],
    ) -> Vec<FeatureProgressItem> {
        processed_features
            .iter()
            .map(|feature| FeatureProgressItem {
                id: feature.feature.id.clone(),
                label: Self::feature_display_label(feature),
            })
            .collect()
    }

    fn print_feature_evaluation_order(&self, feature_progress: &[FeatureProgressItem]) {
        println!("Evaluated feature order:");
        if feature_progress.is_empty() {
            println!("  (no features configured)");
            return;
        }

        for (index, feature) in feature_progress.iter().enumerate() {
            println!("  {}. {}", index + 1, feature.label);
        }
    }

    fn print_build_environment_summary(
        &self,
        evaluated_env: &[String],
        base_env: &HashMap<String, String>,
        resolved_users: &ResolvedUsers,
        probe_info: Option<&ContainerProbeInfo>,
    ) {
        let env_map = evaluated_env
            .iter()
            .filter_map(|entry| {
                let (key, value) = entry.split_once('=')?;
                Some((key.to_string(), value.to_string()))
            })
            .collect::<HashMap<_, _>>();

        let path = env_map
            .get("PATH")
            .cloned()
            .or_else(|| base_env.get("PATH").cloned())
            .unwrap_or_else(|| "<unset>".to_string());

        let user = probe_info
            .map(|p| p.user.clone())
            .unwrap_or_else(|| resolved_users.remote_user.clone());
        let home = probe_info
            .map(|p| p.home.clone())
            .or_else(|| env_map.get("HOME").cloned())
            .unwrap_or_else(|| resolved_users.remote_user_home.clone());

        println!("Evaluated environment summary:");
        println!("  USER={}", user);
        println!("  HOME={}", home);
        println!("  PATH={}", path);
        println!("  Total vars={}", env_map.len());
    }

    fn read_lockfile(
        &self,
        devcontainer_workspace: &Workspace,
    ) -> Result<Option<DevcontainerLockfile>> {
        let Some(lock_path) = resolve_lockfile_path(&devcontainer_workspace.path) else {
            return Ok(None);
        };

        if !lock_path.exists() {
            return Ok(None);
        }

        let content = fs::read_to_string(&lock_path)?;
        let lockfile: DevcontainerLockfile = serde_json::from_str(&content).map_err(|e| {
            Error::feature(format!(
                "Failed to parse lockfile {}: {}",
                lock_path.display(),
                e
            ))
        })?;
        Ok(Some(lockfile))
    }

    fn write_lockfile(
        &self,
        devcontainer_workspace: &Workspace,
        lockfile: &DevcontainerLockfile,
    ) -> Result<()> {
        let Some(lock_path) = resolve_lockfile_path(&devcontainer_workspace.path) else {
            return Err(Error::feature(
                "Could not resolve lockfile path for workspace",
            ));
        };

        let serialized = serde_json::to_string_pretty(lockfile)?;
        if let Ok(existing) = fs::read_to_string(&lock_path)
            && existing == serialized
        {
            return Ok(());
        }

        if let Some(parent) = lock_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let temp_path = lock_path.with_extension("json.tmp");
        fs::write(&temp_path, serialized)?;
        fs::rename(temp_path, lock_path)?;
        Ok(())
    }

    fn get_container_name(&self, devcontainer_workspace: &Workspace) -> String {
        format!("devcon.{}", devcontainer_workspace.get_sanitized_name())
    }

    fn get_container_label(&self, devcontainer_workspace: &Workspace) -> String {
        format!(
            "devcon.project={}",
            devcontainer_workspace.get_sanitized_name()
        )
    }

    fn get_devcontainer_id(&self, devcontainer_workspace: &Workspace) -> String {
        let mut hasher = Sha256::new();

        let devcontainer_path = schema::resolve_devcontainer_file_path(
            &devcontainer_workspace.path,
        )
        .unwrap_or_else(|| {
            devcontainer_workspace
                .path
                .join(".devcontainer")
                .join("devcontainer.json")
        });

        match fs::read_to_string(&devcontainer_path) {
            Ok(content) => {
                hasher.update(content.as_bytes());
            }
            Err(_) => {
                hasher.update(devcontainer_workspace.path.to_string_lossy().as_bytes());
            }
        }

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

            if let Some(args) = &build_config.args {
                let mut sorted_args: Vec<(&String, &String)> = args.iter().collect();
                sorted_args.sort_by_key(|(k, _)| *k);
                for (k, v) in sorted_args {
                    hasher.update(format!("{}={}", k, v).as_bytes());
                }
            }
        }

        if let Some(lockfile_path) = resolve_lockfile_path(&devcontainer_workspace.path)
            && let Ok(lockfile_content) = fs::read_to_string(lockfile_path)
        {
            hasher.update(lockfile_content.as_bytes());
        }

        let result = hasher.finalize();
        result.iter().map(|byte| format!("{:02x}", byte)).collect()
    }

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

    #[allow(dead_code)]
    fn control_server_pid_path() -> PathBuf {
        dirs::runtime_dir()
            .unwrap_or_else(std::env::temp_dir)
            .join("devcon.pid")
    }

    #[allow(dead_code)]
    fn is_control_server_running() -> bool {
        let pid_path = Self::control_server_pid_path();
        let lock = match Pidlock::new_validated(&pid_path) {
            Ok(lock) => lock,
            Err(_) => return false,
        };

        lock.exists() && lock.is_active().unwrap_or(false)
    }

    fn canonical_image_architecture(arch: &str) -> String {
        let normalized = arch.trim().to_lowercase();
        match normalized.as_str() {
            "x86_64" => "amd64".to_string(),
            "aarch64" => "arm64".to_string(),
            _ => normalized,
        }
    }

    fn extract_architecture_from_inspect(inspect: &ContainerImageInfo) -> Option<String> {
        inspect
            .architecture
            .clone()
            .map(|arch| Self::canonical_image_architecture(&arch))
    }

    fn resolve_users_for_image(
        &self,
        workspace: &Workspace,
        image_tag: &str,
        probe_info: Option<&ContainerProbeInfo>,
    ) -> ResolvedUsers {
        let detected_user = probe_info.map(|i| i.user.clone());
        let detected_home = probe_info.map(|i| i.home.clone());

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

        debug!(
            "Resolved container users for '{}': remote_user='{}', container_user='{}'",
            image_tag, remote_user, container_user
        );

        ResolvedUsers {
            remote_user_home,
            container_user_home,
            remote_user,
            container_user,
        }
    }

    fn resolve_image_architecture(
        &self,
        image_tag: &str,
        probe_info: Option<&ContainerProbeInfo>,
    ) -> String {
        let inspect = self.runtime.inspect_image(image_tag).ok().flatten();
        let detected_architecture = probe_info
            .and_then(|i| i.architecture.as_deref())
            .map(Self::canonical_image_architecture);
        let inspect_architecture = inspect
            .as_ref()
            .and_then(Self::extract_architecture_from_inspect);
        let image_architecture = detected_architecture
            .or(inspect_architecture)
            .unwrap_or_else(Self::host_image_architecture);

        debug!(
            "Resolved image architecture for '{}': probe={:?}, inspect={:?}, final='{}'",
            image_tag,
            probe_info.and_then(|i| i.architecture.as_deref()),
            inspect.as_ref().and_then(|i| i.architecture.as_deref()),
            image_architecture
        );

        image_architecture
    }

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
}

fn normalize_capability_name(capability: &str) -> String {
    capability.trim().to_ascii_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DockerRuntimeConfig;

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
        let driver = ContainerOrchestrator::new(config, runtime);

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
        let driver = ContainerOrchestrator::new(config, runtime);

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
    fn test_build_ssh_environment_file_content_filters_invalid_names() {
        let input = vec![
            ("VALID_NAME".to_string(), "ok".to_string()),
            ("1INVALID".to_string(), "bad".to_string()),
            ("ALSO-INVALID".to_string(), "bad".to_string()),
        ];

        let content = ContainerOrchestrator::build_ssh_environment_file_content(&input);
        assert_eq!(content, "VALID_NAME=ok\n");
    }

    #[test]
    fn test_build_ssh_environment_file_content_sanitizes_newlines() {
        let input = vec![("PATH".to_string(), "line1\nline2\r\0".to_string())];

        let content = ContainerOrchestrator::build_ssh_environment_file_content(&input);
        assert_eq!(content, "PATH=line1line2\n");
    }
}
