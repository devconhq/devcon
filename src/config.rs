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

//! # Configuration Module
//!
//! This module handles loading and managing DevCon configuration files.
//!
//! ## Overview
//!
//! The configuration is stored in YAML format in the XDG config directory,
//! typically at `~/.config/devcon/config.yaml` on Linux/macOS.
//!
//! ## Configuration Options
//!
//! - **dotfiles_repository** - URL to a dotfiles repository to clone into containers
//! - **additional_features** - List of devcontainer features to add to all containers
//! - **env_variables** - Environment variables to pass to all containers
//!
//! ## Examples
//!
//! ```yaml
//! dotfilesRepository: https://github.com/user/dotfiles
//! additionalFeatures:
//!   ghcr.io/devcontainers/features/common-utils:2:
//!     installZsh: true
//! envVariables:
//!   - EDITOR=vim
//!   - LANG=en_US.UTF-8
//! ```

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};

/// Agent configuration settings.
///
/// This structure holds all agent-related configuration options.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AgentConfig {
    /// Use Agent binary instead of compiling from source.
    ///
    /// If true, the agent will be downloaded from `binaryUrl`. If false, it will be compiled from `gitRepository`.
    /// If not set, defaults to true
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_agent_binary: Option<bool>,

    /// Agent binary URL for precompiled agent.
    ///
    /// If set, the agent will be downloaded from this URL instead of being compiled.
    /// The URL should point to a precompiled devcon-agent binary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary_url: Option<String>,

    /// Git repository URL for agent source code.
    ///
    /// If set (and binary_url is not set), the agent will be compiled from this repository.
    /// Defaults to "https://github.com/devconhq/devcon.git" if not specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_repository: Option<String>,

    /// Git branch to checkout when compiling agent from source.
    ///
    /// Only used when compiling from git repository.
    /// Defaults to "main" if not specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_branch: Option<String>,

    /// Disable the agent installation.
    ///
    /// If set to true, the agent will not be installed in the container.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable: Option<bool>,

    /// Override the SSH port used inside the container.
    ///
    /// If not set, defaults to 22.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_port: Option<u16>,

    /// Skip OpenSSH setup and SSH port forwarding.
    ///
    /// If set to true, devcon will not install or start sshd and will not
    /// auto-forward the configured SSH port.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_ssh_setup: Option<bool>,
}

/// Docker runtime-specific configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DockerRuntimeConfig {
    /// Memory limit for container builds (e.g., "4g", "512m").
    ///
    /// If not set, no memory limit is applied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_memory: Option<String>,

    /// CPU limit for container builds (e.g., "2", "0.5").
    ///
    /// If not set, no CPU limit is applied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_cpu: Option<String>,

    /// Memory limit for running containers (e.g., "8g", "512m").
    ///
    /// If not set, no memory limit is applied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_memory: Option<String>,

    /// CPU limit for running containers (e.g., "2", "0.5").
    ///
    /// If not set, no CPU limit is applied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_cpu: Option<String>,
}

/// Container runtime-specific configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContainerRuntimeConfig {
    /// Memory limit for container builds (e.g., "4g", "512m").
    ///
    /// Defaults to "4g" if not specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_memory: Option<String>,

    /// CPU limit for container builds (e.g., "2", "0.5").
    ///
    /// If not set, no CPU limit is applied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_cpu: Option<String>,

    /// Memory limit for running containers (e.g., "8g", "512m").
    ///
    /// Defaults to "8g" if not specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_memory: Option<String>,

    /// CPU limit for running containers (e.g., "2", "0.5").
    ///
    /// Defaults to "2" if not specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_cpu: Option<String>,
}

impl Default for ContainerRuntimeConfig {
    fn default() -> Self {
        Self {
            build_memory: Some("4g".to_string()),
            build_cpu: None,
            run_memory: Some("8g".to_string()),
            run_cpu: Some("2".to_string()),
        }
    }
}

/// Runtime-specific configuration settings.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeConfig {
    /// Docker runtime configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub docker: Option<DockerRuntimeConfig>,

    /// Container runtime configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container: Option<ContainerRuntimeConfig>,
}

/// Agent forwarding configuration.
///
/// Controls whether SSH, GPG, and GitHub CLI credentials are forwarded into containers.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AgentForwardingConfig {
    /// Enable SSH agent forwarding.
    ///
    /// When enabled, the SSH_AUTH_SOCK socket will be mounted into the container.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_enabled: Option<bool>,

    /// Enable GPG agent forwarding.
    ///
    /// When enabled, the GPG agent socket will be mounted into the container.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gpg_enabled: Option<bool>,

    /// Enable GitHub CLI (gh) authentication forwarding.
    ///
    /// When enabled, the GitHub CLI configuration directory will be mounted into the container.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gh_enabled: Option<bool>,

    /// Override SSH agent socket path.
    ///
    /// If not set, will auto-detect from SSH_AUTH_SOCK environment variable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_socket_path: Option<String>,

    /// Override GPG agent socket path.
    ///
    /// If not set, will auto-detect using gpgconf.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gpg_socket_path: Option<String>,

    /// Override GitHub CLI configuration directory path.
    ///
    /// If not set, will auto-detect from ~/.config/gh.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gh_config_path: Option<String>,
}

/// Main configuration structure for DevCon.
///
/// This structure holds user preferences and defaults that are applied
/// across all devcontainer operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    /// URL to a dotfiles repository.
    ///
    /// If set, this repository will be cloned into the container
    /// to provide user-specific configuration files.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dotfiles_repository: Option<String>,

    /// Install command which will be used to install dotfiles
    ///
    /// If set, this command will be used to install the dotfiles after cloning
    /// If unset, will search for common install scripts like install.sh, setup.sh, etc.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dotfiles_install_command: Option<String>,

    /// Default shell
    ///
    /// If set, the shell command will use this shell to exec into the container
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_shell: Option<String>,

    /// Additional devcontainer features to include in all containers.
    ///
    /// These features are merged with features defined in devcontainer.json.
    /// The key is the feature identifier (e.g., "ghcr.io/owner/repo/feature:version")
    /// and the value is a map of options for that feature.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub additional_features: HashMap<String, serde_json::Value>,

    /// Environment variables to pass to containers.
    ///
    /// If the string has the format KEY=value, it will be set as an environment variable in the container
    /// If its only a string without "=" it will be passed through as is from the host container.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env_variables: Vec<String>,

    /// Container runtime to use.
    ///
    /// Valid values: "auto", "docker", "container"
    /// If set to "auto" (default), the runtime will be auto-detected.
    #[serde(
        default = "default_runtime",
        skip_serializing_if = "is_default_runtime"
    )]
    pub runtime: String,

    /// Default build path for container builds.
    ///
    /// If set, this path will be used for building containers unless overridden by CLI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_path: Option<String>,

    /// Agent configuration settings.
    ///
    /// Contains all agent-related options like binary URL, git repository, etc.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agents: Option<AgentConfig>,

    /// Runtime-specific configuration settings.
    ///
    /// Contains runtime-specific options for Docker and the container CLI runtime.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_config: Option<RuntimeConfig>,

    /// Agent forwarding configuration.
    ///
    /// Controls SSH and GPG agent socket forwarding into containers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_forwarding: Option<AgentForwardingConfig>,
}

fn default_runtime() -> String {
    "auto".to_string()
}

fn is_default_runtime(runtime: &str) -> bool {
    runtime == "auto"
}

impl Default for Config {
    fn default() -> Self {
        Self {
            dotfiles_repository: None,
            dotfiles_install_command: None,
            default_shell: None,
            additional_features: HashMap::new(),
            env_variables: Vec::new(),
            runtime: default_runtime(),
            build_path: None,
            agents: None,
            runtime_config: None,
            agent_forwarding: None,
        }
    }
}

impl Config {
    /// Loads the configuration from the XDG config directory or a custom path.
    ///
    /// This method looks for the config file at:
    /// - The provided custom path (if `config_path` is Some)
    /// - `$XDG_CONFIG_HOME/devcon/config.yaml` (if XDG_CONFIG_HOME is set)
    /// - `~/.config/devcon/config.yaml` (default on Linux/macOS)
    /// - `%APPDATA%/devcon/config.yaml` (on Windows)
    ///
    /// If no config file exists, returns a default empty configuration.
    ///
    /// # Arguments
    ///
    /// * `config_path` - Optional custom path to config file. If provided, this path
    ///   will be used instead of the default XDG config location.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The config file exists but cannot be read
    /// - The config file contains invalid YAML
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use devcon::config::Config;
    /// # use std::path::PathBuf;
    /// // Load from default location
    /// let config = Config::load(None)?;
    ///
    /// // Load from custom location
    /// let custom_config = Config::load(Some(PathBuf::from("/tmp/test-config.yaml")))?;
    /// # Ok::<(), devcon::error::Error>(())
    /// ```
    pub fn load(config_path: Option<PathBuf>) -> Result<Self> {
        let config_path = match config_path {
            Some(path) => path,
            None => Self::get_config_path()?,
        };

        if !config_path.exists() {
            return Ok(Self::default());
        }

        let content = fs::read_to_string(&config_path).map_err(|e| {
            Error::config(format!(
                "Failed to read config file: {}: {}",
                config_path.display(),
                e
            ))
        })?;

        // Check for old config format fields
        if content.contains("agentBinaryUrl")
            || content.contains("agentGitRepository")
            || content.contains("agentGitBranch")
            || content.contains("agentDisable")
        {
            return Err(Error::config(format!(
                "Old config format detected in {}. Please manually migrate agent_* fields to the new agents.* hierarchy. \
                See the configuration reference in the README or the repository example config for available properties.",
                config_path.display()
            )));
        }

        let config: Config = yaml_serde::from_str(&content).map_err(|e| {
            Error::config(format!(
                "Failed to parse config file: {}: {}",
                config_path.display(),
                e
            ))
        })?;

        Ok(config)
    }

    /// Returns the path to the config file.
    ///
    /// This uses the XDG Base Directory specification on Unix-like systems
    /// and the appropriate AppData directory on Windows.
    ///
    /// # Errors
    ///
    /// Returns an error if the config directory cannot be determined
    /// (e.g., if HOME is not set).
    pub fn get_config_path() -> Result<PathBuf> {
        let config_dir = dirs::config_dir()
            .ok_or_else(|| Error::config("Failed to determine config directory"))?;

        Ok(config_dir.join("devcon").join("config.yaml"))
    }

    /// Merges additional features from the config with existing features.
    ///
    /// This creates a combined map of features, with devcontainer.json
    /// features taking precedence over config features.
    ///
    /// # Arguments
    ///
    /// * `devcontainer_features` - Features from devcontainer.json
    ///
    /// # Returns
    ///
    /// A HashMap containing all features with their options.
    #[allow(dead_code)]
    pub fn merge_features(
        &self,
        devcontainer_features: &[(String, serde_json::Value)],
    ) -> HashMap<String, serde_json::Value> {
        let mut merged = self.additional_features.clone();

        // Devcontainer features override config features
        for (key, value) in devcontainer_features {
            merged.insert(key.clone(), value.clone());
        }

        merged
    }

    /// Detects which container runtime is available.
    ///
    /// Checks for Docker and the container CLI in order.
    /// Returns "docker" if docker is available, "container" if container is available,
    /// or an error if neither is found.
    pub fn detect_runtime() -> Result<String> {
        // Check for docker
        if Command::new("docker")
            .arg("--version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
        {
            return Ok("docker".to_string());
        }

        // Check for container CLI
        if Command::new("container")
            .arg("--version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
        {
            return Ok("container".to_string());
        }

        Err(Error::runtime(
            "No container runtime found. Please install Docker or the container CLI.",
        ))
    }

    /// Gets the runtime to use, resolving "auto" to a specific runtime.
    pub fn resolve_runtime(&self) -> Result<String> {
        if self.runtime == "auto" {
            Self::detect_runtime()
        } else {
            Ok(self.runtime.clone())
        }
    }

    pub fn get_agent_use_binary(&self) -> bool {
        self.agents
            .as_ref()
            .and_then(|a| a.use_agent_binary)
            .unwrap_or(true)
    }

    /// Gets the agent binary URL if configured.
    pub fn get_agent_binary_url(&self) -> Option<&String> {
        self.agents.as_ref().and_then(|a| a.binary_url.as_ref())
    }

    /// Gets the agent git repository if configured.
    pub fn get_agent_git_repository(&self) -> Option<&String> {
        self.agents.as_ref().and_then(|a| a.git_repository.as_ref())
    }

    /// Gets the agent git branch if configured.
    pub fn get_agent_git_branch(&self) -> Option<&String> {
        self.agents.as_ref().and_then(|a| a.git_branch.as_ref())
    }

    /// Checks if the agent is disabled.
    pub fn is_agent_disabled(&self) -> bool {
        self.agents
            .as_ref()
            .and_then(|a| a.disable)
            .unwrap_or(false)
    }

    /// Gets the SSH port used inside the container for `devcon ssh`.
    pub fn get_agent_ssh_port(&self) -> u16 {
        self.agents
            .as_ref()
            .and_then(|a| a.ssh_port)
            .filter(|p| *p != 0)
            .unwrap_or(22)
    }

    /// Checks if OpenSSH setup should be skipped for the in-container agent.
    pub fn should_skip_agent_ssh_setup(&self) -> bool {
        self.agents
            .as_ref()
            .and_then(|a| a.skip_ssh_setup)
            .unwrap_or(false)
    }

    /// Gets the runtime config, using defaults if not configured.
    pub fn get_runtime_config(&self) -> RuntimeConfig {
        self.runtime_config.clone().unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(config.dotfiles_repository.is_none());
        assert!(config.additional_features.is_empty());
        assert!(config.env_variables.is_empty());
    }

    #[test]
    fn test_config_serialization() {
        let config = Config {
            dotfiles_repository: Some("https://github.com/user/dotfiles".to_string()),
            env_variables: vec!["EDITOR=vim".to_string()],
            ..Default::default()
        };

        let yaml = yaml_serde::to_string(&config).unwrap();
        assert!(yaml.contains("dotfilesRepository"));
        assert!(yaml.contains("https://github.com/user/dotfiles"));
        assert!(yaml.contains("envVariables"));
    }

    #[test]
    fn test_config_deserialization() {
        let yaml = r#"
dotfilesRepository: https://github.com/user/dotfiles
additionalFeatures:
  ghcr.io/devcontainers/features/git:1:
    version: latest
envVariables:
  - EDITOR=vim
  - LANG=en_US.UTF-8
"#;

        let config: Config = yaml_serde::from_str(yaml).unwrap();
        assert_eq!(
            config.dotfiles_repository,
            Some("https://github.com/user/dotfiles".to_string())
        );
        assert_eq!(config.additional_features.len(), 1);
        assert_eq!(config.env_variables.len(), 2);
    }

    #[test]
    fn test_merge_features() {
        let mut config = Config::default();
        config.additional_features.insert(
            "ghcr.io/devcontainers/features/git:1".to_string(),
            serde_json::json!({"version": "latest"}),
        );
        config.additional_features.insert(
            "ghcr.io/devcontainers/features/node:2".to_string(),
            serde_json::json!({"version": "18"}),
        );

        let devcontainer_features = vec![(
            "ghcr.io/devcontainers/features/node:2".to_string(),
            serde_json::json!({"version": "20"}),
        )];

        let merged = config.merge_features(&devcontainer_features);

        assert_eq!(merged.len(), 2);
        // Devcontainer feature should override config feature
        assert_eq!(
            merged.get("ghcr.io/devcontainers/features/node:2").unwrap()["version"],
            "20"
        );
        assert_eq!(
            merged.get("ghcr.io/devcontainers/features/git:1").unwrap()["version"],
            "latest"
        );
    }

    #[test]
    fn test_agent_ssh_settings_defaults() {
        let config = Config::default();
        assert_eq!(config.get_agent_ssh_port(), 22);
        assert!(!config.should_skip_agent_ssh_setup());
    }

    #[test]
    fn test_agent_ssh_settings_from_config() {
        let config = Config {
            agents: Some(AgentConfig {
                ssh_port: Some(2222),
                skip_ssh_setup: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        };

        assert_eq!(config.get_agent_ssh_port(), 2222);
        assert!(config.should_skip_agent_ssh_setup());
    }
}
