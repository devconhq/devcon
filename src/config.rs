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

/// Property metadata for configuration fields.
#[derive(Debug, Clone, Copy)]
pub struct PropertyMetadata {
    /// Full property path in camelCase (e.g., "agents.binaryUrl")
    pub path: &'static str,
    /// Property type
    pub property_type: PropertyType,
    /// Human-readable description
    pub description: &'static str,
    /// Validation rule to apply
    pub validator: PropertyValidator,
}

/// Types of configuration properties.
#[derive(Debug, Clone, Copy)]
pub enum PropertyType {
    String,
    Boolean,
}

/// Validation rules for configuration properties.
#[derive(Debug, Clone, Copy)]
pub enum PropertyValidator {
    None,
    Url,
    Enum(&'static [&'static str]),
    Memory,
    Cpu,
    NonEmpty,
}

/// Trait for types that can provide property metadata and get/set operations.
pub trait PropertyRegistry {
    /// Direct properties of this struct (not from nested structs)
    const PROPERTIES: &'static [PropertyMetadata];

    /// Get a property value by its field name (not prefixed path)
    fn get_property(&self, field_name: &str) -> Option<String>;

    /// Set a property value by its field name (not prefixed path)
    fn set_property(&mut self, field_name: &str, value: String) -> Result<()>;

    /// Unset a property value by its field name (not prefixed path)
    fn unset_property(&mut self, field_name: &str) -> Result<()>;
}

/// Macro to implement PropertyRegistry for a struct.
///
/// This eliminates the need for manual match statements and hardcoded property strings.
macro_rules! impl_property_registry {
    (
        $struct_name:ident {
            $(
                $field:ident: Option<String> => {
                    path: $path:literal,
                    property_type: $prop_type:expr,
                    description: $desc:literal,
                    validator: $validator:expr,
                }
            ),* $(,)?
        }
    ) => {
        impl PropertyRegistry for $struct_name {
            const PROPERTIES: &'static [PropertyMetadata] = &[
                $(
                    PropertyMetadata {
                        path: $path,
                        property_type: $prop_type,
                        description: $desc,
                        validator: $validator,
                    },
                )*
            ];

            fn get_property(&self, field_name: &str) -> Option<String> {
                match field_name {
                    $(
                        $path => self.$field.clone(),
                    )*
                    _ => None,
                }
            }

            fn set_property(&mut self, field_name: &str, value: String) -> Result<()> {
                // Find metadata to validate
                let metadata = Self::PROPERTIES
                    .iter()
                    .find(|m| m.path == field_name)
                    .ok_or_else(|| Error::unknown_property(field_name))?;

                // Validate the value
                let validated = validate_property_value(&metadata.validator, &value)?;

                match field_name {
                    $(
                        $path => {
                            self.$field = Some(validated);
                        }
                    )*
                    _ => return Err(Error::unknown_property(field_name)),
                }

                Ok(())
            }

            fn unset_property(&mut self, field_name: &str) -> Result<()> {
                match field_name {
                    $(
                        $path => {
                            self.$field = None;
                        }
                    )*
                    _ => return Err(Error::unknown_property(field_name)),
                }

                Ok(())
            }
        }
    };

    // Variant for Option<bool> fields
    (
        $struct_name:ident {
            $(
                $field:ident: Option<bool> => {
                    path: $path:literal,
                    property_type: $prop_type:expr,
                    description: $desc:literal,
                    validator: $validator:expr,
                }
            ),* $(,)?
        }
    ) => {
        impl PropertyRegistry for $struct_name {
            const PROPERTIES: &'static [PropertyMetadata] = &[
                $(
                    PropertyMetadata {
                        path: $path,
                        property_type: $prop_type,
                        description: $desc,
                        validator: $validator,
                    },
                )*
            ];

            fn get_property(&self, field_name: &str) -> Option<String> {
                match field_name {
                    $(
                        $path => self.$field.map(|b| b.to_string()),
                    )*
                    _ => None,
                }
            }

            fn set_property(&mut self, field_name: &str, value: String) -> Result<()> {
                // Find metadata to validate
                let metadata = Self::PROPERTIES
                    .iter()
                    .find(|m| m.path == field_name)
                    .ok_or_else(|| Error::unknown_property(field_name))?;

                // Validate the value
                let validated = validate_property_value(&metadata.validator, &value)?;

                match field_name {
                    $(
                        $path => {
                            self.$field = Some(validated == "true");
                        }
                    )*
                    _ => return Err(Error::unknown_property(field_name)),
                }

                Ok(())
            }

            fn unset_property(&mut self, field_name: &str) -> Result<()> {
                match field_name {
                    $(
                        $path => {
                            self.$field = None;
                        }
                    )*
                    _ => return Err(Error::unknown_property(field_name)),
                }

                Ok(())
            }
        }
    };

    // Variant for mixed String and bool fields
    (
        @mixed $struct_name:ident {
            $(
                $string_field:ident: Option<String> => {
                    path: $string_path:literal,
                    property_type: $string_prop_type:expr,
                    description: $string_desc:literal,
                    validator: $string_validator:expr,
                }
            ),*
            ---
            $(
                $bool_field:ident: Option<bool> => {
                    path: $bool_path:literal,
                    property_type: $bool_prop_type:expr,
                    description: $bool_desc:literal,
                    validator: $bool_validator:expr,
                }
            ),*
        }
    ) => {
        impl PropertyRegistry for $struct_name {
            const PROPERTIES: &'static [PropertyMetadata] = &[
                $(
                    PropertyMetadata {
                        path: $string_path,
                        property_type: $string_prop_type,
                        description: $string_desc,
                        validator: $string_validator,
                    },
                )*
                $(
                    PropertyMetadata {
                        path: $bool_path,
                        property_type: $bool_prop_type,
                        description: $bool_desc,
                        validator: $bool_validator,
                    },
                )*
            ];

            fn get_property(&self, field_name: &str) -> Option<String> {
                match field_name {
                    $(
                        $string_path => self.$string_field.clone(),
                    )*
                    $(
                        $bool_path => self.$bool_field.map(|b| b.to_string()),
                    )*
                    _ => None,
                }
            }

            fn set_property(&mut self, field_name: &str, value: String) -> Result<()> {
                // Find metadata to validate
                let metadata = Self::PROPERTIES
                    .iter()
                    .find(|m| m.path == field_name)
                    .ok_or_else(|| Error::unknown_property(field_name))?;

                // Validate the value
                let validated = validate_property_value(&metadata.validator, &value)?;

                match field_name {
                    $(
                        $string_path => {
                            self.$string_field = Some(validated);
                        }
                    )*
                    $(
                        $bool_path => {
                            self.$bool_field = Some(validated == "true");
                        }
                    )*
                    _ => return Err(Error::unknown_property(field_name)),
                }

                Ok(())
            }

            fn unset_property(&mut self, field_name: &str) -> Result<()> {
                match field_name {
                    $(
                        $string_path => {
                            self.$string_field = None;
                        }
                    )*
                    $(
                        $bool_path => {
                            self.$bool_field = None;
                        }
                    )*
                    _ => return Err(Error::unknown_property(field_name)),
                }

                Ok(())
            }
        }
    };
}

/// Validates a property value according to the specified validator.
fn validate_property_value(validator: &PropertyValidator, value: &str) -> Result<String> {
    match validator {
        PropertyValidator::None => Ok(value.to_string()),

        PropertyValidator::Url => {
            if !value.starts_with("http://") && !value.starts_with("https://") {
                return Err(Error::new("URL must start with http:// or https://"));
            }
            Ok(value.to_string())
        }

        PropertyValidator::Enum(allowed) => {
            if !allowed.contains(&value) {
                return Err(Error::invalid_value(
                    "enum".to_string(),
                    format!("Value must be one of: {}", allowed.join(", ")),
                ));
            }
            Ok(value.to_string())
        }

        PropertyValidator::Memory => normalize_memory_value(value),

        PropertyValidator::Cpu => {
            if value.parse::<f64>().is_err() {
                return Err(Error::new(
                    "CPU value must be a number (e.g., '2' or '0.5')",
                ));
            }
            Ok(value.to_string())
        }

        PropertyValidator::NonEmpty => {
            if value.is_empty() {
                return Err(Error::new("Value cannot be empty"));
            }
            Ok(value.to_string())
        }
    }
}

/// Normalizes memory values to Docker format.
fn normalize_memory_value(value: &str) -> Result<String> {
    let value_lower = value.to_lowercase();

    if value_lower.ends_with('k') || value_lower.ends_with('m') || value_lower.ends_with('g') {
        let num_part = &value_lower[..value_lower.len() - 1];
        if num_part.parse::<u64>().is_err() {
            return Err(Error::new(
                "Memory value must be a number followed by k, m, or g (e.g., '512m', '4g')",
            ));
        }
        Ok(value.to_string())
    } else {
        if value.parse::<u64>().is_err() {
            return Err(Error::new(
                "Memory value must be a number or a number with unit (e.g., '512' or '512m')",
            ));
        }
        Ok(format!("{}m", value))
    }
}

/// Agent configuration settings.
///
/// This structure holds all agent-related configuration options.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AgentConfig {
    /// Agent binary URL for precompiled agent.
    ///
    /// If set, the agent will be downloaded from this URL instead of being compiled.
    /// The URL should point to a precompiled devcon-agent binary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary_url: Option<String>,

    /// Git repository URL for agent source code.
    ///
    /// If set (and binary_url is not set), the agent will be compiled from this repository.
    /// Defaults to "https://github.com/kreemer/devcon.git" if not specified.
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
}

impl_property_registry! {
    @mixed AgentConfig {
        binary_url: Option<String> => {
            path: "binaryUrl",
            property_type: PropertyType::String,
            description: "URL to precompiled agent binary",
            validator: PropertyValidator::Url,
        },
        git_repository: Option<String> => {
            path: "gitRepository",
            property_type: PropertyType::String,
            description: "Git repository URL for building agent from source",
            validator: PropertyValidator::Url,
        },
        git_branch: Option<String> => {
            path: "gitBranch",
            property_type: PropertyType::String,
            description: "Git branch for agent source (default: main)",
            validator: PropertyValidator::None,
        }
        ---
        disable: Option<bool> => {
            path: "disable",
            property_type: PropertyType::Boolean,
            description: "Disable agent installation in containers",
            validator: PropertyValidator::None,
        }
    }
}

/// Docker runtime-specific configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DockerRuntimeConfig {}

/// Apple runtime-specific configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppleRuntimeConfig {
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
}

impl Default for AppleRuntimeConfig {
    fn default() -> Self {
        Self {
            build_memory: Some("4g".to_string()),
            build_cpu: None,
        }
    }
}

impl_property_registry! {
    AppleRuntimeConfig {
        build_memory: Option<String> => {
            path: "buildMemory",
            property_type: PropertyType::String,
            description: "Memory limit for Apple builds (default: 4g)",
            validator: PropertyValidator::Memory,
        },
        build_cpu: Option<String> => {
            path: "buildCpu",
            property_type: PropertyType::String,
            description: "CPU limit for Apple builds (e.g., 2, 0.5)",
            validator: PropertyValidator::Cpu,
        },
    }
}

/// Runtime-specific configuration settings.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeConfig {
    /// Docker runtime configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub docker: Option<DockerRuntimeConfig>,

    /// Apple runtime configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub apple: Option<AppleRuntimeConfig>,
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

impl_property_registry! {
    @mixed AgentForwardingConfig {
        ssh_socket_path: Option<String> => {
            path: "sshSocketPath",
            property_type: PropertyType::String,
            description: "Override SSH agent socket path (auto-detected if unset)",
            validator: PropertyValidator::None,
        },
        gpg_socket_path: Option<String> => {
            path: "gpgSocketPath",
            property_type: PropertyType::String,
            description: "Override GPG agent socket path (auto-detected if unset)",
            validator: PropertyValidator::None,
        },
        gh_config_path: Option<String> => {
            path: "ghConfigPath",
            property_type: PropertyType::String,
            description: "Override GitHub CLI config directory path (auto-detected if unset)",
            validator: PropertyValidator::None,
        }
        ---
        ssh_enabled: Option<bool> => {
            path: "sshEnabled",
            property_type: PropertyType::Boolean,
            description: "Enable SSH agent forwarding into containers",
            validator: PropertyValidator::None,
        },
        gpg_enabled: Option<bool> => {
            path: "gpgEnabled",
            property_type: PropertyType::Boolean,
            description: "Enable GPG agent forwarding into containers",
            validator: PropertyValidator::None,
        },
        gh_enabled: Option<bool> => {
            path: "ghEnabled",
            property_type: PropertyType::Boolean,
            description: "Enable GitHub CLI authentication forwarding into containers",
            validator: PropertyValidator::None,
        }
    }
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
    /// Valid values: "auto", "docker", "apple"
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
    /// Contains runtime-specific options for Docker and Apple container runtimes.
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
    /// Loads the configuration from the XDG config directory.
    ///
    /// This method looks for the config file at:
    /// - `$XDG_CONFIG_HOME/devcon/config.yaml` (if XDG_CONFIG_HOME is set)
    /// - `~/.config/devcon/config.yaml` (default on Linux/macOS)
    /// - `%APPDATA%/devcon/config.yaml` (on Windows)
    ///
    /// If no config file exists, returns a default empty configuration.
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
    /// let config = Config::load()?;
    /// if let Some(dotfiles) = &config.dotfiles_repository {
    ///     println!("Dotfiles repo: {}", dotfiles);
    /// }
    /// # Ok::<(), devcon::error::Error>(())
    /// ```
    pub fn load() -> Result<Self> {
        let config_path = Self::get_config_path()?;

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
                See 'devcon config list' for available properties.",
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

    /// Saves the configuration to the XDG config directory.
    ///
    /// This method creates the config directory if it doesn't exist,
    /// then writes the configuration in YAML format.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The config directory cannot be created
    /// - The config file cannot be written
    /// - The configuration cannot be serialized to YAML
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use devcon::config::Config;
    /// let mut config = Config::default();
    /// config.dotfiles_repository = Some("https://github.com/user/dotfiles".to_string());
    /// config.save()?;
    /// # Ok::<(), devcon::error::Error>(())
    /// ```
    pub fn save(&self) -> Result<()> {
        let config_path = Self::get_config_path()?;

        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                Error::config(format!(
                    "Failed to create config directory: {}: {}",
                    parent.display(),
                    e
                ))
            })?;
        }

        let yaml = yaml_serde::to_string(self).map_err(|e| {
            Error::config(format!("Failed to serialize configuration to YAML: {}", e))
        })?;

        fs::write(&config_path, yaml).map_err(|e| {
            Error::config(format!(
                "Failed to write config file: {}: {}",
                config_path.display(),
                e
            ))
        })?;

        Ok(())
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
    /// Checks for Docker and Apple's container CLI in order.
    /// Returns "docker" if docker is available, "apple" if container is available,
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

        // Check for Apple container CLI
        if Command::new("container")
            .arg("--version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
        {
            return Ok("apple".to_string());
        }

        Err(Error::runtime(
            "No container runtime found. Please install Docker or Apple's container CLI.",
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

    /// Gets the runtime config, using defaults if not configured.
    pub fn get_runtime_config(&self) -> RuntimeConfig {
        self.runtime_config.clone().unwrap_or_default()
    }

    /// Gets the value of a configuration property by path.
    ///
    /// Uses camelCase dot-notation (e.g., "agents.binaryUrl").
    pub fn get_value(&self, property: &str) -> Option<String> {
        // Handle direct Config properties
        match property {
            "dotfilesRepository" => return self.dotfiles_repository.clone(),
            "dotfilesInstallCommand" => return self.dotfiles_install_command.clone(),
            "defaultShell" => return self.default_shell.clone(),
            "buildPath" => return self.build_path.clone(),
            "runtime" => return Some(self.runtime.clone()),
            _ => {}
        }

        // Handle nested agents properties
        if let Some(rest) = property.strip_prefix("agents.") {
            return self.agents.as_ref()?.get_property(rest);
        }

        // Handle nested runtimeConfig.apple properties
        if let Some(rest) = property.strip_prefix("runtimeConfig.apple.") {
            return self
                .runtime_config
                .as_ref()?
                .apple
                .as_ref()?
                .get_property(rest);
        }

        // Handle nested agentForwarding properties
        if let Some(rest) = property.strip_prefix("agentForwarding.") {
            return self.agent_forwarding.as_ref()?.get_property(rest);
        }

        None
    }

    /// Sets the value of a configuration property by path.
    ///
    /// Uses camelCase dot-notation (e.g., "agents.binaryUrl").
    /// Auto-creates parent structures as needed.
    /// Values are validated and normalized before being set.
    pub fn set_value(&mut self, property: &str, value: String) -> Result<()> {
        // Handle direct Config properties
        match property {
            "dotfilesRepository" => {
                let validated = validate_property_value(&PropertyValidator::Url, &value)?;
                self.dotfiles_repository = Some(validated);
                return Ok(());
            }
            "dotfilesInstallCommand" => {
                self.dotfiles_install_command = Some(value);
                return Ok(());
            }
            "defaultShell" => {
                self.default_shell = Some(value);
                return Ok(());
            }
            "buildPath" => {
                let validated = validate_property_value(&PropertyValidator::NonEmpty, &value)?;
                self.build_path = Some(validated);
                return Ok(());
            }
            "runtime" => {
                let validated = validate_property_value(
                    &PropertyValidator::Enum(&["auto", "docker", "apple"]),
                    &value,
                )?;
                self.runtime = validated;
                return Ok(());
            }
            _ => {}
        }

        // Handle nested agents properties
        if let Some(rest) = property.strip_prefix("agents.") {
            let agents = self.agents.get_or_insert_with(Default::default);
            return agents.set_property(rest, value);
        }

        // Handle nested runtimeConfig.apple properties
        if let Some(rest) = property.strip_prefix("runtimeConfig.apple.") {
            let runtime_config = self.runtime_config.get_or_insert_with(Default::default);
            let apple = runtime_config.apple.get_or_insert_with(Default::default);
            return apple.set_property(rest, value);
        }

        // Handle nested agentForwarding properties
        if let Some(rest) = property.strip_prefix("agentForwarding.") {
            let agent_forwarding = self.agent_forwarding.get_or_insert_with(Default::default);
            return agent_forwarding.set_property(rest, value);
        }

        Err(Error::unknown_property(property))
    }

    /// Unsets (removes) the value of a configuration property by path.
    ///
    /// Uses camelCase dot-notation (e.g., "agents.binaryUrl").
    pub fn unset_value(&mut self, property: &str) -> Result<()> {
        // Handle direct Config properties
        match property {
            "dotfilesRepository" => {
                self.dotfiles_repository = None;
                return Ok(());
            }
            "dotfilesInstallCommand" => {
                self.dotfiles_install_command = None;
                return Ok(());
            }
            "defaultShell" => {
                self.default_shell = None;
                return Ok(());
            }
            "buildPath" => {
                self.build_path = None;
                return Ok(());
            }
            "runtime" => {
                self.runtime = "auto".to_string();
                return Ok(());
            }
            _ => {}
        }

        // Handle nested agents properties
        if let Some(rest) = property.strip_prefix("agents.") {
            if let Some(agents) = self.agents.as_mut() {
                return agents.unset_property(rest);
            }
            return Ok(());
        }

        // Handle nested runtimeConfig.apple properties
        if let Some(rest) = property.strip_prefix("runtimeConfig.apple.")
            && let Some(runtime_config) = self.runtime_config.as_mut()
        {
            if let Some(apple) = runtime_config.apple.as_mut() {
                return apple.unset_property(rest);
            }
            return Ok(());
        }

        // Handle nested agentForwarding properties
        if let Some(rest) = property.strip_prefix("agentForwarding.") {
            if let Some(agent_forwarding) = self.agent_forwarding.as_mut() {
                return agent_forwarding.unset_property(rest);
            }
            return Ok(());
        }

        Err(Error::unknown_property(property))
    }

    /// Lists all available configuration properties.
    ///
    /// Returns a vector of tuples: (property_path, type, description).
    /// Can be filtered by a substring match on the property path.
    pub fn list_properties(filter: Option<&str>) -> Vec<(String, String, String)> {
        let mut all_properties = vec![
            // Direct Config properties
            (
                "dotfilesRepository".to_string(),
                "string".to_string(),
                "URL to dotfiles repository to clone into containers".to_string(),
            ),
            (
                "dotfilesInstallCommand".to_string(),
                "string".to_string(),
                "Custom install command for dotfiles (auto-detected if unset)".to_string(),
            ),
            (
                "defaultShell".to_string(),
                "string".to_string(),
                "Default shell for shell command (e.g., /bin/zsh)".to_string(),
            ),
            (
                "buildPath".to_string(),
                "string".to_string(),
                "Default build path for container builds".to_string(),
            ),
            (
                "runtime".to_string(),
                "string".to_string(),
                "Container runtime: auto, docker, or apple (default: auto)".to_string(),
            ),
        ];

        // Add agents properties with prefix
        for meta in AgentConfig::PROPERTIES {
            all_properties.push((
                format!("agents.{}", meta.path),
                match meta.property_type {
                    PropertyType::String => "string".to_string(),
                    PropertyType::Boolean => "boolean".to_string(),
                },
                meta.description.to_string(),
            ));
        }

        // Add runtimeConfig.apple properties with prefix
        for meta in AppleRuntimeConfig::PROPERTIES {
            all_properties.push((
                format!("runtimeConfig.apple.{}", meta.path),
                match meta.property_type {
                    PropertyType::String => "string".to_string(),
                    PropertyType::Boolean => "boolean".to_string(),
                },
                meta.description.to_string(),
            ));
        }

        // Add agentForwarding properties with prefix
        for meta in AgentForwardingConfig::PROPERTIES {
            all_properties.push((
                format!("agentForwarding.{}", meta.path),
                match meta.property_type {
                    PropertyType::String => "string".to_string(),
                    PropertyType::Boolean => "boolean".to_string(),
                },
                meta.description.to_string(),
            ));
        }

        if let Some(filter_str) = filter {
            all_properties
                .into_iter()
                .filter(|(path, _, _)| path.contains(filter_str))
                .collect()
        } else {
            all_properties
        }
    }

    /// Validates the entire configuration.
    ///
    /// Returns an error if any configuration values are invalid.
    pub fn validate(&self) -> Result<()> {
        // Validate URLs
        if let Some(url) = &self.dotfiles_repository {
            validate_property_value(&PropertyValidator::Url, url)?;
        }
        if let Some(url) = self.get_agent_binary_url() {
            validate_property_value(&PropertyValidator::Url, url)?;
        }
        if let Some(url) = self.get_agent_git_repository() {
            validate_property_value(&PropertyValidator::Url, url)?;
        }

        // Validate runtime
        validate_property_value(
            &PropertyValidator::Enum(&["auto", "docker", "apple"]),
            &self.runtime,
        )?;

        // Validate runtime config
        if let Some(rc) = &self.runtime_config
            && let Some(apple) = &rc.apple
        {
            if let Some(mem) = &apple.build_memory {
                validate_property_value(&PropertyValidator::Memory, mem)?;
            }
            if let Some(cpu) = &apple.build_cpu {
                validate_property_value(&PropertyValidator::Cpu, cpu)?;
            }
        }

        Ok(())
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
}
