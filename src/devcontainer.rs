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

//! # Devcontainer Configuration
//!
//! This module provides types and functionality for parsing and working with
//! devcontainer.json configuration files.
//!
//! ## Overview
//!
//! The devcontainer specification defines how to configure development containers
//! with specific tools, runtime environments, and features. This module implements
//! parsing and deserialization of these configurations.
//!
//! ## Main Types
//!
//! - [`Devcontainer`] - The main configuration structure
//!
//! ## Examples
//!
//! ```no_run
//! use std::path::PathBuf;
//! use devcon::devcontainer::Devcontainer;
//!
//! let config = Devcontainer::try_from(PathBuf::from("/path/to/project"))?;
//! println!("Container name: {}", config.name.as_deref().unwrap_or("default"));
//! # Ok::<(), devcon::error::Error>(())
//! ```

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use crate::error::{Error, Result};
use serde::Deserialize;
use serde::de;
use serde_json::Value;

/// Represents a lifecycle command that can be a string, array, or object.
///
/// The devcontainer spec supports multiple formats for lifecycle commands:
/// - String: A single command to execute
/// - Array: Multiple commands to execute in sequence
/// - Object: Named commands with their execution strings
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum LifecycleCommand {
    /// Single command as a string
    String(String),
    /// Multiple commands as an array
    Array(Vec<String>),
    /// Named commands as an object
    Object(HashMap<String, LifecycleCommandValue>),
}

/// Represents a value in a lifecycle command object that can be a string or array
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum LifecycleCommandValue {
    String(String),
    Array(Vec<String>),
}

impl LifecycleCommandValue {
    /// Convert to a shell command string
    pub fn to_command_string(&self) -> String {
        match self {
            LifecycleCommandValue::String(s) => s.clone(),
            LifecycleCommandValue::Array(arr) => arr.join(" && "),
        }
    }
}

/// Represents a port forwarding configuration
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum ForwardPort {
    /// Simple port number
    Port(u16),
    /// Host:port format
    HostPort(String),
}

impl std::fmt::Display for ForwardPort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ForwardPort::Port(port) => write!(f, "{}", port),
            ForwardPort::HostPort(mapping) => write!(f, "{}", mapping),
        }
    }
}

/// Port attributes for forwarded ports
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct PortAttributes {
    pub on_auto_forward: Option<OnAutoForward>,
    pub elevate_if_needed: Option<bool>,
    pub label: Option<String>,
    pub require_local_port: Option<bool>,
    pub protocol: Option<PortProtocol>,
}

/// Action to take when a port is auto-forwarded
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum OnAutoForward {
    Notify,
    OpenBrowser,
    OpenBrowserOnce,
    OpenPreview,
    Silent,
    Ignore,
}

/// Protocol for port forwarding
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PortProtocol {
    Http,
    Https,
}

/// Mount configuration
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Mount {
    /// String format for mount
    String(String),
    /// Structured mount
    Structured(StructuredMount),
}

/// Structured mount configuration
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StructuredMount {
    #[serde(rename = "type")]
    pub mount_type: MountType,
    pub source: Option<String>,
    pub target: String,
}

/// Type of mount
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MountType {
    Bind,
    Volume,
}

/// Build configuration for Dockerfile-based containers
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct BuildConfig {
    pub dockerfile: Option<String>,
    pub context: Option<String>,
    pub target: Option<String>,
    pub args: Option<HashMap<String, String>>,
    pub cache_from: Option<CacheFrom>,
    pub options: Option<Vec<String>>,
}

/// Cache from configuration
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
#[allow(dead_code)]
pub enum CacheFrom {
    Single(String),
    Multiple(Vec<String>),
}

/// Docker Compose configuration
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct ComposeConfig {
    pub docker_compose_file: ComposeFile,
    pub service: String,
    pub run_services: Option<Vec<String>>,
}

/// Docker Compose file reference
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
#[allow(dead_code)]
pub enum ComposeFile {
    Single(String),
    Multiple(Vec<String>),
}

/// Application port configuration
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
#[allow(dead_code)]
pub enum AppPort {
    Single(AppPortValue),
    Multiple(Vec<AppPortValue>),
}

/// Individual app port value
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
#[allow(dead_code)]
pub enum AppPortValue {
    Port(u16),
    Mapping(String),
}

/// Shutdown action when disconnecting
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ShutdownAction {
    None,
    StopContainer,
    StopCompose,
}

/// User environment probe setting
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum UserEnvProbe {
    None,
    LoginShell,
    LoginInteractiveShell,
    InteractiveShell,
}

/// Wait for command setting
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum WaitFor {
    #[serde(rename = "initializeCommand")]
    Initialize,

    #[serde(rename = "onCreateCommand")]
    OnCreate,

    #[serde(rename = "updateContentCommand")]
    UpdateContent,

    #[serde(rename = "postCreateCommand")]
    PostCreate,

    #[serde(rename = "postStartCommand")]
    PostStart,
}

/// Host requirements
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct HostRequirements {
    pub cpus: Option<u32>,
    pub memory: Option<String>,
    pub storage: Option<String>,
    pub gpu: Option<GpuRequirement>,
}

/// GPU requirement
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
#[allow(dead_code)]
pub enum GpuRequirement {
    Boolean(bool),
    Optional(String), // "optional"
    Detailed(DetailedGpuRequirement),
}

/// Detailed GPU requirements
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct DetailedGpuRequirement {
    pub cores: Option<u32>,
    pub memory: Option<String>,
}

/// Represents a devcontainer.json configuration.
///
/// This structure contains all the necessary information to build and run
/// a development container, including the base image, features, and user settings.
///
/// # Fields
///
/// ## General Properties
/// * `name` - Optional name for the container (defaults to directory name if not set)
/// * `features` - List of features to install in the container
/// * `override_feature_install_order` - Custom order for feature installation
/// * `forward_ports` - Ports to forward from container to host
/// * `ports_attributes` - Attributes for specific ports or port ranges
/// * `other_ports_attributes` - Default attributes for unspecified ports
///
/// ## Image/Build Configuration
/// * `image` - The Docker base image to use
/// * `build` - Build configuration for Dockerfile-based containers
/// * `dockerfile` - Path to Dockerfile (deprecated, use build.dockerfile)
/// * `context` - Build context path (deprecated, use build.context)
///
/// ## Docker Compose Configuration
/// * `docker_compose_file` - Docker Compose file(s) to use
/// * `service` - Service name in docker-compose.yml
/// * `run_services` - Services to start
///
/// ## Container Configuration
/// * `workspace_folder` - Path to workspace inside container
/// * `workspace_mount` - Custom workspace mount configuration
/// * `mounts` - Additional mount points
/// * `run_args` - Additional arguments for docker run
/// * `app_port` - Application ports to expose
/// * `override_command` - Whether to override the default command
/// * `shutdown_action` - Action when disconnecting from container
///
/// ## User Configuration
/// * `remote_user` - User for spawning processes in container
/// * `container_user` - User the container starts with
/// * `update_remote_user_uid` - Whether to update user UID/GID on Linux
///
/// ## Environment
/// * `container_env` - Environment variables for the container
/// * `remote_env` - Environment variables for remote processes
///
/// ## Security and Capabilities
/// * `init` - Whether to use init process
/// * `privileged` - Run container in privileged mode
/// * `cap_add` - Linux capabilities to add
/// * `security_opt` - Security options
///
/// ## Lifecycle Commands
/// * `initialize_command` - Command to run before anything else (on host)
/// * `on_create_command` - Command to run when creating the container
/// * `update_content_command` - Command to run after updating content
/// * `post_create_command` - Command to run after creating the container
/// * `post_start_command` - Command to run after starting the container
/// * `post_attach_command` - Command to run after attaching to the container
/// * `wait_for` - Which lifecycle command to wait for
/// * `user_env_probe` - How to probe user environment
///
/// ## Advanced
/// * `host_requirements` - Minimum host hardware requirements
/// * `customizations` - Tool-specific customizations
/// * `additional_properties` - Other unspecified properties
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Devcontainer {
    // General properties
    pub name: Option<String>,
    pub features: Vec<FeatureRef>,
    pub override_feature_install_order: Option<Vec<String>>,
    pub forward_ports: Option<Vec<ForwardPort>>,
    pub ports_attributes: Option<HashMap<String, PortAttributes>>,
    pub other_ports_attributes: Option<PortAttributes>,

    // Image/Build configuration
    pub image: Option<String>,
    pub build: Option<BuildConfig>,
    #[deprecated(note = "Use build.dockerfile instead")]
    pub dockerfile: Option<String>,
    #[deprecated(note = "Use build.context instead")]
    pub context: Option<String>,

    // Docker Compose configuration
    pub docker_compose_file: Option<ComposeFile>,
    pub service: Option<String>,
    pub run_services: Option<Vec<String>>,

    // Container configuration
    pub workspace_folder: Option<String>,
    pub workspace_mount: Option<String>,
    pub mounts: Option<Vec<Mount>>,
    pub run_args: Option<Vec<String>>,
    pub app_port: Option<AppPort>,
    pub override_command: Option<bool>,
    pub shutdown_action: Option<ShutdownAction>,

    // User configuration
    pub remote_user: Option<String>,
    pub container_user: Option<String>,
    pub update_remote_user_uid: Option<bool>,

    // Environment
    pub container_env: Option<HashMap<String, String>>,
    pub remote_env: Option<HashMap<String, Option<String>>>,

    // Security and capabilities
    pub init: Option<bool>,
    pub privileged: Option<bool>,
    pub cap_add: Option<Vec<String>>,
    pub security_opt: Option<Vec<String>>,

    // Lifecycle commands
    pub initialize_command: Option<LifecycleCommand>,
    pub on_create_command: Option<LifecycleCommand>,
    pub update_content_command: Option<LifecycleCommand>,
    pub post_create_command: Option<LifecycleCommand>,
    pub post_start_command: Option<LifecycleCommand>,
    pub post_attach_command: Option<LifecycleCommand>,
    pub wait_for: Option<WaitFor>,
    pub user_env_probe: Option<UserEnvProbe>,

    // Advanced
    pub host_requirements: Option<HostRequirements>,
    pub customizations: Option<HashMap<String, Value>>,
    pub additional_properties: Option<HashMap<String, Value>>,
}

#[allow(deprecated)]
impl<'de> Deserialize<'de> for Devcontainer {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct DevcontainerHelper {
            // General properties
            name: Option<String>,
            #[serde(default)]
            #[serde(deserialize_with = "deserialize_features_map")]
            features: Vec<(String, serde_json::Value)>,
            override_feature_install_order: Option<Vec<String>>,
            forward_ports: Option<Vec<ForwardPort>>,
            ports_attributes: Option<HashMap<String, PortAttributes>>,
            other_ports_attributes: Option<PortAttributes>,

            // Image/Build configuration
            image: Option<String>,
            build: Option<BuildConfig>,
            #[serde(rename = "dockerFile")]
            dockerfile: Option<String>,
            context: Option<String>,

            // Docker Compose configuration
            docker_compose_file: Option<ComposeFile>,
            service: Option<String>,
            run_services: Option<Vec<String>>,

            // Container configuration
            workspace_folder: Option<String>,
            workspace_mount: Option<String>,
            mounts: Option<Vec<Mount>>,
            run_args: Option<Vec<String>>,
            app_port: Option<AppPort>,
            override_command: Option<bool>,
            shutdown_action: Option<ShutdownAction>,

            // User configuration
            remote_user: Option<String>,
            container_user: Option<String>,
            #[serde(rename = "updateRemoteUserUID")]
            update_remote_user_uid: Option<bool>,

            // Environment
            container_env: Option<HashMap<String, String>>,
            remote_env: Option<HashMap<String, Option<String>>>,

            // Security and capabilities
            init: Option<bool>,
            privileged: Option<bool>,
            cap_add: Option<Vec<String>>,
            security_opt: Option<Vec<String>>,

            // Lifecycle commands
            initialize_command: Option<LifecycleCommand>,
            on_create_command: Option<LifecycleCommand>,
            update_content_command: Option<LifecycleCommand>,
            post_create_command: Option<LifecycleCommand>,
            post_start_command: Option<LifecycleCommand>,
            post_attach_command: Option<LifecycleCommand>,
            wait_for: Option<WaitFor>,
            user_env_probe: Option<UserEnvProbe>,

            // Advanced
            host_requirements: Option<HostRequirements>,
            customizations: Option<HashMap<String, Value>>,

            // Catch-all for additional properties
            #[serde(flatten)]
            additional_properties: Option<HashMap<String, Value>>,
        }

        let helper = DevcontainerHelper::deserialize(deserializer)?;

        let features: std::result::Result<Vec<FeatureRef>, D::Error> = helper
            .features
            .into_iter()
            .map(|(url, options)| parse_feature(&url, options))
            .collect();

        Ok(Devcontainer {
            // General properties
            name: helper.name,
            features: features?,
            override_feature_install_order: helper.override_feature_install_order,
            forward_ports: helper.forward_ports,
            ports_attributes: helper.ports_attributes,
            other_ports_attributes: helper.other_ports_attributes,

            // Image/Build configuration
            image: helper.image,
            build: helper.build,
            dockerfile: helper.dockerfile,
            context: helper.context,

            // Docker Compose configuration
            docker_compose_file: helper.docker_compose_file,
            service: helper.service,
            run_services: helper.run_services,

            // Container configuration
            workspace_folder: helper.workspace_folder,
            workspace_mount: helper.workspace_mount,
            mounts: helper.mounts,
            run_args: helper.run_args,
            app_port: helper.app_port,
            override_command: helper.override_command,
            shutdown_action: helper.shutdown_action,

            // User configuration
            remote_user: helper.remote_user,
            container_user: helper.container_user,
            update_remote_user_uid: helper.update_remote_user_uid,

            // Environment
            container_env: helper.container_env,
            remote_env: helper.remote_env,

            // Security and capabilities
            init: helper.init,
            privileged: helper.privileged,
            cap_add: helper.cap_add,
            security_opt: helper.security_opt,

            // Lifecycle commands
            initialize_command: helper.initialize_command,
            on_create_command: helper.on_create_command,
            update_content_command: helper.update_content_command,
            post_create_command: helper.post_create_command,
            post_start_command: helper.post_start_command,
            post_attach_command: helper.post_attach_command,
            wait_for: helper.wait_for,
            user_env_probe: helper.user_env_probe,

            // Advanced
            host_requirements: helper.host_requirements,
            customizations: helper.customizations,
            additional_properties: helper.additional_properties,
        })
    }
}

fn deserialize_features_map<'de, D>(
    deserializer: D,
) -> std::result::Result<Vec<(String, serde_json::Value)>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct FeaturesVisitor;

    impl<'de> serde::de::Visitor<'de> for FeaturesVisitor {
        type Value = Vec<(String, serde_json::Value)>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a map of features")
        }

        fn visit_map<M>(self, mut map: M) -> std::result::Result<Self::Value, M::Error>
        where
            M: serde::de::MapAccess<'de>,
        {
            let mut features = Vec::new();
            while let Some((key, value)) = map.next_entry()? {
                features.push((key, value));
            }
            Ok(features)
        }
    }

    deserializer.deserialize_map(FeaturesVisitor)
}

impl Devcontainer {
    /// Merges additional features from configuration into this devcontainer.
    ///
    /// This method adds features from the config that aren't already present
    /// in the devcontainer.json. Existing features take precedence.
    ///
    /// # Arguments
    ///
    /// * `additional_features` - HashMap of feature URLs to their options
    ///
    /// # Errors
    ///
    /// Returns an error if any additional feature cannot be parsed.
    pub fn merge_additional_features(
        &self,
        additional_features: &std::collections::HashMap<String, serde_json::Value>,
    ) -> Result<Vec<FeatureRef>> {
        // Get set of existing feature URLs
        let existing_urls: Vec<String> = self
            .features
            .iter()
            .map(|f| match &f.source {
                FeatureSource::Registry { registry, .. } => format!(
                    "ghcr.io/{}/{}/{}:{}",
                    registry.owner, registry.repository, registry.name, registry.version
                ),
                FeatureSource::Local { path } => path.to_string_lossy().to_string(),
            })
            .collect();

        let mut return_features = self.features.clone();
        // Add features that don't already exist
        for (url, options) in additional_features {
            if !existing_urls.contains(url) {
                let feature = parse_feature::<serde::de::value::Error>(url, options.clone())
                    .map_err(|e| {
                        Error::feature(format!("Failed to parse additional feature: {}", e))
                    })?;
                return_features.push(feature);
            }
        }

        Ok(return_features)
    }
}

impl TryFrom<PathBuf> for Devcontainer {
    type Error = Error;

    fn try_from(path: PathBuf) -> std::result::Result<Self, Self::Error> {
        // Check locations in order of precedence per devcontainer spec:
        // 1. .devcontainer/devcontainer.json
        // 2. .devcontainer.json
        // 3. .devcontainer/<folder>/devcontainer.json (one level deep)

        let primary_paths = vec![
            path.join(".devcontainer").join("devcontainer.json"),
            path.join("devcontainer.json"),
        ];

        // Find the first existing path from primary locations
        let mut final_path = None;
        for p in primary_paths {
            if fs::exists(&p).unwrap_or(false) {
                final_path = Some(p);
                break;
            }
        }

        // If not found in primary locations, check .devcontainer subfolders (one level deep)
        if final_path.is_none() {
            let devcontainer_dir = path.join(".devcontainer");
            if let Ok(entries) = fs::read_dir(&devcontainer_dir) {
                for entry in entries.flatten() {
                    if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                        let candidate = entry.path().join("devcontainer.json");
                        if fs::exists(&candidate).unwrap_or(false) {
                            final_path = Some(candidate);
                            break;
                        }
                    }
                }
            }
        }

        let final_path = final_path.ok_or_else(|| {
            Error::devcontainer(format!(
                "Devcontainer definition not found in any standard location under {}",
                path.to_string_lossy()
            ))
        })?;

        let file_result = fs::read_to_string(&final_path);

        if file_result.is_err() {
            return Err(Error::devcontainer(format!(
                "Devcontainer definition cannot be read {}",
                &final_path.to_string_lossy()
            )));
        }

        let result = Self::try_from(file_result.unwrap());
        if result.is_err() {
            return Err(Error::devcontainer(
                "Devcontainer content could not be parsed",
            ));
        }

        // Fix name of container if not present
        let mut result = result?;
        if result.name.is_none() {
            let name = fs::canonicalize(&path)?
                .file_name()
                .ok_or_else(|| Error::invalid_path(path.clone()))?
                .to_string_lossy()
                .to_string();
            result.name = Some(name);
        }

        Ok(result)
    }
}

impl TryFrom<String> for Devcontainer {
    type Error = serde_json::Error;

    fn try_from(content: String) -> std::result::Result<Self, Self::Error> {
        let mut data = content.clone();
        json_strip_comments::strip(&mut data).unwrap();

        serde_json::from_str(&data)
    }
}

/// Defines the source location of a feature.
#[derive(Debug, Clone)]
pub enum FeatureSource {
    Registry { registry: FeatureRegistry },
    Local { path: PathBuf },
}

/// Metadata for a feature stored in an OCI registry.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct FeatureRegistry {
    pub owner: String,
    pub repository: String,
    pub name: String,
    pub version: String,
    pub registry_type: FeatureRegistryType,
}

/// Type of OCI registry for features.
#[derive(Debug, Clone)]
pub enum FeatureRegistryType {
    Ghcr,
}

/// Represents a reference to a feature in devcontainer.json.
#[derive(Debug, Clone)]
pub struct FeatureRef {
    pub source: FeatureSource,
    pub options: serde_json::Value,
}

impl FeatureRef {
    pub fn new(source: FeatureSource) -> Self {
        Self {
            source,
            options: serde_json::json!({}),
        }
    }
}

/// Parses a feature URL string and options into a FeatureRef struct.
pub fn parse_feature<E: de::Error>(
    url: &str,
    user_options: serde_json::Value,
) -> std::result::Result<FeatureRef, E> {
    if !url.starts_with("ghcr.io") && url.contains(":") {
        return Err(de::Error::custom("Only ghcr.io features are supported"));
    }

    if url.starts_with("ghcr.io") {
        parse_registry_feature(url, user_options)
    } else {
        parse_local_feature(url, user_options)
    }
}

fn parse_local_feature<E: de::Error>(
    url: &str,
    user_options: serde_json::Value,
) -> std::result::Result<FeatureRef, E> {
    let path = PathBuf::from(url);
    Ok(FeatureRef {
        source: FeatureSource::Local { path },
        options: user_options,
    })
}

fn parse_registry_feature<E: de::Error>(
    url: &str,
    user_options: serde_json::Value,
) -> std::result::Result<FeatureRef, E> {
    let owner = url
        .split("/")
        .nth(1)
        .ok_or_else(|| de::Error::custom("Invalid feature URL, missing owner information"))?;
    let repository = url
        .split("/")
        .nth(2)
        .ok_or_else(|| de::Error::custom("Invalid feature URL, missing repository information"))?;
    let name = url
        .split("/")
        .nth(3)
        .and_then(|s| s.split(":").next())
        .ok_or_else(|| de::Error::custom("Invalid feature URL, missing name information"))?;

    let version = url
        .split("/")
        .nth(3)
        .and_then(|s| s.split(":").nth(1))
        .unwrap_or("latest");

    Ok(FeatureRef {
        source: FeatureSource::Registry {
            registry: FeatureRegistry {
                owner: owner.to_string(),
                repository: repository.to_string(),
                name: name.to_string(),
                version: version.to_string(),
                registry_type: FeatureRegistryType::Ghcr,
            },
        },
        options: user_options,
    })
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_feature() {
        let feature = FeatureRef {
            source: FeatureSource::Registry {
                registry: FeatureRegistry {
                    registry_type: FeatureRegistryType::Ghcr,
                    owner: "devcontainers".to_string(),
                    repository: "features".to_string(),
                    name: "github-cli".to_string(),
                    version: "1".to_string(),
                },
            },
            options: serde_json::Value::Null,
        };

        assert!(feature.options.is_null());
        match feature.source {
            FeatureSource::Registry { registry } => {
                match registry.registry_type {
                    FeatureRegistryType::Ghcr => {}
                }
                assert_eq!("devcontainers", registry.owner);
                assert_eq!("features", registry.repository);
                assert_eq!("github-cli", registry.name);
                assert_eq!("1", registry.version);
            }
            _ => unreachable!("Feature source should be Local"),
        }
    }

    #[test]
    fn test_feature_parsing() {
        let feature_json = r#"
        {
            "name": "test",
            "image": "ubuntu:20.04",
            "features": {
               "ghcr.io/devcontainers/features/github-cli:1": {}
            }
        }
        "#;

        let devcontainer: Devcontainer = serde_json::from_str(feature_json).unwrap();

        assert_eq!(devcontainer.name.as_deref(), Some("test"));
        assert_eq!(devcontainer.image.as_deref(), Some("ubuntu:20.04"));
        assert_eq!(devcontainer.features.len(), 1);
        let feature = &devcontainer.features[0];
        match &feature.source {
            FeatureSource::Registry { registry } => {
                match registry.registry_type {
                    FeatureRegistryType::Ghcr => {}
                }
                assert_eq!("devcontainers", registry.owner);
                assert_eq!("features", registry.repository);
                assert_eq!("github-cli", registry.name);
                assert_eq!("1", registry.version);
            }
            _ => unreachable!("Feature source should be Local"),
        }
    }

    #[test]
    fn test_multiple_feature_parsing() {
        let feature_json = r#"
        {
            "name": "test",
            "image": "ubuntu:20.04",
            "features": {
               "ghcr.io/devcontainers/features/github-cli:1": {},
               "ghcr.io/devcontainers/features/node:2": {}
            }
        }
        "#;

        let devcontainer: Devcontainer = serde_json::from_str(feature_json).unwrap();

        assert_eq!(devcontainer.name.as_deref(), Some("test"));
        assert_eq!(devcontainer.features.len(), 2);
        let feature = &devcontainer.features[0];
        match &feature.source {
            FeatureSource::Registry { registry } => {
                match registry.registry_type {
                    FeatureRegistryType::Ghcr => {}
                }
                assert_eq!("devcontainers", registry.owner);
                assert_eq!("features", registry.repository);
                assert_eq!("github-cli", registry.name);
                assert_eq!("1", registry.version);
            }
            _ => unreachable!("Feature source should be Local"),
        }
        let feature = &devcontainer.features[1];
        match &feature.source {
            FeatureSource::Registry { registry } => {
                match registry.registry_type {
                    FeatureRegistryType::Ghcr => {}
                }
                assert_eq!("devcontainers", registry.owner);
                assert_eq!("features", registry.repository);
                assert_eq!("node", registry.name);
                assert_eq!("2", registry.version);
            }
            _ => unreachable!("Feature source should be Local"),
        }
    }

    #[test]
    fn test_local_feature() {
        let feature_json = r#"
        {
            "name": "test",
            "image": "ubuntu:20.04",
            "features": {
               "./devfeatures/myfeature": {}
            }
        }
        "#;

        let devcontainer: Devcontainer = serde_json::from_str(feature_json).unwrap();

        assert_eq!(devcontainer.name.as_deref(), Some("test"));
        assert_eq!(devcontainer.features.len(), 1);
        let feature = &devcontainer.features[0];
        match &feature.source {
            FeatureSource::Local { path } => {
                assert_eq!(PathBuf::from("./devfeatures/myfeature"), *path);
            }
            _ => unreachable!("Feature source should be Local"),
        }
    }

    #[test]
    fn test_mixed_features() {
        let feature_json = r#"
        {
            "name": "test",
            "image": "ubuntu:20.04",
            "features": {
               "ghcr.io/devcontainers/features/github-cli:1": {},
               "./local-feature": {},
               "ghcr.io/devcontainers/features/node:2": {}
            }
        }
        "#;

        let devcontainer: Devcontainer = serde_json::from_str(feature_json).unwrap();

        assert_eq!(devcontainer.features.len(), 3);

        // First should be registry
        match &devcontainer.features[0].source {
            FeatureSource::Registry { registry, .. } => {
                assert_eq!("github-cli", registry.name);
            }
            _ => panic!("Expected Registry feature"),
        }

        // Second should be local
        match &devcontainer.features[1].source {
            FeatureSource::Local { path } => {
                assert_eq!(PathBuf::from("./local-feature"), *path);
            }
            _ => panic!("Expected Local feature"),
        }

        // Third should be registry
        match &devcontainer.features[2].source {
            FeatureSource::Registry { registry, .. } => {
                assert_eq!("node", registry.name);
            }
            _ => panic!("Expected Registry feature"),
        }
    }

    #[test]
    fn test_feature_with_options() {
        let feature_json = r#"
        {
            "name": "test",
            "image": "ubuntu:20.04",
            "features": {
               "ghcr.io/devcontainers/features/node:2": {
                   "version": "18",
                   "installYarnUsingApt": true
               }
            }
        }
        "#;

        let devcontainer: Devcontainer = serde_json::from_str(feature_json).unwrap();

        assert_eq!(devcontainer.features.len(), 1);
        let feature = &devcontainer.features[0];

        assert!(feature.options.is_object());
        assert_eq!(
            feature.options.get("version").and_then(|v| v.as_str()),
            Some("18")
        );
        assert_eq!(
            feature
                .options
                .get("installYarnUsingApt")
                .and_then(|v| v.as_bool()),
            Some(true)
        );
    }

    #[test]
    fn test_feature_without_version() {
        let feature_json = r#"
        {
            "name": "test",
            "image": "ubuntu:20.04",
            "features": {
               "ghcr.io/devcontainers/features/docker-in-docker": {}
            }
        }
        "#;

        let devcontainer: Devcontainer = serde_json::from_str(feature_json).unwrap();

        let feature = &devcontainer.features[0];
        match &feature.source {
            FeatureSource::Registry { registry, .. } => {
                assert_eq!("latest", registry.version);
            }
            _ => panic!("Expected Registry feature"),
        }
    }

    #[test]
    fn test_empty_features() {
        let feature_json = r#"
        {
            "name": "test",
            "image": "ubuntu:20.04",
            "features": {}
        }
        "#;

        let devcontainer: Devcontainer = serde_json::from_str(feature_json).unwrap();

        assert_eq!(devcontainer.features.len(), 0);
    }

    #[test]
    fn test_no_features_field() {
        let feature_json = r#"
        {
            "name": "test",
            "image": "ubuntu:20.04"
        }
        "#;

        let devcontainer: Devcontainer = serde_json::from_str(feature_json).unwrap();

        assert_eq!(devcontainer.features.len(), 0);
    }

    #[test]
    fn test_missing_name_field() {
        let feature_json = r#"
        {
            "image": "ubuntu:20.04",
            "features": {}
        }
        "#;

        let devcontainer: Devcontainer = serde_json::from_str(feature_json).unwrap();

        assert_eq!(devcontainer.name, None);
    }

    #[test]
    fn test_with_remote_user() {
        let feature_json = r#"
        {
            "name": "test",
            "image": "ubuntu:20.04",
            "remoteUser": "vscode"
        }
        "#;

        let devcontainer: Devcontainer = serde_json::from_str(feature_json).unwrap();

        assert_eq!(devcontainer.remote_user.as_deref(), Some("vscode"));
    }

    #[test]
    fn test_get_computed_name_with_name() {
        let feature_json = r#"
        {
            "name": "my-project",
            "image": "ubuntu:20.04"
        }
        "#;

        let devcontainer: Devcontainer = serde_json::from_str(feature_json).unwrap();

        assert_eq!(devcontainer.name, Some("my-project".to_string()));
    }

    #[test]
    fn test_invalid_feature_url_missing_owner() {
        let feature_json = r#"
        {
            "name": "test",
            "image": "ubuntu:20.04",
            "features": {
               "ghcr.io/invalid:1": {}
            }
        }
        "#;

        let result: std::result::Result<Devcontainer, _> = serde_json::from_str(feature_json);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_feature_url_missing_name() {
        let feature_json = r#"
        {
            "name": "test",
            "image": "ubuntu:20.04",
            "features": {
               "ghcr.io/devcontainers/features": {}
            }
        }
        "#;

        let result: std::result::Result<Devcontainer, _> = serde_json::from_str(feature_json);
        assert!(result.is_err());
    }

    #[test]
    fn test_dockerfile_build() {
        let feature_json = r#"
        {
            "name": "test",
            "build": {
                "dockerfile": "Dockerfile",
                "context": ".."
            }
        }
        "#;

        let devcontainer: Devcontainer = serde_json::from_str(feature_json).unwrap();
        assert!(devcontainer.build.is_some());
        let build = devcontainer.build.unwrap();
        assert_eq!(build.dockerfile.as_deref(), Some("Dockerfile"));
        assert_eq!(build.context.as_deref(), Some(".."));
    }

    #[test]
    fn test_try_from_string() {
        let content = r#"
        {
            "name": "test",
            "image": "ubuntu:20.04"
        }
        "#;

        let devcontainer = Devcontainer::try_from(content.to_string()).unwrap();
        assert_eq!(devcontainer.name.as_deref(), Some("test"));
        assert_eq!(devcontainer.image.as_deref(), Some("ubuntu:20.04"));
    }

    #[test]
    fn test_complex_feature_parsing() {
        let feature_json = r#"
        {
            "name": "complex-test",
            "image": "mcr.microsoft.com/devcontainers/base:ubuntu",
            "features": {
                "ghcr.io/devcontainers/features/common-utils:2": {
                    "installZsh": true,
                    "installOhMyZsh": true,
                    "username": "vscode"
                },
                "ghcr.io/devcontainers/features/git:1": {
                    "version": "latest",
                    "ppa": true
                },
                "./local-features/custom-tool": {
                    "enabled": true
                }
            },
            "remoteUser": "vscode"
        }
        "#;

        let devcontainer: Devcontainer = serde_json::from_str(feature_json).unwrap();

        assert_eq!(devcontainer.name.as_deref(), Some("complex-test"));
        assert_eq!(
            devcontainer.image.as_deref(),
            Some("mcr.microsoft.com/devcontainers/base:ubuntu")
        );
        assert_eq!(devcontainer.features.len(), 3);
        assert_eq!(devcontainer.remote_user.as_deref(), Some("vscode"));

        // Verify first feature
        match &devcontainer.features[0].source {
            FeatureSource::Registry { registry, .. } => {
                assert_eq!("common-utils", registry.name);
                assert_eq!("2", registry.version);
            }
            _ => panic!("Expected Registry feature"),
        }

        // Verify second feature
        match &devcontainer.features[1].source {
            FeatureSource::Registry { registry, .. } => {
                assert_eq!("git", registry.name);
                assert_eq!("1", registry.version);
            }
            _ => panic!("Expected Registry feature"),
        }

        // Verify third feature is local
        match &devcontainer.features[2].source {
            FeatureSource::Local { .. } => {}
            _ => panic!("Expected Local feature"),
        }
    }

    #[test]
    fn test_lifecycle_hook_string() {
        let json = r#"
        {
            "name": "test",
            "image": "ubuntu:20.04",
            "postCreateCommand": "npm install"
        }
        "#;

        let devcontainer: Devcontainer = serde_json::from_str(json).unwrap();
        assert!(devcontainer.post_create_command.is_some());

        let command = match devcontainer.post_create_command {
            Some(LifecycleCommand::String(cmd)) => cmd,
            _ => unreachable!("Expected String command"),
        };
        assert_eq!(command, "npm install");
    }

    #[test]
    fn test_lifecycle_hook_array() {
        let json = r#"
        {
            "name": "test",
            "image": "ubuntu:20.04",
            "postStartCommand": ["npm install", "npm run dev"]
        }
        "#;

        let devcontainer: Devcontainer = serde_json::from_str(json).unwrap();
        assert!(devcontainer.post_start_command.is_some());

        let commands = match devcontainer.post_start_command {
            Some(LifecycleCommand::Array(cmds)) => cmds,
            _ => unreachable!("Expected Array command"),
        };
        assert_eq!(commands.len(), 2);
        assert_eq!(commands[0], "npm install");
        assert_eq!(commands[1], "npm run dev");
    }

    #[test]
    fn test_lifecycle_hook_object() {
        let json = r#"
        {
            "name": "test",
            "image": "ubuntu:20.04",
            "onCreateCommand": {
                "install": "npm install",
                "build": "npm run build"
            }
        }
        "#;

        let devcontainer: Devcontainer = serde_json::from_str(json).unwrap();
        assert!(devcontainer.on_create_command.is_some());

        match devcontainer.on_create_command {
            Some(LifecycleCommand::Object(map)) => {
                assert_eq!(map.len(), 2);
                assert!(map.contains_key("install"));
                assert!(map.contains_key("build"));
            }
            _ => unreachable!("Expected Object command"),
        }
    }

    #[test]
    fn test_docker_compose_config() {
        let json = r#"
        {
            "name": "test",
            "dockerComposeFile": "docker-compose.yml",
            "service": "app",
            "workspaceFolder": "/workspace",
            "runServices": ["db", "cache"]
        }
        "#;

        let devcontainer: Devcontainer = serde_json::from_str(json).unwrap();
        assert!(devcontainer.docker_compose_file.is_some());
        assert_eq!(devcontainer.service.as_deref(), Some("app"));
        assert_eq!(devcontainer.workspace_folder.as_deref(), Some("/workspace"));
        assert_eq!(devcontainer.run_services.as_ref().map(|s| s.len()), Some(2));
    }

    #[test]
    fn test_port_forwarding() {
        let json = r#"
        {
            "name": "test",
            "image": "ubuntu:20.04",
            "forwardPorts": [3000, "8080:8080"],
            "portsAttributes": {
                "3000": {
                    "label": "Application",
                    "onAutoForward": "notify"
                }
            }
        }
        "#;

        let devcontainer: Devcontainer = serde_json::from_str(json).unwrap();
        assert!(devcontainer.forward_ports.is_some());
        let ports = devcontainer.forward_ports.unwrap();
        assert_eq!(ports.len(), 2);

        assert!(devcontainer.ports_attributes.is_some());
        let attrs = devcontainer.ports_attributes.unwrap();
        assert!(attrs.contains_key("3000"));
    }

    #[test]
    fn test_mounts() {
        let json = r#"
        {
            "name": "test",
            "image": "ubuntu:20.04",
            "mounts": [
                "source=/var/run/docker.sock,target=/var/run/docker.sock,type=bind",
                {
                    "type": "volume",
                    "source": "myvolume",
                    "target": "/data"
                }
            ]
        }
        "#;

        let devcontainer: Devcontainer = serde_json::from_str(json).unwrap();
        assert!(devcontainer.mounts.is_some());
        let mounts = devcontainer.mounts.unwrap();
        assert_eq!(mounts.len(), 2);
    }

    #[test]
    fn test_container_env() {
        let json = r#"
        {
            "name": "test",
            "image": "ubuntu:20.04",
            "containerEnv": {
                "MY_VAR": "value",
                "ANOTHER_VAR": "another_value"
            },
            "remoteEnv": {
                "PATH": "/usr/local/bin:${PATH}",
                "REMOVE_ME": null
            }
        }
        "#;

        let devcontainer: Devcontainer = serde_json::from_str(json).unwrap();
        assert!(devcontainer.container_env.is_some());
        let env = devcontainer.container_env.unwrap();
        assert_eq!(env.get("MY_VAR").map(|s| s.as_str()), Some("value"));

        assert!(devcontainer.remote_env.is_some());
        let remote_env = devcontainer.remote_env.unwrap();
        assert!(remote_env.contains_key("PATH"));
        assert_eq!(remote_env.get("REMOVE_ME"), Some(&None));
    }

    #[test]
    fn test_security_options() {
        let json = r#"
        {
            "name": "test",
            "image": "ubuntu:20.04",
            "init": true,
            "privileged": true,
            "capAdd": ["SYS_PTRACE"],
            "securityOpt": ["seccomp=unconfined"]
        }
        "#;

        let devcontainer: Devcontainer = serde_json::from_str(json).unwrap();
        assert_eq!(devcontainer.init, Some(true));
        assert_eq!(devcontainer.privileged, Some(true));
        assert!(devcontainer.cap_add.is_some());
        assert!(devcontainer.security_opt.is_some());
    }

    #[test]
    fn test_host_requirements() {
        let json = r#"
        {
            "name": "test",
            "image": "ubuntu:20.04",
            "hostRequirements": {
                "cpus": 4,
                "memory": "8gb",
                "storage": "32gb",
                "gpu": true
            }
        }
        "#;

        let devcontainer: Devcontainer = serde_json::from_str(json).unwrap();
        assert!(devcontainer.host_requirements.is_some());
        let reqs = devcontainer.host_requirements.unwrap();
        assert_eq!(reqs.cpus, Some(4));
        assert_eq!(reqs.memory.as_deref(), Some("8gb"));
        assert_eq!(reqs.storage.as_deref(), Some("32gb"));
        assert!(reqs.gpu.is_some());
    }

    #[test]
    fn test_customizations() {
        let json = r#"
        {
            "name": "test",
            "image": "ubuntu:20.04",
            "customizations": {
                "vscode": {
                    "extensions": ["ms-python.python"],
                    "settings": {
                        "python.linting.enabled": true
                    }
                }
            }
        }
        "#;

        let devcontainer: Devcontainer = serde_json::from_str(json).unwrap();
        assert!(devcontainer.customizations.is_some());
        let customizations = devcontainer.customizations.unwrap();
        assert!(customizations.contains_key("vscode"));
    }

    #[test]
    fn test_build_with_args() {
        let json = r#"
        {
            "name": "test",
            "build": {
                "dockerfile": "Dockerfile",
                "context": "..",
                "args": {
                    "VARIANT": "3.9",
                    "NODE_VERSION": "14"
                },
                "target": "development"
            }
        }
        "#;

        let devcontainer: Devcontainer = serde_json::from_str(json).unwrap();
        assert!(devcontainer.build.is_some());
        let build = devcontainer.build.unwrap();
        assert_eq!(build.target.as_deref(), Some("development"));
        assert!(build.args.is_some());
        let args = build.args.unwrap();
        assert_eq!(args.get("VARIANT").map(|s| s.as_str()), Some("3.9"));
    }

    #[test]
    fn test_override_command() {
        let json = r#"
        {
            "name": "test",
            "image": "ubuntu:20.04",
            "overrideCommand": false
        }
        "#;

        let devcontainer: Devcontainer = serde_json::from_str(json).unwrap();
        assert_eq!(devcontainer.override_command, Some(false));
    }

    #[test]
    fn test_shutdown_action() {
        let json = r#"
        {
            "name": "test",
            "image": "ubuntu:20.04",
            "shutdownAction": "stopContainer"
        }
        "#;

        let devcontainer: Devcontainer = serde_json::from_str(json).unwrap();
        assert!(devcontainer.shutdown_action.is_some());
    }

    #[test]
    fn test_user_env_probe() {
        let json = r#"
        {
            "name": "test",
            "image": "ubuntu:20.04",
            "userEnvProbe": "loginInteractiveShell"
        }
        "#;

        let devcontainer: Devcontainer = serde_json::from_str(json).unwrap();
        assert!(devcontainer.user_env_probe.is_some());
    }

    #[test]
    fn test_wait_for() {
        let json = r#"
        {
            "name": "test",
            "image": "ubuntu:20.04",
            "waitFor": "postCreateCommand"
        }
        "#;

        let devcontainer: Devcontainer = serde_json::from_str(json).unwrap();
        assert!(devcontainer.wait_for.is_some());
    }

    #[test]
    fn test_initialize_command() {
        let json = r#"
        {
            "name": "test",
            "image": "ubuntu:20.04",
            "initializeCommand": "echo Initializing"
        }
        "#;

        let devcontainer: Devcontainer = serde_json::from_str(json).unwrap();
        assert!(devcontainer.initialize_command.is_some());
    }

    #[test]
    fn test_app_port() {
        let json = r#"
        {
            "name": "test",
            "image": "ubuntu:20.04",
            "appPort": [3000, "8080:8080"]
        }
        "#;

        let devcontainer: Devcontainer = serde_json::from_str(json).unwrap();
        assert!(devcontainer.app_port.is_some());
    }

    #[test]
    fn test_run_args() {
        let json = r#"
        {
            "name": "test",
            "image": "ubuntu:20.04",
            "runArgs": ["--cap-add=SYS_PTRACE", "--security-opt", "seccomp=unconfined"]
        }
        "#;

        let devcontainer: Devcontainer = serde_json::from_str(json).unwrap();
        assert!(devcontainer.run_args.is_some());
        let args = devcontainer.run_args.unwrap();
        assert_eq!(args.len(), 3);
    }

    #[test]
    fn test_workspace_mount() {
        let json = r#"
        {
            "name": "test",
            "image": "ubuntu:20.04",
            "workspaceFolder": "/workspace",
            "workspaceMount": "source=${localWorkspaceFolder},target=/workspace,type=bind"
        }
        "#;

        let devcontainer: Devcontainer = serde_json::from_str(json).unwrap();
        assert_eq!(devcontainer.workspace_folder.as_deref(), Some("/workspace"));
        assert!(devcontainer.workspace_mount.is_some());
    }

    #[test]
    fn test_update_remote_user_uid() {
        let json = r#"
        {
            "name": "test",
            "image": "ubuntu:20.04",
            "updateRemoteUserUID": true
        }
        "#;

        let devcontainer: Devcontainer = serde_json::from_str(json).unwrap();
        assert_eq!(devcontainer.update_remote_user_uid, Some(true));
    }

    #[test]
    fn test_all_lifecycle_hooks() {
        let json = r#"
        {
            "name": "test",
            "image": "ubuntu:20.04",
            "onCreateCommand": "echo onCreate",
            "updateContentCommand": "echo updateContent",
            "postCreateCommand": "echo postCreate",
            "postStartCommand": "echo postStart",
            "postAttachCommand": "echo postAttach"
        }
        "#;

        let devcontainer: Devcontainer = serde_json::from_str(json).unwrap();

        assert!(devcontainer.on_create_command.is_some());
        assert!(devcontainer.update_content_command.is_some());
        assert!(devcontainer.post_create_command.is_some());
        assert!(devcontainer.post_start_command.is_some());
        assert!(devcontainer.post_attach_command.is_some());
    }

    #[test]
    fn test_lifecycle_hooks_optional() {
        let json = r#"
        {
            "name": "test",
            "image": "ubuntu:20.04"
        }
        "#;

        let devcontainer: Devcontainer = serde_json::from_str(json).unwrap();

        assert!(devcontainer.on_create_command.is_none());
        assert!(devcontainer.update_content_command.is_none());
        assert!(devcontainer.post_create_command.is_none());
        assert!(devcontainer.post_start_command.is_none());
        assert!(devcontainer.post_attach_command.is_none());
    }

    #[test]
    fn test_comprehensive_devcontainer() {
        let json = r#"
        {
            "name": "My Dev Container",
            "build": {
                "dockerfile": "Dockerfile",
                "context": "..",
                "args": {
                    "VARIANT": "20.04",
                    "NODE_VERSION": "18"
                },
                "target": "development"
            },
            "features": {
                "ghcr.io/devcontainers/features/node:1": {
                    "version": "18"
                },
                "ghcr.io/devcontainers/features/docker-in-docker:2": {}
            },
            "forwardPorts": [3000, 8080],
            "portsAttributes": {
                "3000": {
                    "label": "Frontend",
                    "onAutoForward": "openBrowser"
                }
            },
            "mounts": [
                {
                    "type": "volume",
                    "source": "node_modules",
                    "target": "/workspace/node_modules"
                }
            ],
            "containerEnv": {
                "NODE_ENV": "development"
            },
            "remoteEnv": {
                "PATH": "${containerEnv:PATH}:/custom/bin"
            },
            "runArgs": ["--init"],
            "postCreateCommand": {
                "install": "npm install",
                "prepare": "npm run prepare"
            },
            "postStartCommand": "npm run dev",
            "remoteUser": "vscode",
            "updateRemoteUserUID": true,
            "customizations": {
                "vscode": {
                    "extensions": [
                        "dbaeumer.vscode-eslint",
                        "esbenp.prettier-vscode"
                    ]
                }
            },
            "hostRequirements": {
                "cpus": 2,
                "memory": "4gb"
            }
        }
        "#;

        let devcontainer: Devcontainer = serde_json::from_str(json).unwrap();

        // Verify general properties
        assert_eq!(devcontainer.name.as_deref(), Some("My Dev Container"));
        assert_eq!(devcontainer.features.len(), 2);

        // Verify build configuration
        assert!(devcontainer.build.is_some());
        let build = devcontainer.build.unwrap();
        assert_eq!(build.dockerfile.as_deref(), Some("Dockerfile"));
        assert_eq!(build.context.as_deref(), Some(".."));
        assert_eq!(build.target.as_deref(), Some("development"));
        assert!(build.args.is_some());

        // Verify port forwarding
        assert!(devcontainer.forward_ports.is_some());
        assert!(devcontainer.ports_attributes.is_some());

        // Verify mounts
        assert!(devcontainer.mounts.is_some());

        // Verify environment
        assert!(devcontainer.container_env.is_some());
        assert!(devcontainer.remote_env.is_some());

        // Verify lifecycle commands
        assert!(devcontainer.post_create_command.is_some());
        assert!(devcontainer.post_start_command.is_some());

        // Verify user configuration
        assert_eq!(devcontainer.remote_user.as_deref(), Some("vscode"));
        assert_eq!(devcontainer.update_remote_user_uid, Some(true));

        // Verify customizations
        assert!(devcontainer.customizations.is_some());

        // Verify host requirements
        assert!(devcontainer.host_requirements.is_some());
    }
}
