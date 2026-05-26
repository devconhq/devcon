// MIT License
//
// Copyright (c) 2025 DevCon Contributors

//! # Devcontainer Features
//!
//! This module provides types and functionality for working with devcontainer features.
//!
//! ## Main Types
//!
//! - [`Feature`] - The full feature definition from devcontainer-feature.json
//! - [`FeatureOption`] - Configuration option for a feature
//! - [`LifecycleCommand`] - Command that can run at different container lifecycle stages
//! - [`FeatureMount`] - Mount configuration for volumes or bind mounts
//!
//! ## Related Types
//!
//! For feature references and sources used in devcontainer.json, see the
//! [`Devcontainer`](crate::Devcontainer) type.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::lifecycle::LifecycleCommand;

/// Represents the metadata from a devcontainer-feature.json file.
///
/// This is the full feature definition that describes what the feature does,
/// what options it accepts, and how it should be installed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Feature {
    /// Unique identifier for the feature (required)
    pub id: String,

    /// Version following semver specification (required)
    pub version: String,

    /// Display name of the feature
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Description of the feature
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// URL to documentation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub documentation_url: Option<String>,

    /// URL to the license
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license_url: Option<String>,

    /// Keywords for searching
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keywords: Option<Vec<String>>,

    /// User-configurable options schema
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<HashMap<String, FeatureOption>>,

    /// Array of feature IDs that should execute before this one
    #[serde(skip_serializing_if = "Option::is_none")]
    pub installs_after: Option<Vec<String>>,

    /// Feature dependencies that must be satisfied
    #[serde(skip_serializing_if = "Option::is_none")]
    pub depends_on: Option<HashMap<String, serde_json::Value>>,

    /// Indicates the feature is deprecated
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deprecated: Option<bool>,

    /// Old IDs used for renaming this feature
    #[serde(skip_serializing_if = "Option::is_none")]
    pub legacy_ids: Option<Vec<String>>,

    /// Docker capabilities to add
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cap_add: Option<Vec<String>>,

    /// Container security options
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_opt: Option<Vec<String>>,

    /// Sets privileged mode for the container
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privileged: Option<bool>,

    /// Adds tiny init process to the container
    #[serde(skip_serializing_if = "Option::is_none")]
    pub init: Option<bool>,

    /// Entrypoint script that fires at container startup
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entrypoint: Option<String>,

    /// Mounts for volumes or bind mounts
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mounts: Option<Vec<FeatureMount>>,

    /// Container environment variables
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_env: Option<HashMap<String, String>>,

    /// Tool-specific configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customizations: Option<HashMap<String, serde_json::Value>>,

    /// Command to run when creating the container
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_create_command: Option<LifecycleCommand>,

    /// Command to run when workspace content is updated
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update_content_command: Option<LifecycleCommand>,

    /// Command to run after creating the container
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_create_command: Option<LifecycleCommand>,

    /// Command to run after starting the container
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_start_command: Option<LifecycleCommand>,

    /// Command to run when attaching to the container
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_attach_command: Option<LifecycleCommand>,
}

/// Mount configuration for volumes or bind mounts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FeatureMount {
    /// String format mount
    String(String),
    /// Structured mount configuration
    Structured(StructuredMount),
}

/// Structured mount configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StructuredMount {
    /// Type of mount (bind or volume)
    #[serde(rename = "type")]
    pub mount_type: MountType,

    /// Mount source (optional for volume mounts)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,

    /// Mount target (required)
    pub target: String,
}

/// Type of mount.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MountType {
    Bind,
    Volume,
}

/// Configuration option for a feature.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FeatureOption {
    /// Type of the option (boolean or string)
    #[serde(rename = "type")]
    pub option_type: FeatureOptionType,

    /// Description displayed to the user
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Default value
    pub default: serde_json::Value,

    /// Allowed values (user cannot provide custom values)
    #[serde(rename = "enum", skip_serializing_if = "Option::is_none")]
    pub allowed_values: Option<Vec<String>>,

    /// Suggested values (user can provide custom values)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proposals: Option<Vec<String>>,
}

/// Type of feature option.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FeatureOptionType {
    Boolean,
    String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_feature_minimal() {
        let json = json!({
            "id": "test-feature",
            "version": "1.0.0"
        });

        let feature: Feature = serde_json::from_value(json).unwrap();
        assert_eq!(feature.id, "test-feature");
        assert_eq!(feature.version, "1.0.0");
        assert!(feature.name.is_none());
        assert!(feature.options.is_none());
    }

    #[test]
    fn test_feature_with_options() {
        let json = json!({
            "id": "test-feature",
            "version": "1.0.0",
            "options": {
                "version": {
                    "type": "string",
                    "default": "latest",
                    "description": "Version to install"
                },
                "enabled": {
                    "type": "boolean",
                    "default": true
                }
            }
        });

        let feature: Feature = serde_json::from_value(json).unwrap();
        let options = feature.options.unwrap();
        assert_eq!(options.len(), 2);
        assert!(options.contains_key("version"));
        assert!(options.contains_key("enabled"));
    }

    #[test]
    fn test_feature_option_with_enum() {
        let json = json!({
            "type": "string",
            "default": "stable",
            "enum": ["stable", "beta", "nightly"]
        });

        let option: FeatureOption = serde_json::from_value(json).unwrap();
        assert_eq!(
            option.allowed_values.unwrap(),
            vec!["stable", "beta", "nightly"]
        );
    }

    #[test]
    fn test_feature_option_with_proposals() {
        let json = json!({
            "type": "string",
            "default": "3.11",
            "proposals": ["3.9", "3.10", "3.11", "3.12"]
        });

        let option: FeatureOption = serde_json::from_value(json).unwrap();
        assert_eq!(
            option.proposals.unwrap(),
            vec!["3.9", "3.10", "3.11", "3.12"]
        );
    }

    #[test]
    fn test_lifecycle_command_string() {
        let json = json!("echo 'hello'");
        let cmd: LifecycleCommand = serde_json::from_value(json).unwrap();
        assert!(matches!(cmd, LifecycleCommand::String(_)));
    }

    #[test]
    fn test_lifecycle_command_array() {
        let json = json!(["echo", "hello"]);
        let cmd: LifecycleCommand = serde_json::from_value(json).unwrap();
        assert!(matches!(cmd, LifecycleCommand::Array(_)));
    }

    #[test]
    fn test_lifecycle_command_object() {
        let json = json!({
            "server": "npm start",
            "db": ["docker", "run", "postgres"]
        });
        let cmd: LifecycleCommand = serde_json::from_value(json).unwrap();
        if let LifecycleCommand::Object(map) = cmd {
            assert_eq!(map.len(), 2);
            assert!(map.contains_key("server"));
            assert!(map.contains_key("db"));
        } else {
            panic!("Expected Object variant");
        }
    }

    #[test]
    fn test_feature_mount_string() {
        let json = json!("source=/var/run/docker.sock,target=/var/run/docker.sock,type=bind");
        let mount: FeatureMount = serde_json::from_value(json).unwrap();
        assert!(matches!(mount, FeatureMount::String(_)));
    }

    #[test]
    fn test_feature_mount_structured() {
        let json = json!({
            "type": "bind",
            "source": "/var/run/docker.sock",
            "target": "/var/run/docker.sock"
        });
        let mount: FeatureMount = serde_json::from_value(json).unwrap();
        if let FeatureMount::Structured(s) = mount {
            assert!(matches!(s.mount_type, MountType::Bind));
            assert_eq!(s.source.unwrap(), "/var/run/docker.sock");
            assert_eq!(s.target, "/var/run/docker.sock");
        } else {
            panic!("Expected Structured variant");
        }
    }

    #[test]
    fn test_feature_mount_volume() {
        let json = json!({
            "type": "volume",
            "target": "/data"
        });
        let mount: FeatureMount = serde_json::from_value(json).unwrap();
        if let FeatureMount::Structured(s) = mount {
            assert!(matches!(s.mount_type, MountType::Volume));
            assert!(s.source.is_none());
            assert_eq!(s.target, "/data");
        } else {
            panic!("Expected Structured variant");
        }
    }

    #[test]
    fn test_feature_with_lifecycle_commands() {
        let json = json!({
            "id": "test-feature",
            "version": "1.0.0",
            "onCreateCommand": "echo 'created'",
            "postStartCommand": ["echo", "started"],
            "postAttachCommand": {
                "welcome": "echo 'Welcome!'"
            }
        });

        let feature: Feature = serde_json::from_value(json).unwrap();
        assert!(feature.on_create_command.is_some());
        assert!(feature.post_start_command.is_some());
        assert!(feature.post_attach_command.is_some());
    }

    #[test]
    fn test_feature_with_container_config() {
        let json = json!({
            "id": "test-feature",
            "version": "1.0.0",
            "capAdd": ["SYS_PTRACE"],
            "securityOpt": ["seccomp=unconfined"],
            "privileged": true,
            "init": true
        });

        let feature: Feature = serde_json::from_value(json).unwrap();
        assert_eq!(feature.cap_add.unwrap(), vec!["SYS_PTRACE"]);
        assert_eq!(feature.security_opt.unwrap(), vec!["seccomp=unconfined"]);
        assert_eq!(feature.privileged, Some(true));
        assert_eq!(feature.init, Some(true));
    }

    #[test]
    fn test_feature_with_depends_on() {
        let json = json!({
            "id": "test-feature",
            "version": "1.0.0",
            "dependsOn": {
                "ghcr.io/devcontainers/features/common-utils": {}
            }
        });

        let feature: Feature = serde_json::from_value(json).unwrap();
        let deps = feature.depends_on.unwrap();
        assert!(deps.contains_key("ghcr.io/devcontainers/features/common-utils"));
    }

    #[test]
    fn test_feature_serialization_roundtrip() {
        let feature = Feature {
            id: "test".to_string(),
            version: "1.0.0".to_string(),
            name: Some("Test Feature".to_string()),
            description: Some("A test feature".to_string()),
            documentation_url: None,
            license_url: None,
            keywords: Some(vec!["test".to_string()]),
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

        let json = serde_json::to_value(&feature).unwrap();
        let deserialized: Feature = serde_json::from_value(json).unwrap();
        assert_eq!(feature.id, deserialized.id);
        assert_eq!(feature.version, deserialized.version);
    }
}
