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

//! # Image Metadata
//!
//! Implements the `devcontainer.metadata` OCI image label as defined in
//! <https://containers.dev/implementors/spec/#image-metadata>.
//!
//! The label value is a JSON array of [`ImageMetadataEntry`] objects — one per
//! installed feature and one for the `devcontainer.json` itself.  The
//! [`merge_metadata_entries`] function applies the spec's merge rules to produce
//! a single [`MergedImageMetadata`] value.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::lifecycle::LifecycleCommand;

/// A single entry in the `devcontainer.metadata` OCI image label.
///
/// Each installed feature contributes one entry (with `id` set to the feature's
/// registry reference), and the `devcontainer.json` contributes one entry
/// (with `id` absent).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageMetadataEntry {
    /// Feature ID, e.g. `ghcr.io/devcontainers/features/node:1`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub init: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privileged: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cap_add: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_opt: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entrypoint: Option<String>,
    /// Mounts serialised as raw JSON to accommodate both string and structured forms.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mounts: Option<Vec<serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_create_command: Option<LifecycleCommand>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update_content_command: Option<LifecycleCommand>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_create_command: Option<LifecycleCommand>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_start_command: Option<LifecycleCommand>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_attach_command: Option<LifecycleCommand>,
    /// Which lifecycle command to wait for; last value wins.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wait_for: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customizations: Option<HashMap<String, serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_env_probe: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_env: Option<HashMap<String, Option<String>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_env: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub override_command: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ports_attributes: Option<HashMap<String, serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub other_ports_attributes: Option<serde_json::Value>,
    /// Forwarded ports as raw JSON to handle both port numbers and `"host:port"` strings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forward_ports: Option<Vec<serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shutdown_action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update_remote_user_uid: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_requirements: Option<serde_json::Value>,
}

/// The result of merging all [`ImageMetadataEntry`] items found in a
/// `devcontainer.metadata` image label.
///
/// Merge rules (per the devcontainer spec):
///
/// | Property | Rule |
/// |---|---|
/// | `init`, `privileged` | `true` if any entry is `true` |
/// | `capAdd`, `securityOpt`, `entrypoints`, `mounts`, lifecycle commands | collected union |
/// | `forwardPorts` | union without duplicates |
/// | `remoteUser`, `containerUser`, scalar strings | last non-`None` value wins |
/// | `remoteEnv`, `containerEnv` maps | per-key, last value wins |
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MergedImageMetadata {
    pub init: bool,
    pub privileged: bool,
    pub cap_add: Vec<String>,
    pub security_opt: Vec<String>,
    pub entrypoints: Vec<String>,
    pub mounts: Vec<serde_json::Value>,
    pub on_create_commands: Vec<LifecycleCommand>,
    pub update_content_commands: Vec<LifecycleCommand>,
    pub post_create_commands: Vec<LifecycleCommand>,
    pub post_start_commands: Vec<LifecycleCommand>,
    pub post_attach_commands: Vec<LifecycleCommand>,
    pub wait_for: Option<String>,
    pub remote_user: Option<String>,
    pub container_user: Option<String>,
    pub user_env_probe: Option<String>,
    pub container_env: HashMap<String, String>,
    pub remote_env: HashMap<String, Option<String>>,
    pub override_command: Option<bool>,
    pub forward_ports: Vec<serde_json::Value>,
    pub shutdown_action: Option<String>,
    pub update_remote_user_uid: Option<bool>,
    /// IDs of features that contributed entries (entries with a non-empty `id` field).
    pub feature_ids: Vec<String>,
}

/// Parses the value of a `devcontainer.metadata` image label into a list of
/// [`ImageMetadataEntry`] objects.
///
/// Accepts both the canonical JSON-array form and the single-object shorthand
/// permitted by the spec.  Returns an empty `Vec` on any parse failure so
/// callers can treat a missing or malformed label as "no metadata".
pub fn parse_metadata_label(label: &str) -> Vec<ImageMetadataEntry> {
    let value: serde_json::Value = match serde_json::from_str(label) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    match value {
        serde_json::Value::Array(arr) => arr
            .into_iter()
            .filter_map(|v| serde_json::from_value(v).ok())
            .collect(),
        obj @ serde_json::Value::Object(_) => {
            serde_json::from_value(obj).ok().into_iter().collect()
        }
        _ => Vec::new(),
    }
}

/// Merges a slice of [`ImageMetadataEntry`] items into a single [`MergedImageMetadata`]
/// using the rules defined by the devcontainer spec.
pub fn merge_metadata_entries(entries: &[ImageMetadataEntry]) -> MergedImageMetadata {
    let mut merged = MergedImageMetadata::default();

    for entry in entries {
        if let Some(ref id) = entry.id
            && !id.is_empty()
        {
            merged.feature_ids.push(id.clone());
        }
        // Boolean OR
        if entry.init == Some(true) {
            merged.init = true;
        }
        if entry.privileged == Some(true) {
            merged.privileged = true;
        }
        // Union lists (deduplicated)
        if let Some(ref caps) = entry.cap_add {
            for cap in caps {
                if !merged.cap_add.contains(cap) {
                    merged.cap_add.push(cap.clone());
                }
            }
        }
        if let Some(ref opts) = entry.security_opt {
            for opt in opts {
                if !merged.security_opt.contains(opt) {
                    merged.security_opt.push(opt.clone());
                }
            }
        }
        if let Some(ref ep) = entry.entrypoint
            && !ep.is_empty()
        {
            merged.entrypoints.push(ep.clone());
        }
        if let Some(ref mounts) = entry.mounts {
            for mount in mounts {
                if !merged.mounts.contains(mount) {
                    merged.mounts.push(mount.clone());
                }
            }
        }
        // Lifecycle — collect all
        if let Some(ref cmd) = entry.on_create_command {
            merged.on_create_commands.push(cmd.clone());
        }
        if let Some(ref cmd) = entry.update_content_command {
            merged.update_content_commands.push(cmd.clone());
        }
        if let Some(ref cmd) = entry.post_create_command {
            merged.post_create_commands.push(cmd.clone());
        }
        if let Some(ref cmd) = entry.post_start_command {
            merged.post_start_commands.push(cmd.clone());
        }
        if let Some(ref cmd) = entry.post_attach_command {
            merged.post_attach_commands.push(cmd.clone());
        }
        // Last-wins scalars
        if entry.wait_for.is_some() {
            merged.wait_for = entry.wait_for.clone();
        }
        if entry.remote_user.is_some() {
            merged.remote_user = entry.remote_user.clone();
        }
        if entry.container_user.is_some() {
            merged.container_user = entry.container_user.clone();
        }
        if entry.user_env_probe.is_some() {
            merged.user_env_probe = entry.user_env_probe.clone();
        }
        if entry.override_command.is_some() {
            merged.override_command = entry.override_command;
        }
        if entry.shutdown_action.is_some() {
            merged.shutdown_action = entry.shutdown_action.clone();
        }
        if entry.update_remote_user_uid.is_some() {
            merged.update_remote_user_uid = entry.update_remote_user_uid;
        }
        // Per-key last-wins maps
        if let Some(ref env) = entry.container_env {
            for (k, v) in env {
                merged.container_env.insert(k.clone(), v.clone());
            }
        }
        if let Some(ref env) = entry.remote_env {
            for (k, v) in env {
                merged.remote_env.insert(k.clone(), v.clone());
            }
        }
        // forwardPorts — union without duplicates
        if let Some(ref ports) = entry.forward_ports {
            for port in ports {
                if !merged.forward_ports.contains(port) {
                    merged.forward_ports.push(port.clone());
                }
            }
        }
    }

    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_metadata_label_array() {
        let label = r#"[{"id":"ghcr.io/devcontainers/features/node:1","remoteUser":"vscode"}]"#;
        let entries = parse_metadata_label(label);
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].id.as_deref(),
            Some("ghcr.io/devcontainers/features/node:1")
        );
        assert_eq!(entries[0].remote_user.as_deref(), Some("vscode"));
    }

    #[test]
    fn test_parse_metadata_label_single_object() {
        let label = r#"{"remoteUser":"vscode"}"#;
        let entries = parse_metadata_label(label);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].remote_user.as_deref(), Some("vscode"));
    }

    #[test]
    fn test_parse_metadata_label_invalid() {
        assert!(parse_metadata_label("not json").is_empty());
        assert!(parse_metadata_label("42").is_empty());
    }

    #[test]
    fn test_merge_boolean_or() {
        let entries = vec![
            ImageMetadataEntry {
                init: Some(false),
                privileged: Some(true),
                ..Default::default()
            },
            ImageMetadataEntry {
                init: Some(true),
                privileged: Some(false),
                ..Default::default()
            },
        ];
        let merged = merge_metadata_entries(&entries);
        assert!(merged.init);
        assert!(merged.privileged);
    }

    #[test]
    fn test_merge_remote_user_last_wins() {
        let entries = vec![
            ImageMetadataEntry {
                remote_user: Some("root".to_string()),
                ..Default::default()
            },
            ImageMetadataEntry {
                remote_user: Some("vscode".to_string()),
                ..Default::default()
            },
        ];
        let merged = merge_metadata_entries(&entries);
        assert_eq!(merged.remote_user.as_deref(), Some("vscode"));
    }

    #[test]
    fn test_merge_container_env_per_key_last_wins() {
        let entries = vec![
            ImageMetadataEntry {
                container_env: Some([("FOO".to_string(), "a".to_string())].into()),
                ..Default::default()
            },
            ImageMetadataEntry {
                container_env: Some(
                    [
                        ("FOO".to_string(), "b".to_string()),
                        ("BAR".to_string(), "c".to_string()),
                    ]
                    .into(),
                ),
                ..Default::default()
            },
        ];
        let merged = merge_metadata_entries(&entries);
        assert_eq!(
            merged.container_env.get("FOO").map(String::as_str),
            Some("b")
        );
        assert_eq!(
            merged.container_env.get("BAR").map(String::as_str),
            Some("c")
        );
    }

    #[test]
    fn test_merge_cap_add_union() {
        let entries = vec![
            ImageMetadataEntry {
                cap_add: Some(vec!["SYS_PTRACE".to_string()]),
                ..Default::default()
            },
            ImageMetadataEntry {
                cap_add: Some(vec!["SYS_PTRACE".to_string(), "NET_ADMIN".to_string()]),
                ..Default::default()
            },
        ];
        let merged = merge_metadata_entries(&entries);
        assert_eq!(merged.cap_add, vec!["SYS_PTRACE", "NET_ADMIN"]);
    }

    #[test]
    fn test_merge_feature_ids_collected() {
        let entries = vec![
            ImageMetadataEntry {
                id: Some("feature/a:1".to_string()),
                ..Default::default()
            },
            ImageMetadataEntry {
                id: None,
                remote_user: Some("vscode".to_string()),
                ..Default::default()
            },
            ImageMetadataEntry {
                id: Some("feature/b:1".to_string()),
                ..Default::default()
            },
        ];
        let merged = merge_metadata_entries(&entries);
        assert_eq!(merged.feature_ids, vec!["feature/a:1", "feature/b:1"]);
    }
}
