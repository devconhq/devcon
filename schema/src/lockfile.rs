// MIT License
//
// Copyright (c) 2025 DevCon Contributors

//! Devcontainer feature lockfile model.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Represents a `devcontainer-lock.json` file.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DevcontainerLockfile {
    #[serde(default)]
    pub features: BTreeMap<String, DevcontainerLockEntry>,
}

/// Represents a single feature lock entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DevcontainerLockEntry {
    pub resolved: String,
    pub version: String,
    pub integrity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub depends_on: Option<Vec<String>>,
}

/// Lowercases feature identifiers for normalized lockfile key handling.
pub fn normalize_feature_identifier(value: &str) -> String {
    value.to_ascii_lowercase()
}
