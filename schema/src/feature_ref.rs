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

use std::path::PathBuf;

use serde::de;

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
