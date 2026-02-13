// MIT License
//
// Copyright (c) 2025 DevCon Contributors

//! # Feature Processing
//!
//! This module provides functionality for downloading, processing, and applying
//! devcontainer features.
//!
//! ## Main Components
//!
//! - Feature downloading from OCI registries
//! - Feature option merging and validation
//! - Feature installation script execution
//! - Feature dependency resolution
//!
//! ## Overview
//!
//! The driver module handles:
//! - Processing and downloading devcontainer features from registries
//! - Building container images with Dockerfiles
//! - Starting and managing container instances
//!
//! ## Submodules
//!
//! - [`container`] - Container lifecycle management (build, start, stop)
//!
//! ## Feature Processing
//!
//! Features can be sourced from:
//! - **Registry** - Downloaded from OCI-compliant registries like ghcr.io
//! - **Local** - Loaded from the local filesystem (not yet implemented)

use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs::{self, File},
    path::{Path, PathBuf},
};

use crate::error::{Error, Result};
use tempfile::TempDir;
use tracing::{debug, info};

use crate::devcontainer::{
    FeatureRef, FeatureRegistry,
    FeatureSource::{Local, Registry},
    parse_feature,
};
use crate::feature::Feature;

#[derive(Debug, Clone)]
pub struct FeatureProcessResult {
    pub feature_ref: FeatureRef,
    pub feature: Feature,
    pub path: PathBuf,
}

impl FeatureProcessResult {
    /// Returns the name of the feature.
    ///
    /// Tries to return the feature's `name` field if it exists,
    /// otherwise falls back to the registry name or local path name.
    pub fn name(&self) -> String {
        // First, try to use the feature's name field if it exists
        if let Some(ref name) = self.feature.name {
            return name.clone();
        }

        // Fall back to the feature reference source
        match &self.feature_ref.source {
            Registry { registry } => registry.name.clone(),
            Local { path } => path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("unknown")
                .to_string(),
        }
    }

    /// Returns a directory-safe name for the feature.
    ///
    /// The directory name is constructed from the feature name and version,
    /// with spaces replaced by hyphens and all characters lowercased.
    ///
    /// # Returns
    ///
    /// A string in the format "name-version" suitable for use as a directory name.
    pub fn directory_name(&self) -> String {
        let name = self.name().replace(' ', "-").to_lowercase();
        let version = &self.feature.version;
        format!("{}-{}", name, version)
    }
}

/// Processes a list of features, downloading and extracting them as needed.
///
/// This function iterates through all features and processes each one,
/// resolving transitive dependencies and ordering them topologically.
///
/// # Arguments
///
/// * `features` - Slice of features to process
///
/// # Returns
///
/// A vector of FeatureProcessResult in dependency order (dependencies first)
///
/// # Errors
///
/// Returns an error if any feature fails to download, extract, or if there are
/// circular dependencies.
pub fn process_features(features: &[FeatureRef], silent: bool) -> Result<Vec<FeatureProcessResult>> {
    if !silent {
        println!("Processing features..");
    }
    let mut initial_results: Vec<FeatureProcessResult> = vec![];

    // Process initial features
    for feature_ref in features {
        match &feature_ref.source {
            Registry { registry, .. } => {
                if !silent {
                    println!("Processing feature {}", registry.name)
                }
            }
            Local { path } => {
                if !silent {
                    println!(
                        "Processing feature {}",
                        path.canonicalize()?
                            .file_name()
                            .ok_or_else(|| Error::new("Could not get basename of directory"))?
                            .to_string_lossy()
                    )
                }
            }
        }
        let feature_result = process_feature(feature_ref)?;
        initial_results.push(feature_result);
    }

    // Resolve all dependencies (transitive)
    if !silent {
        println!("Resolving feature dependencies..");
    }
    let all_features = resolve_all_dependencies(initial_results, silent)?;

    // Sort features topologically
    if !silent {
        println!("Ordering features by dependencies..");
    }
    let sorted_features = topological_sort(all_features)?;

    if !silent {
        println!(
            "Processed {} features (including dependencies)",
            sorted_features.len()
        );
    }

    Ok(sorted_features)
}

/// Recursively resolves and downloads all feature dependencies.
///
/// This function processes the initial features and their transitive dependencies,
/// downloading any features referenced in `dependsOn` or `installsAfter` fields.
///
/// # Arguments
///
/// * `initial_features` - The initial set of features to process
///
/// # Returns
///
/// A map from feature ID to its processed result, including all transitive dependencies
///
/// # Errors
///
/// Returns an error if:
/// - A dependency cannot be downloaded or processed
/// - A circular dependency is detected
/// - A dependency reference cannot be parsed
fn resolve_all_dependencies(
    initial_features: Vec<FeatureProcessResult>,
    silent: bool,
) -> Result<HashMap<String, FeatureProcessResult>> {
    let mut all_features: HashMap<String, FeatureProcessResult> = HashMap::new();
    let mut to_process: VecDeque<FeatureProcessResult> = VecDeque::new();
    let mut processing: HashSet<String> = HashSet::new();

    // Add initial features to processing queue
    for feature_result in initial_features {
        let feature_id = feature_result.feature.id.clone();
        to_process.push_back(feature_result);
        processing.insert(feature_id);
    }

    while let Some(current) = to_process.pop_front() {
        let current_id = current.feature.id.clone();
        debug!("Processing dependencies for feature: {}", current_id);

        // Collect only dependsOn dependencies for downloading
        // installsAfter is only used for ordering, not for automatic dependency resolution
        let mut dependencies: Vec<String> = Vec::new();

        if let Some(ref depends_on) = current.feature.depends_on {
            dependencies.extend(depends_on.keys().cloned());
        }

        // Process each dependency
        for dep_id in dependencies {
            // Skip if already processed or in processing queue
            if all_features.contains_key(&dep_id) || processing.contains(&dep_id) {
                continue;
            }

            debug!(
                "Downloading dependency: {} for feature: {}",
                dep_id, current_id
            );

            // Parse the dependency ID and download the feature
            // Dependencies can be:
            // 1. Just feature ID (e.g., "ghcr.io/devcontainers/features/common-utils")
            // 2. Feature ID with version from dependsOn map
            let dep_ref = if let Some(ref depends_on) = current.feature.depends_on {
                if let Some(version_value) = depends_on.get(&dep_id) {
                    // Parse version from the value (could be string or object with version)
                    let version = match version_value {
                        serde_json::Value::String(v) => v.clone(),
                        serde_json::Value::Object(obj) => obj
                            .get("version")
                            .and_then(|v| v.as_str())
                            .unwrap_or("latest")
                            .to_string(),
                        _ => "latest".to_string(),
                    };

                    // Create FeatureRef from dependency ID
                    // Format the ID with version: "ghcr.io/owner/repo/feature:version"
                    let feature_url = if dep_id.contains(':') {
                        dep_id.clone()
                    } else {
                        format!("{}:{}", dep_id, version)
                    };
                    parse_feature::<serde_json::Error>(&feature_url, serde_json::json!({}))?
                } else {
                    // Use from installsAfter, default to latest
                    let feature_url = if dep_id.contains(':') {
                        dep_id.clone()
                    } else {
                        format!("{}:latest", dep_id)
                    };
                    parse_feature::<serde_json::Error>(&feature_url, serde_json::json!({}))?
                }
            } else {
                let feature_url = if dep_id.contains(':') {
                    dep_id.clone()
                } else {
                    format!("{}:latest", dep_id)
                };
                parse_feature::<serde_json::Error>(&feature_url, serde_json::json!({}))?
            };

            // Process the dependency
            if !silent {
                println!("Downloading dependency feature: {}", dep_id);
            }
            let dep_result = process_feature(&dep_ref)?;
            let dep_feature_id = dep_result.feature.id.clone();

            // Add to processing queue
            processing.insert(dep_feature_id.clone());
            to_process.push_back(dep_result);
        }

        // Add current feature to results
        all_features.insert(current_id.clone(), current);
        processing.remove(&current_id);
    }

    Ok(all_features)
}

/// Performs topological sort on features based on their dependencies.
/// Performs topological sort on features based on their dependencies.
///
/// Uses Kahn's algorithm to order features such that dependencies are installed
/// before features that depend on them.
///
/// # Arguments
///
/// * `features` - Map of feature ID to FeatureProcessResult
///
/// # Returns
///
/// An ordered vector of FeatureProcessResult where dependencies come before dependents
///
/// # Errors
///
/// Returns an error if a circular dependency is detected
fn topological_sort(
    features: HashMap<String, FeatureProcessResult>,
) -> Result<Vec<FeatureProcessResult>> {
    let mut in_degree: HashMap<String, usize> = HashMap::new();
    let mut adjacency: HashMap<String, Vec<String>> = HashMap::new();
    let mut feature_map = features;

    // Build the dependency graph
    for (feature_id, feature_result) in &feature_map {
        in_degree.entry(feature_id.clone()).or_insert(0);
        adjacency.entry(feature_id.clone()).or_default();

        let mut dependencies = Vec::new();

        // Add dependsOn dependencies
        if let Some(ref depends_on) = feature_result.feature.depends_on {
            dependencies.extend(depends_on.keys().cloned());
        }

        // Add installsAfter dependencies
        if let Some(ref installs_after) = feature_result.feature.installs_after {
            dependencies.extend(installs_after.iter().cloned());
        }

        debug!(
            "Feature {} has {} dependencies: {:?}",
            feature_id,
            dependencies.len(),
            dependencies
        );

        for dep_id in dependencies {
            // Normalize the dependency ID to match the feature ID format
            // Dependencies can be full URLs like "ghcr.io/devcontainers/features/common-utils"
            // but feature IDs are just the name like "common-utils"
            let normalized_dep_id = if dep_id.contains('/') {
                // Extract the last component (feature name) from the URL
                dep_id
                    .split('/')
                    .next_back()
                    .unwrap_or(&dep_id)
                    .split(':')
                    .next()
                    .unwrap_or(&dep_id)
                    .to_string()
            } else {
                dep_id.clone()
            };

            // Only process dependencies that are in our feature set
            if feature_map.contains_key(&normalized_dep_id) {
                debug!(
                    "  Adding edge: {} -> {} (from dependency: {})",
                    normalized_dep_id, feature_id, dep_id
                );
                adjacency
                    .entry(normalized_dep_id.clone())
                    .or_default()
                    .push(feature_id.clone());
                *in_degree.entry(feature_id.clone()).or_default() += 1;
            } else {
                debug!(
                    "  Dependency {} (normalized: {}) not found in feature set for {}",
                    dep_id, normalized_dep_id, feature_id
                );
            }
        }
    }

    // Kahn's algorithm: start with nodes that have no dependencies
    // Sort by feature ID for deterministic ordering
    let mut initial_zero_degree: Vec<String> = in_degree
        .iter()
        .filter(|(_, degree)| **degree == 0)
        .map(|(id, _)| id.clone())
        .collect();
    initial_zero_degree.sort();

    let mut queue: VecDeque<String> = initial_zero_degree.into_iter().collect();
    let mut sorted: Vec<FeatureProcessResult> = Vec::new();

    while let Some(current_id) = queue.pop_front() {
        // Move the feature from the map to the sorted list
        if let Some(feature_result) = feature_map.remove(&current_id) {
            sorted.push(feature_result);
        }

        // Reduce in-degree for all dependent features
        if let Some(dependents) = adjacency.get(&current_id) {
            let mut newly_ready: Vec<String> = Vec::new();
            for dependent_id in dependents {
                if let Some(degree) = in_degree.get_mut(dependent_id) {
                    *degree -= 1;
                    if *degree == 0 {
                        newly_ready.push(dependent_id.clone());
                    }
                }
            }
            // Sort for deterministic ordering
            newly_ready.sort();
            for id in newly_ready {
                queue.push_back(id);
            }
        }
    }

    // Check for circular dependencies
    if sorted.len() != in_degree.len() {
        let remaining: Vec<String> = feature_map.keys().cloned().collect();
        return Err(Error::new(format!(
            "Circular dependency detected among features: {:?}",
            remaining
        )));
    }

    debug!("Topologically sorted {} features", sorted.len());
    for (i, feature) in sorted.iter().enumerate() {
        debug!("  {}. {}", i + 1, feature.feature.id);
    }

    // Prioritize common-utils to be first if present and no dependencies prevent it
    // common-utils is a foundational feature that other features often depend on
    if let Some(common_utils_pos) = sorted
        .iter()
        .position(|f| f.feature.id.contains("common-utils"))
        && common_utils_pos > 0
    {
        // Check if common-utils has ANY dependencies in the feature set
        // If it does, they must all be before it in the sorted order (guaranteed by topo sort)
        // We can only move it to position 0 if it has NO dependencies
        let has_any_dependencies = {
            let mut deps = Vec::new();

            if let Some(ref depends_on) = sorted[common_utils_pos].feature.depends_on {
                deps.extend(depends_on.keys());
            }

            if let Some(ref installs_after) = sorted[common_utils_pos].feature.installs_after {
                deps.extend(installs_after.iter());
            }

            // Check if any of these dependencies are in our sorted feature list
            deps.iter()
                .any(|dep_id| sorted.iter().any(|f| &f.feature.id == *dep_id))
        };

        if !has_any_dependencies {
            debug!("Moving common-utils to the beginning of the feature list");
            let common_utils = sorted.remove(common_utils_pos);
            sorted.insert(0, common_utils);

            debug!("Reordered feature list with common-utils first:");
            for (i, feature) in sorted.iter().enumerate() {
                debug!("  {}. {}", i + 1, feature.feature.id);
            }
        } else {
            debug!("common-utils has dependencies, keeping it in topological order");
        }
    }

    Ok(sorted)
}

pub fn process_feature(feature_ref: &FeatureRef) -> Result<FeatureProcessResult> {
    let relative_path = match &feature_ref.source {
        Registry { registry } => download_feature(registry),
        Local { path } => local_feature(path),
    }?;

    // Read devcontainer-feature.json if it exists to parse the Feature metadata
    let feature_json_path = relative_path.join("devcontainer-feature.json");

    if !feature_json_path.exists() {
        return Err(Error::new(format!(
            "Feature definition file not found: {}",
            feature_json_path.display()
        )));
    }

    let feature_json_content = fs::read_to_string(&feature_json_path)?;
    let parsed_feature: Feature = serde_json::from_str(&feature_json_content)?;

    Ok(FeatureProcessResult {
        feature_ref: feature_ref.clone(),
        feature: parsed_feature,
        path: relative_path,
    })
}

/// Get the cache directory for devcontainer features
fn get_feature_cache_dir() -> Result<std::path::PathBuf> {
    let cache_dir =
        dirs::cache_dir().ok_or_else(|| Error::new("Could not determine cache directory"))?;
    let devcon_cache = cache_dir.join("devcon").join("features");
    fs::create_dir_all(&devcon_cache)?;
    Ok(devcon_cache)
}

/// Get the versioned cache path for a specific feature based on layer SHA
fn get_cached_feature_path(
    registry: &FeatureRegistry,
    layer_sha: &str,
) -> Result<std::path::PathBuf> {
    let cache_dir = get_feature_cache_dir()?;
    // Create path: cache/owner/repository/name/sha
    // Using SHA ensures automatic invalidation when content changes
    let feature_cache = cache_dir
        .join(&registry.owner)
        .join(&registry.repository)
        .join(&registry.name)
        .join(layer_sha);
    Ok(feature_cache)
}

/// Get local feature path
fn local_feature(path: &Path) -> Result<PathBuf> {
    info!("Using local feature from path: {}", path.display());
    path.canonicalize().map_err(|e| Error::new(e.to_string()))
}

/// Download a feature from registry to cache, or use cached version if available
fn download_feature(registry: &FeatureRegistry) -> Result<PathBuf> {
    // First, fetch the manifest to get the layer SHA
    let (token, layer_digest) = fetch_manifest_and_layer_digest(registry)?;

    // Extract SHA from digest (format: "sha256:abc123...")
    let layer_sha = layer_digest
        .strip_prefix("sha256:")
        .unwrap_or(&layer_digest)
        .chars()
        .take(12) // Use first 12 chars of SHA for shorter paths
        .collect::<String>();

    let cached_feature_path = get_cached_feature_path(registry, &layer_sha)?;

    // Check if feature is already cached
    if !cached_feature_path.exists()
        || !cached_feature_path
            .join("devcontainer-feature.json")
            .exists()
    {
        info!(
            "Downloading feature: {} (version {}, SHA: {})",
            registry.name, registry.version, layer_sha
        );
        download_and_cache_feature(registry, &cached_feature_path, &token, &layer_digest)?;
    } else {
        info!(
            "Using cached feature: {} (version {}, SHA: {})",
            registry.name, registry.version, layer_sha
        );
    }

    Ok(cached_feature_path)
}

/// Fetch the manifest and extract the layer digest (SHA)
fn fetch_manifest_and_layer_digest(registry: &FeatureRegistry) -> Result<(String, String)> {
    let token_url = format!(
        "https://{}/token?scope=repository:{}/{}:pull",
        "ghcr.io", registry.owner, registry.repository
    );

    let response = reqwest::blocking::get(&token_url)?;
    if !response.status().is_success() {
        return Err(Error::new(format!(
            "Failed to get token for feature: {}",
            registry.name
        )));
    }
    let json: serde_json::Value = response.json()?;
    let token = json["token"]
        .as_str()
        .ok_or_else(|| {
            Error::new(format!(
                "Token not found in response for feature: {}",
                registry.name
            ))
        })?
        .to_string();

    let manifest_url = format!(
        "https://{}/v2/{}/{}/{}/manifests/{}",
        "ghcr.io", registry.owner, registry.repository, registry.name, registry.version
    );

    let manifest_response = reqwest::blocking::Client::new()
        .get(&manifest_url)
        .bearer_auth(&token)
        .header("Accept", "application/vnd.oci.image.manifest.v1+json")
        .send()?;

    if !manifest_response.status().is_success() {
        return Err(Error::new(format!(
            "Failed to download manifest for feature: {}",
            registry.name
        )));
    }
    let manifest_json: serde_json::Value = manifest_response.json()?;
    let manifest_str = serde_json::to_string(&manifest_json)?;
    let reader = std::io::Cursor::new(manifest_str);
    let manifest = oci_spec::image::ImageManifest::from_reader(reader)?;
    let layer = manifest.layers().first().ok_or_else(|| {
        Error::new(format!(
            "No layers found in manifest for feature: {}",
            registry.name
        ))
    })?;

    Ok((token, layer.digest().to_string()))
}

/// Download and extract a feature to the cache directory
fn download_and_cache_feature(
    registry: &FeatureRegistry,
    cache_path: &std::path::Path,
    token: &str,
    layer_digest: &str,
) -> Result<()> {
    let temp_directory = TempDir::new()?;

    let layer_url = format!(
        "https://{}/v2/{}/{}/{}/blobs/{}",
        "ghcr.io", registry.owner, registry.repository, registry.name, layer_digest
    );
    let layer_response = reqwest::blocking::Client::new()
        .get(&layer_url)
        .bearer_auth(token)
        .send()?;

    if !layer_response.status().is_success() {
        return Err(Error::new(format!(
            "Failed to download layer for feature: {}",
            registry.name
        )));
    }
    let layer_bytes = layer_response.bytes()?;

    // Re-fetch manifest to get media type (we only got the digest earlier)
    let manifest_url = format!(
        "https://{}/v2/{}/{}/{}/manifests/{}",
        "ghcr.io", registry.owner, registry.repository, registry.name, registry.version
    );
    let manifest_response = reqwest::blocking::Client::new()
        .get(&manifest_url)
        .bearer_auth(token)
        .header("Accept", "application/vnd.oci.image.manifest.v1+json")
        .send()?;
    let manifest_json: serde_json::Value = manifest_response.json()?;
    let manifest_str = serde_json::to_string(&manifest_json)?;
    let reader = std::io::Cursor::new(manifest_str);
    let manifest = oci_spec::image::ImageManifest::from_reader(reader)?;
    let layer = manifest.layers().first().ok_or_else(|| {
        Error::new(format!(
            "No layers found in manifest for feature: {}",
            registry.name
        ))
    })?;

    let extract_path = match layer.media_type() {
        oci_spec::image::MediaType::Other(str) => match str.as_str() {
            "application/vnd.devcontainers.layer.v1+tar"
            | "application/vnd.oci.image.layer.v1.tar" => {
                debug!(
                    "Extracting uncompressed layer for feature: {}",
                    registry.name
                );
                let temp_file = temp_directory.path().join("feature.tar");
                fs::write(&temp_file, &layer_bytes)?;

                let feature_archive = File::open(&temp_file)?;
                let mut archive = tar::Archive::new(feature_archive);
                let extract_path = temp_directory.path().join("extract");
                fs::create_dir_all(&extract_path)?;
                archive.unpack(&extract_path).unwrap();

                extract_path
            }
            "application/vnd.devcontainers.layer.v1+tar+gzip"
            | "application/vnd.oci.image.layer.v1.tar+gzip" => {
                debug!(
                    "Extracting gzip compressed layer for feature: {}",
                    registry.name
                );
                let temp_file = temp_directory.path().join("feature.tar.gz");
                fs::write(&temp_file, &layer_bytes)?;

                let feature_archive = File::open(&temp_file)?;
                let decompressor = flate2::read::GzDecoder::new(feature_archive);
                let mut archive = tar::Archive::new(decompressor);
                let extract_path = temp_directory.path().join("extract");
                fs::create_dir_all(&extract_path)?;
                archive.unpack(&extract_path).unwrap();

                extract_path
            }
            _ => {
                return Err(Error::new(format!(
                    "Unsupported layer media type for feature: {}, media type: {}",
                    registry.name, str
                )));
            }
        },

        _ => {
            return Err(Error::new(format!(
                "Unsupported layer media type for feature: {}",
                registry.name
            )));
        }
    };

    debug!(
        "Feature {} extracted to temporary path: {}",
        registry.name,
        extract_path.display()
    );

    // Move extracted feature to cache path
    fs::create_dir_all(cache_path)?;

    let mut options = fs_extra::dir::CopyOptions::new();
    options.overwrite = true;
    options.copy_inside = true;
    options.content_only = true;

    debug!(
        "Copying extracted feature to cache path: {}",
        cache_path.display()
    );
    fs_extra::dir::copy(&extract_path, cache_path, &options)
        .map_err(|e| Error::new(format!("Failed to copy extracted feature: {}", e)))?;

    Ok(())
}

/// Clear the entire feature cache
/// TODO: Add command which invokes this function
#[allow(dead_code)]
pub fn clear_feature_cache() -> Result<()> {
    let cache_dir = get_feature_cache_dir()?;
    if cache_dir.exists() {
        info!("Clearing feature cache at: {}", cache_dir.display());
        fs::remove_dir_all(&cache_dir)?;
        fs::create_dir_all(&cache_dir)?;
        println!("Feature cache cleared successfully");
    } else {
        println!("Feature cache is already empty");
    }
    Ok(())
}

/// Clear cache for a specific feature
/// TODO: Add command which invokes this function
#[allow(dead_code)]
pub fn clear_feature_cache_for(owner: &str, repository: &str, name: &str) -> Result<()> {
    let cache_dir = get_feature_cache_dir()?;
    let feature_cache = cache_dir.join(owner).join(repository).join(name);

    if feature_cache.exists() {
        info!(
            "Clearing cache for feature: {}/{}/{}",
            owner, repository, name
        );
        fs::remove_dir_all(&feature_cache)?;
        println!("Cache cleared for {}/{}/{}", owner, repository, name);
    } else {
        println!("No cache found for {}/{}/{}", owner, repository, name);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::devcontainer::{FeatureRegistryType, FeatureSource};

    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_download_feature() {
        let registry = FeatureRegistry {
            owner: "devcontainers".to_string(),
            repository: "features".to_string(),
            name: "node".to_string(),
            version: "1.0.0".to_string(),
            registry_type: FeatureRegistryType::Ghcr,
        };
        let temp_dir = tempdir().unwrap();
        let result = download_feature(&registry);
        assert!(
            result.is_ok(),
            "Failed to download feature: {:?}",
            result.err()
        );
        let relative_path = result.unwrap();
        let feature_path = temp_dir.path().join(&relative_path);
        assert!(feature_path.exists());
    }

    #[test]
    fn test_process_feature() {
        let feature_ref = FeatureRef::new(FeatureSource::Registry {
            registry: FeatureRegistry {
                owner: "devcontainers".to_string(),
                repository: "features".to_string(),
                name: "node".to_string(),
                version: "1.0.0".to_string(),
                registry_type: FeatureRegistryType::Ghcr,
            },
        });
        let result = process_feature(&feature_ref);
        assert!(
            result.is_ok(),
            "Failed to download feature: {:?}",
            result.err()
        );
        let feature_result = result.unwrap();
        let feature = feature_result.feature;
        // Check that default option exists
        if let Some(ref options) = feature.options {
            assert!(options.contains_key("version"));
        }
    }

    #[test]
    fn test_process_feature_default() {
        let feature_ref = FeatureRef::new(FeatureSource::Registry {
            registry: FeatureRegistry {
                owner: "devcontainers".to_string(),
                repository: "features".to_string(),
                name: "node".to_string(),
                version: "1.0.0".to_string(),
                registry_type: FeatureRegistryType::Ghcr,
            },
        });
        let result = process_feature(&feature_ref);
        assert!(
            result.is_ok(),
            "Failed to download feature: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_topological_sort_simple() {
        // Create mock features with dependencies
        let mut features = HashMap::new();

        // Feature A (no dependencies)
        let feature_a = create_mock_feature("feature-a", None, None);
        features.insert("feature-a".to_string(), feature_a);

        // Feature B depends on A
        let mut depends_on_b = HashMap::new();
        depends_on_b.insert("feature-a".to_string(), serde_json::json!("1.0.0"));
        let feature_b = create_mock_feature("feature-b", Some(depends_on_b), None);
        features.insert("feature-b".to_string(), feature_b);

        // Feature C depends on B
        let mut depends_on_c = HashMap::new();
        depends_on_c.insert("feature-b".to_string(), serde_json::json!("1.0.0"));
        let feature_c = create_mock_feature("feature-c", Some(depends_on_c), None);
        features.insert("feature-c".to_string(), feature_c);

        let result = topological_sort(features);
        assert!(
            result.is_ok(),
            "Topological sort failed: {:?}",
            result.err()
        );

        let sorted = result.unwrap();
        assert_eq!(sorted.len(), 3);

        // Verify order: A should come before B, B should come before C
        let ids: Vec<String> = sorted.iter().map(|f| f.feature.id.clone()).collect();
        let pos_a = ids.iter().position(|id| id == "feature-a").unwrap();
        let pos_b = ids.iter().position(|id| id == "feature-b").unwrap();
        let pos_c = ids.iter().position(|id| id == "feature-c").unwrap();

        assert!(pos_a < pos_b, "Feature A should come before B");
        assert!(pos_b < pos_c, "Feature B should come before C");
    }

    #[test]
    fn test_topological_sort_installs_after() {
        let mut features = HashMap::new();

        // Feature A
        let feature_a = create_mock_feature("feature-a", None, None);
        features.insert("feature-a".to_string(), feature_a);

        // Feature B installs after A
        let installs_after_b = vec!["feature-a".to_string()];
        let feature_b = create_mock_feature("feature-b", None, Some(installs_after_b));
        features.insert("feature-b".to_string(), feature_b);

        let result = topological_sort(features);
        assert!(result.is_ok());

        let sorted = result.unwrap();
        let ids: Vec<String> = sorted.iter().map(|f| f.feature.id.clone()).collect();
        let pos_a = ids.iter().position(|id| id == "feature-a").unwrap();
        let pos_b = ids.iter().position(|id| id == "feature-b").unwrap();

        assert!(pos_a < pos_b, "Feature A should come before B");
    }

    #[test]
    fn test_topological_sort_circular_dependency() {
        let mut features = HashMap::new();

        // Feature A depends on B
        let mut depends_on_a = HashMap::new();
        depends_on_a.insert("feature-b".to_string(), serde_json::json!("1.0.0"));
        let feature_a = create_mock_feature("feature-a", Some(depends_on_a), None);
        features.insert("feature-a".to_string(), feature_a);

        // Feature B depends on A (circular!)
        let mut depends_on_b = HashMap::new();
        depends_on_b.insert("feature-a".to_string(), serde_json::json!("1.0.0"));
        let feature_b = create_mock_feature("feature-b", Some(depends_on_b), None);
        features.insert("feature-b".to_string(), feature_b);

        let result = topological_sort(features);
        assert!(result.is_err(), "Should detect circular dependency");

        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Circular dependency"),
            "Error should mention circular dependency"
        );
    }

    #[test]
    fn test_topological_sort_diamond_dependency() {
        // Diamond pattern: D depends on B and C, both B and C depend on A
        let mut features = HashMap::new();

        // Feature A (base)
        let feature_a = create_mock_feature("feature-a", None, None);
        features.insert("feature-a".to_string(), feature_a);

        // Feature B depends on A
        let mut depends_on_b = HashMap::new();
        depends_on_b.insert("feature-a".to_string(), serde_json::json!("1.0.0"));
        let feature_b = create_mock_feature("feature-b", Some(depends_on_b), None);
        features.insert("feature-b".to_string(), feature_b);

        // Feature C depends on A
        let mut depends_on_c = HashMap::new();
        depends_on_c.insert("feature-a".to_string(), serde_json::json!("1.0.0"));
        let feature_c = create_mock_feature("feature-c", Some(depends_on_c), None);
        features.insert("feature-c".to_string(), feature_c);

        // Feature D depends on B and C
        let mut depends_on_d = HashMap::new();
        depends_on_d.insert("feature-b".to_string(), serde_json::json!("1.0.0"));
        depends_on_d.insert("feature-c".to_string(), serde_json::json!("1.0.0"));
        let feature_d = create_mock_feature("feature-d", Some(depends_on_d), None);
        features.insert("feature-d".to_string(), feature_d);

        let result = topological_sort(features);
        assert!(result.is_ok());

        let sorted = result.unwrap();
        let ids: Vec<String> = sorted.iter().map(|f| f.feature.id.clone()).collect();

        let pos_a = ids.iter().position(|id| id == "feature-a").unwrap();
        let pos_b = ids.iter().position(|id| id == "feature-b").unwrap();
        let pos_c = ids.iter().position(|id| id == "feature-c").unwrap();
        let pos_d = ids.iter().position(|id| id == "feature-d").unwrap();

        // A must come before both B and C
        assert!(pos_a < pos_b, "A should come before B");
        assert!(pos_a < pos_c, "A should come before C");
        // Both B and C must come before D
        assert!(pos_b < pos_d, "B should come before D");
        assert!(pos_c < pos_d, "C should come before D");
    }

    // Helper function to create mock feature results
    fn create_mock_feature(
        id: &str,
        depends_on: Option<HashMap<String, serde_json::Value>>,
        installs_after: Option<Vec<String>>,
    ) -> FeatureProcessResult {
        use std::path::PathBuf;

        let feature = crate::feature::Feature {
            id: id.to_string(),
            version: "1.0.0".to_string(),
            name: Some(format!("Mock {}", id)),
            description: None,
            documentation_url: None,
            license_url: None,
            keywords: None,
            options: None,
            installs_after,
            depends_on,
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
}
