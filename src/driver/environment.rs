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

//! # Environment Composition
//!
//! Helpers for building the container environment variable map from multiple
//! sources: the base image, devcontainer features, `devcontainer.json`, and
//! explicit overrides supplied at start time.

use std::collections::HashMap;

use tracing::{debug, warn};

use crate::driver::feature_process::FeatureProcessResult;
use crate::driver::runtime::{ContainerProbeInfo, ContainerRuntime};

/// Builds the base environment map for a container image.
///
/// Merges the static env vars baked into the image (`docker inspect`) with any
/// runtime-probed PATH discovered by `probe_image_info`.  The probed PATH
/// always wins over the inspected one when both are present.
pub(crate) fn base_container_environment(
    runtime: &dyn ContainerRuntime,
    image_tag: &str,
    probe_info: Option<&ContainerProbeInfo>,
) -> HashMap<String, String> {
    let mut env = HashMap::new();

    match runtime.inspect_image(image_tag) {
        Ok(Some(inspect)) => {
            for raw in &inspect.config.env {
                let Some((key, value)) = raw.split_once('=') else {
                    continue;
                };
                env.insert(key.to_string(), value.to_string());
            }
        }
        Ok(None) => {
            debug!(
                "Image '{}' could not be inspected before PATH probing; using probe only",
                image_tag
            );
        }
        Err(err) => {
            warn!(
                "Failed to inspect image '{}' for base container environment: {}",
                image_tag, err
            );
        }
    }

    if let Some(info) = probe_info {
        if !info.path.is_empty() {
            debug!("Using probed PATH from image: {}", info.path);
            env.insert("PATH".to_string(), info.path.clone());
        }
    } else {
        debug!(
            "No probe info available for '{}'; using inspected PATH if present",
            image_tag
        );
    }

    env
}

/// Resolves a single env-value string, expanding `${containerEnv:VAR}`,
/// `${localEnv:VAR}`, and bare `${VAR}` references.
pub(crate) fn resolve_container_env_value(
    raw_value: &str,
    merged_env: &HashMap<String, String>,
    host_env: &HashMap<String, String>,
) -> String {
    let mut resolved = String::new();
    let mut index = 0;

    while let Some(rel_start) = raw_value[index..].find("${") {
        let start = index + rel_start;
        resolved.push_str(&raw_value[index..start]);

        let after_start = start + 2;
        let Some(rel_end) = raw_value[after_start..].find('}') else {
            resolved.push_str(&raw_value[start..]);
            return resolved;
        };
        let end = after_start + rel_end;

        let token = &raw_value[after_start..end];
        let replacement = if let Some(name) = token.strip_prefix("containerEnv:") {
            merged_env.get(name).cloned().unwrap_or_default()
        } else if let Some(name) = token.strip_prefix("localEnv:") {
            host_env.get(name).cloned().unwrap_or_default()
        } else {
            merged_env.get(token).cloned().unwrap_or_default()
        };

        resolved.push_str(&replacement);
        index = end + 1;
    }

    resolved.push_str(&raw_value[index..]);
    resolved
}

pub(crate) fn merge_container_env_map(
    merged_env: &mut HashMap<String, String>,
    source_env: &HashMap<String, String>,
    host_env: &HashMap<String, String>,
) {
    for (key, value) in source_env {
        let resolved = resolve_container_env_value(value, merged_env, host_env);
        merged_env.insert(key.clone(), resolved);
    }
}

/// Composes the final list of `KEY=VALUE` environment strings passed to
/// `container run`.
///
/// Merge order (later wins):
/// 1. Base image env (from `base_container_env`)
/// 2. Feature `containerEnv` (in feature order)
/// 3. `devcontainer.json` `containerEnv`
/// 4. Explicit `env_variables` overrides supplied at start time
pub(crate) fn compose_start_environment(
    processed_features: &[FeatureProcessResult],
    devcontainer_container_env: Option<&HashMap<String, String>>,
    env_variables: &[String],
    base_container_env: &HashMap<String, String>,
) -> Vec<String> {
    let mut merged_env = base_container_env.clone();
    let host_env: HashMap<String, String> = std::env::vars().collect();

    // Feature-provided containerEnv values are merged first in feature order.
    for feature_result in processed_features {
        if let Some(feature_env) = &feature_result.feature.container_env {
            merge_container_env_map(&mut merged_env, feature_env, &host_env);
        }
    }

    // Devcontainer containerEnv overrides feature defaults.
    if let Some(container_env) = devcontainer_container_env {
        merge_container_env_map(&mut merged_env, container_env, &host_env);
    }

    // Explicit env vars passed to start override prior values.
    for env_var in env_variables {
        if let Some((key, value)) = env_var.split_once('=') {
            let resolved = resolve_container_env_value(value, &merged_env, &host_env);
            merged_env.insert(key.to_string(), resolved);
        } else {
            let host_value = host_env.get(env_var).cloned().unwrap_or_default();
            merged_env.insert(env_var.clone(), host_value);
        }
    }

    merged_env
        .into_iter()
        .map(|(key, value)| format!("{}={}", key, value))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devcontainer::{FeatureRegistry, FeatureRegistryType, FeatureSource};
    use crate::driver::feature_process::FeatureProcessResult;
    use crate::feature::Feature;
    use std::collections::HashMap;
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

        FeatureProcessResult {
            feature,
            feature_ref: crate::devcontainer::FeatureRef::new(FeatureSource::Registry {
                registry: FeatureRegistry {
                    owner: "devcontainers".to_string(),
                    repository: "features".to_string(),
                    name: id.to_string(),
                    version: "1".to_string(),
                    registry_type: FeatureRegistryType::Ghcr,
                },
            }),
            path: PathBuf::from("/tmp/test"),
        }
    }

    fn env_vec_to_map(env_vars: Vec<String>) -> HashMap<String, String> {
        env_vars
            .into_iter()
            .filter_map(|e| {
                let mut parts = e.splitn(2, '=');
                let key = parts.next()?.to_string();
                let value = parts.next()?.to_string();
                Some((key, value))
            })
            .collect()
    }

    #[test]
    fn test_compose_start_environment_includes_feature_container_env() {
        let mut feature_a = create_test_feature_result("featureA");
        let mut feature_env = HashMap::new();
        feature_env.insert("MY_VAR".to_string(), "from_feature".to_string());
        feature_a.feature.container_env = Some(feature_env);

        let base_env = HashMap::new();
        let env = compose_start_environment(&[feature_a], None, &[], &base_env);

        let map = env_vec_to_map(env);
        assert_eq!(map.get("MY_VAR").map(String::as_str), Some("from_feature"));
    }

    #[test]
    fn test_compose_start_environment_config_overrides_feature_values() {
        let mut feature_a = create_test_feature_result("featureA");
        let mut feature_env = HashMap::new();
        feature_env.insert("MY_VAR".to_string(), "from_feature".to_string());
        feature_a.feature.container_env = Some(feature_env);

        let mut devcontainer_env = HashMap::new();
        devcontainer_env.insert("MY_VAR".to_string(), "from_devcontainer".to_string());

        let base_env = HashMap::new();
        let env = compose_start_environment(&[feature_a], Some(&devcontainer_env), &[], &base_env);

        let map = env_vec_to_map(env);
        assert_eq!(
            map.get("MY_VAR").map(String::as_str),
            Some("from_devcontainer")
        );
    }

    #[test]
    fn test_compose_start_environment_devcontainer_container_env_overrides_feature_values() {
        let mut feature_a = create_test_feature_result("featureA");
        let mut feature_b = create_test_feature_result("featureB");

        let mut env_a = HashMap::new();
        env_a.insert("MY_VAR".to_string(), "from_feature_a".to_string());
        env_a.insert("FEATURE_A_ONLY".to_string(), "only_a".to_string());
        feature_a.feature.container_env = Some(env_a);

        let mut env_b = HashMap::new();
        env_b.insert("MY_VAR".to_string(), "from_feature_b".to_string());
        env_b.insert("FEATURE_B_ONLY".to_string(), "only_b".to_string());
        feature_b.feature.container_env = Some(env_b);

        let mut devcontainer_env = HashMap::new();
        devcontainer_env.insert("MY_VAR".to_string(), "from_devcontainer".to_string());

        let base_env = HashMap::new();
        let env = compose_start_environment(
            &[feature_a, feature_b],
            Some(&devcontainer_env),
            &[],
            &base_env,
        );

        let map = env_vec_to_map(env);
        assert_eq!(
            map.get("MY_VAR").map(String::as_str),
            Some("from_devcontainer")
        );
        assert_eq!(
            map.get("FEATURE_A_ONLY").map(String::as_str),
            Some("only_a")
        );
        assert_eq!(
            map.get("FEATURE_B_ONLY").map(String::as_str),
            Some("only_b")
        );
    }
}
