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

//! # Dockerfile Build Context
//!
//! Manages the temporary build directory used when building devcontainer images.
//! The [`BuildContext`] struct owns the directory and exposes helpers for copying
//! features, writing the dotfiles helper script, and rendering the final
//! multi-stage Dockerfile.

use std::fs::{self, File};
use std::path::{Path, PathBuf};

use minijinja::Environment;
use tempfile::TempDir;
use tracing::{Level, debug, warn};

use crate::devcontainer::FeatureSource;
use crate::driver::feature_process::FeatureProcessResult;
use crate::error::{Error, Result};

/// Metadata required to render the features Dockerfile template.
pub(crate) struct DockerfileParams<'a> {
    pub base_image: &'a str,
    pub remote_user: &'a str,
    pub container_user: &'a str,
    pub remote_user_home: &'a str,
    pub container_user_home: &'a str,
    pub workspace_name: &'a str,
    pub runtime_host_address: &'a str,
    pub config_hash: &'a str,
    pub image_architecture: &'a str,
    pub feature_install: &'a str,
    pub env_setup: &'a str,
    pub dotfiles_setup: &'a str,
}

/// Owns the temporary directory that forms the `docker build` context.
///
/// Drop this value to delete the directory (unless it was kept for debugging).
pub(crate) struct BuildContext {
    /// Path to the build directory; valid for the lifetime of this value.
    pub dir: PathBuf,
    _temp: Option<TempDir>,
}

impl BuildContext {
    /// Creates a new build context, optionally rooted at `build_path`.
    ///
    /// When `build_path` is `None` a system temp directory is used.
    /// In debug builds the directory is kept on disk (not cleaned up) so
    /// the generated Dockerfile can be inspected.
    pub(crate) fn new(build_path: Option<PathBuf>) -> Result<Self> {
        let temp = match build_path {
            Some(path) => {
                std::fs::create_dir_all(&path)?;
                TempDir::new_in(path)?
            }
            None => TempDir::new()?,
        };

        let dir = if tracing::event_enabled!(Level::DEBUG) {
            temp.keep()
        } else {
            temp.path().to_path_buf()
        };

        Ok(Self { dir, _temp: None })
    }

    /// Copies a feature directory into the build context and writes the
    /// `devcontainer-features.env` file with merged options.
    ///
    /// Returns the name of the copied directory (used in the Dockerfile `COPY`
    /// instruction).
    pub(crate) fn copy_feature(&self, process: &FeatureProcessResult) -> Result<String> {
        let feature_dest = self.dir.join(&process.feature.id);

        let mut options = fs_extra::dir::CopyOptions::new();
        options.overwrite = true;
        options.copy_inside = true;
        fs_extra::dir::copy(&process.path, &feature_dest, &options)
            .map_err(|e| Error::new(format!("Failed to copy feature directory: {}", e)))?;

        // Create env variable file with merged options (defaults + user overrides)
        let mut feature_options = serde_json::json!({});

        // Start with default values from feature definition
        if let Some(options_map) = &process.feature.options {
            for (key, option) in options_map {
                feature_options
                    .as_object_mut()
                    .unwrap()
                    .insert(key.clone(), option.default.clone());
            }
        }

        // Override with user-specified options from feature_ref
        if let Some(user_opts) = process.feature_ref.options.as_object() {
            for (key, value) in user_opts {
                feature_options
                    .as_object_mut()
                    .unwrap()
                    .insert(key.clone(), value.clone());
            }
        }

        // Create env variable file for feature installation
        let env_file_path = feature_dest.join("devcontainer-features.env");
        let mut env_file = File::create(&env_file_path)?;
        for (key, value) in feature_options.as_object().unwrap() {
            use std::io::Write;

            let val = if let Some(str_value) = value.as_str() {
                str_value
            } else if let Some(bool_value) = value.as_bool() {
                if bool_value { "true" } else { "false" }
            } else if let Some(num_value) = value.as_number() {
                &format!("{}", num_value)
            } else {
                ""
            };

            writeln!(env_file, "export {}={}", key.to_uppercase(), val)?;
        }

        Ok(feature_dest
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string())
    }

    /// Writes the dotfiles helper shell script into the build directory and
    /// returns the Dockerfile snippet that copies and chmod-s it.
    pub(crate) fn write_dotfiles_helper(&self) -> Result<String> {
        let dotfiles_helper_path = self.dir.join("dotfiles_helper.sh");
        let dotfiles_helper_content = r#"
#!/bin/sh
set -e
cd && git clone $1 .dotfiles && cd .dotfiles
if [ -n "$2" ]; then
    chmod +x $2
    ./$2 || true
else
    for f in install.sh setup.sh bootstrap.sh script/install.sh script/setup.sh script/bootstrap.sh
    do
        if [ -e $f ]
        then
            installCommand=$f
            break
        fi
    done

    if [ -n "$installCommand" ]; then
        chmod +x $installCommand
        ./$installCommand || true
    fi
fi
"#;

        fs::write(&dotfiles_helper_path, dotfiles_helper_content)?;
        Ok(
            "COPY dotfiles_helper.sh /dotfiles_helper.sh \nRUN chmod +x /dotfiles_helper.sh"
                .to_string(),
        )
    }

    /// Generates the multi-stage `COPY`+`RUN` snippet for all features.
    ///
    /// Each feature becomes its own stage so Docker can cache them independently.
    pub(crate) fn generate_feature_install_snippet(
        &self,
        processed_features: &[FeatureProcessResult],
    ) -> Result<String> {
        let mut feature_install = String::new();
        let mut i = 0usize;

        for feature_result in processed_features {
            let feature_path_name = self.copy_feature(feature_result)?;
            let feature_name = match &feature_result.feature_ref.source {
                FeatureSource::Registry { registry } => registry.name.clone(),
                FeatureSource::Local { path } => path
                    .canonicalize()?
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .to_string(),
            };

            if i == 0 {
                feature_install.push_str(&format!("FROM {} AS feature_0 \n", "base"));
            } else {
                feature_install.push_str(&format!("FROM feature_{} AS feature_{} \n", i - 1, i));
            }

            if let Some(env_vars) = &feature_result.feature.container_env {
                for env_var in env_vars {
                    feature_install.push_str(&format!("ENV {}={} \n", env_var.0, env_var.1));
                }
            }

            feature_install.push_str(&format!(
                "COPY {}/. /tmp/features/{}/ \n",
                feature_path_name, feature_name
            ));
            feature_install.push_str(&format!(
                "RUN chmod +x /tmp/features/{}/install.sh && . /tmp/features/{}/devcontainer-features.env && cd /tmp/features/{} && ./install.sh\n",
                feature_name, feature_name, feature_name
            ));

            i += 1;
        }

        if i > 0 {
            feature_install.push_str(&format!("FROM feature_{} AS feature_last \n", i - 1));
        } else {
            feature_install.push_str("FROM base AS feature_last \n");
        }

        Ok(feature_install)
    }

    /// Renders the features Dockerfile template and writes it to the build directory.
    ///
    /// Returns the path to the written Dockerfile.
    pub(crate) fn write_dockerfile(&self, params: &DockerfileParams<'_>) -> Result<PathBuf> {
        let dockerfile = self.dir.join("Dockerfile");
        File::create(&dockerfile)?;

        let env = Environment::new();
        let template = env.template_from_str(
            r#"
FROM {{ image }} AS base

ENV DEVCON=true
ENV DEVCON_WORKSPACE_NAME={{ workspace_name }}
ENV _REMOTE_USER={{ remote_user }}
ENV _CONTAINER_USER={{ container_user }}
ENV _REMOTE_USER_HOME={{ remote_user_home }}
ENV _CONTAINER_USER_HOME={{ container_user_home }}
ENV DEVCON_CONTROL_HOST={{ runtime_host_address }}
LABEL devcon.config-hash={{ config_hash }}
LABEL devcon.image-architecture={{ image_architecture }}

USER root
RUN mkdir /tmp/features
{{ feature_install }}
{{ env_setup }}

FROM feature_last AS dotfiles_setup
{{ dotfiles_setup }}

FROM dotfiles_setup
USER {{ remote_user }}
WORKDIR /workspaces/{{ workspace_name }}
ENTRYPOINT [ "/bin/sh" ]
CMD ["-c", "echo Container started\ntrap \"exit 0\" 15\n\nexec \"$@\"\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nif command -v sleep >/dev/null 2>&1; then\n  while sleep 1 \u0026 wait $!; do :; done\nelif command -v tail >/dev/null 2>&1; then\n  tail -f /dev/null\nelse\n  while :; do ( : ) \u0026 wait $!; done\nfi", "-"]
"#,
        )?;

        let contents = template.render(minijinja::context! {
            image => params.base_image,
            remote_user => params.remote_user,
            container_user => params.container_user,
            remote_user_home => params.remote_user_home,
            container_user_home => params.container_user_home,
            feature_install => params.feature_install,
            dotfiles_setup => params.dotfiles_setup,
            env_setup => params.env_setup,
            workspace_name => params.workspace_name,
            runtime_host_address => params.runtime_host_address,
            config_hash => params.config_hash,
            image_architecture => params.image_architecture,
        })?;

        fs::write(&dockerfile, contents)?;
        Ok(dockerfile)
    }

    /// Path to the build directory.
    pub(crate) fn path(&self) -> &Path {
        &self.dir
    }
}

/// Applies a manual override to the feature installation order.
///
/// Reorders features according to the specified feature IDs, keeping any
/// features not mentioned in the override list at the end in their original order.
///
/// # Errors
///
/// Returns an error if a feature ID in the override list is not found.
pub(crate) fn apply_feature_order_override(
    features: Vec<FeatureProcessResult>,
    override_order: &[String],
) -> Result<Vec<FeatureProcessResult>> {
    let mut ordered = Vec::new();
    let mut remaining = features.clone();

    for feature_id in override_order {
        if let Some(pos) = remaining.iter().position(|f| &f.feature.id == feature_id) {
            ordered.push(remaining.remove(pos));
        } else {
            warn!(
                "Feature '{}' specified in overrideFeatureInstallOrder not found",
                feature_id
            );
        }
    }

    // Append any features not mentioned in the override order
    ordered.extend(remaining);

    debug!(
        "Applied override order. Final feature order: {:?}",
        ordered.iter().map(|f| &f.feature.id).collect::<Vec<_>>()
    );

    Ok(ordered)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devcontainer::{FeatureRegistry, FeatureRegistryType, FeatureSource};
    use crate::driver::feature_process::FeatureProcessResult;
    use crate::feature::Feature;

    fn make_feature_result(id: &str) -> FeatureProcessResult {
        let feature = Feature {
            id: id.to_string(),
            version: "1.0.0".to_string(),
            name: None,
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

    #[test]
    fn test_apply_feature_order_override_complete() {
        let features = vec![
            make_feature_result("a"),
            make_feature_result("b"),
            make_feature_result("c"),
        ];
        let override_order = vec!["c".to_string(), "a".to_string(), "b".to_string()];

        let result = apply_feature_order_override(features, &override_order).unwrap();
        assert_eq!(result[0].feature.id, "c");
        assert_eq!(result[1].feature.id, "a");
        assert_eq!(result[2].feature.id, "b");
    }

    #[test]
    fn test_apply_feature_order_override_partial() {
        let features = vec![
            make_feature_result("a"),
            make_feature_result("b"),
            make_feature_result("c"),
        ];
        let override_order = vec!["c".to_string()];

        let result = apply_feature_order_override(features, &override_order).unwrap();
        assert_eq!(result[0].feature.id, "c");
        // a and b follow in original order
        assert_eq!(result[1].feature.id, "a");
        assert_eq!(result[2].feature.id, "b");
    }

    #[test]
    fn test_apply_feature_order_override_empty() {
        let features = vec![make_feature_result("a"), make_feature_result("b")];
        let result = apply_feature_order_override(features, &[]).unwrap();
        assert_eq!(result[0].feature.id, "a");
        assert_eq!(result[1].feature.id, "b");
    }

    #[test]
    fn test_apply_feature_order_override_nonexistent() {
        let features = vec![make_feature_result("a")];
        // Non-existent IDs are warned about but not treated as errors
        let result = apply_feature_order_override(features, &["nonexistent".to_string()]).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].feature.id, "a");
    }

    #[test]
    fn test_copy_feature_options_include_different_options() {
        let temp_dir = tempfile::tempdir().unwrap();
        let feature_dir = temp_dir.path().join("myfeature");
        std::fs::create_dir_all(&feature_dir).unwrap();

        let feature = Feature {
            id: "base".to_string(),
            version: "1.0.0".to_string(),
            name: None,
            description: None,
            documentation_url: None,
            license_url: None,
            keywords: None,
            options: Some(
                serde_json::from_str(
                    r#"{
    "default": {
        "type": "string",
        "default": ""
    },
    "string": {
        "type": "string",
        "default": "test"
    },
    "bool": {
        "type": "boolean",
        "default": false
    }
}"#,
                )
                .unwrap(),
            ),
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

        let feature_ref = crate::devcontainer::FeatureRef::new(FeatureSource::Registry {
            registry: FeatureRegistry {
                owner: "devcontainers".to_string(),
                repository: "features".to_string(),
                name: "base".to_string(),
                version: "1".to_string(),
                registry_type: FeatureRegistryType::Ghcr,
            },
        });

        let process = FeatureProcessResult {
            feature,
            feature_ref,
            path: feature_dir.clone(),
        };

        let ctx = BuildContext {
            dir: temp_dir.path().to_path_buf(),
            _temp: None,
        };

        let result = ctx.copy_feature(&process);
        assert!(result.is_ok());
        assert!(
            std::fs::exists(
                temp_dir
                    .path()
                    .join("base")
                    .join("devcontainer-features.env")
            )
            .unwrap()
        );

        let content = std::fs::read_to_string(
            temp_dir
                .path()
                .join("base")
                .join("devcontainer-features.env"),
        )
        .unwrap();
        assert!(content.contains("export DEFAULT="));
        assert!(content.contains("export STRING=test"));
        assert!(content.contains("export BOOL=false"));
    }
}
