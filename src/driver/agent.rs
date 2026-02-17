use crate::error::{Error, Result};
use minijinja::Environment;
use serde::{Deserialize, Serialize};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

/// Configuration for generating a devcontainer feature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Feature ID (e.g., "my-feature")
    pub id: String,
    /// Feature version
    pub version: String,
    /// Feature name
    pub name: String,
    /// Feature description
    pub description: Option<String>,
    /// Install script content
    pub install_script: String,
    /// Additional options for the feature
    pub options: Option<serde_json::Value>,
    /// URL to download precompiled agent binary
    pub binary_url: Option<String>,
    /// Git repository URL for agent source
    pub git_repository: Option<String>,
    /// Git branch to checkout
    pub git_branch: Option<String>,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self::new(true, None, None, None)
    }
}

impl AgentConfig {
    /// Create a new AgentConfig with optional binary URL and git settings
    pub fn new(
        use_binary: bool,
        binary_url: Option<String>,
        git_repository: Option<String>,
        git_branch: Option<String>,
    ) -> Self {
        let env = Environment::new();
        let template = env
            .template_from_str(
                r###"#!/usr/bin/env bash

set -e
echo "Installing DevCon Agent..."

{% if use_binary %}
# Download precompiled binary

{% if binary_url %}
echo "Downloading precompiled agent from {{ binary_url }}..."
curl -L -o /usr/local/bin/devcon-agent "{{ binary_url }}"
{% else %}
echo "No binary URL provided, using default release from GitHub..."
arch=$(uname -m)
if [[ $arch == x86_64* ]]; then
    echo "X64 Architecture"
    enumerated_arch="x86_64"
elif [[ $arch == aarch64* ]] || [[ $arch == arm* ]]; then
    echo "ARM Architecture"
    enumerated_arch="arm64"
else
    echo "Unsupported architecture: $arch"
    exit 1
fi

curl -L -o /usr/local/bin/devcon-agent \
    "https://github.com/devconhq/devcon/releases/latest/download/devcon-agent-linux-${enumerated_arch}"

{% endif %}
chmod +x /usr/local/bin/devcon-agent
{% else %}
# Compile from source
echo "Compiling agent from source..."

echo $PATH

. "/usr/local/cargo/env" 

git clone {{ git_repository }} /tmp/devcon
cd /tmp/devcon
git checkout {{ git_branch }}
cargo b --release --workspace --bin devcon-agent
mv target/release/devcon-agent /usr/local/bin/devcon-agent
rm -rf /tmp/devcon
{% endif %}

echo '#!/bin/bash' > /usr/local/bin/devcon-browser
echo 'devcon-agent open-url $1' >> /usr/local/bin/devcon-browser
chmod +x /usr/local/bin/devcon-browser

echo "DevCon Agent installed successfully."
"###,
            )
            .expect("Failed to create template");

        let git_repo = match use_binary {
            false => Some(
                git_repository
                    .unwrap_or_else(|| "https://github.com/devconhq/devcon.git".to_string()),
            ),
            true => None,
        };

        let git_br = match use_binary {
            false => Some(git_branch.unwrap_or_else(|| "main".to_string())),
            true => None,
        };

        let contents = template
            .render(minijinja::context! {
                use_binary => use_binary,
                binary_url => binary_url,
                git_repository => git_repo,
                git_branch => git_br,
            })
            .expect("Could not create install script");

        Self {
            id: "devcon-agent".to_string(),
            version: "1.0.0".to_string(),
            name: "DevCon Agent".to_string(),
            description: Some("DevCon Agent for managing devcontainer features".to_string()),
            install_script: contents,
            options: None,
            binary_url,
            git_repository: git_repo,
            git_branch: git_br,
        }
    }
}

/// Agent for generating devcontainer features
pub struct Agent {
    config: AgentConfig,
}

impl Agent {
    /// Create a new Agent with the given configuration
    pub fn new(config: AgentConfig) -> Self {
        Self { config }
    }

    /// Generate the devcontainer feature in a temporary directory
    pub fn generate(&mut self) -> Result<PathBuf> {
        // Create temporary directory
        let temp_dir = TempDir::new().map_err(|e| {
            Error::new(format!("{}: {}", "Failed to create temporary directory", e))
        })?;
        let feature_dir = temp_dir.keep().join(&self.config.id);

        // Create feature directory
        std::fs::create_dir_all(&feature_dir)
            .map_err(|e| Error::new(format!("{}: {}", "Failed to create feature directory", e)))?;

        // Generate devcontainer-feature.json
        self.generate_feature_json(&feature_dir, self.config.binary_url.is_none())?;

        // Generate install.sh
        self.generate_install_script(&feature_dir)?;

        let path = feature_dir.clone();

        Ok(path)
    }

    /// Generate the devcontainer-feature.json file
    fn generate_feature_json(&self, feature_dir: &Path, compile_needed: bool) -> Result<()> {
        let mut feature_json = serde_json::json!({
            "id": self.config.id,
            "version": self.config.version,
            "name": self.config.name,
            "containerEnv": {
                "DEVCON_AGENT": "1",
                "BROWSER": "/usr/local/bin/devcon-browser"
            },
            "entrypoint": "/usr/local/bin/devcon-agent daemon",
        });

        if compile_needed {
            feature_json["dependsOn"]["ghcr.io/devcontainers/features/rust"] =
                serde_json::Value::Object(serde_json::Map::new());
            feature_json["dependsOn"]["ghcr.io/devcontainers-extra/features/protoc"] =
                serde_json::Value::Object(serde_json::Map::new());
        }

        if let Some(desc) = &self.config.description {
            feature_json["description"] = serde_json::Value::String(desc.clone());
        }

        if let Some(options) = &self.config.options {
            feature_json["options"] = options.clone();
        }

        let json_path = feature_dir.join("devcontainer-feature.json");
        let json_content = serde_json::to_string_pretty(&feature_json)
            .map_err(|e| Error::new(format!("{}: {}", "Failed to serialize feature JSON", e)))?;

        std::fs::write(&json_path, json_content).map_err(|e| {
            Error::new(format!(
                "{}: {}",
                "Failed to write devcontainer-feature.json", e
            ))
        })?;

        Ok(())
    }

    /// Generate the install.sh script
    fn generate_install_script(&self, feature_dir: &Path) -> Result<()> {
        let install_path = feature_dir.join("install.sh");
        std::fs::write(&install_path, &self.config.install_script)
            .map_err(|e| Error::new(format!("{}: {}", "Failed to write install.sh", e)))?;

        // Make install.sh executable on Unix systems
        #[cfg(unix)]
        {
            let mut perms = std::fs::metadata(&install_path)?.permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&install_path, perms)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_generation() {
        let config = AgentConfig {
            id: "test-feature".to_string(),
            version: "1.0.0".to_string(),
            name: "Test Feature".to_string(),
            description: Some("A test feature".to_string()),
            install_script: "#!/bin/bash\necho 'Installing...'".to_string(),
            options: None,
            binary_url: None,
            git_repository: None,
            git_branch: None,
        };

        let mut agent = Agent::new(config);
        let path = agent.generate().expect("Failed to generate feature");

        assert!(path.exists());
        assert!(path.join("devcontainer-feature.json").exists());
        assert!(path.join("install.sh").exists());
    }

    #[test]
    fn test_agent_with_binary_url() {
        let config = AgentConfig::new(
            true,
            Some("https://example.com/devcon-agent".to_string()),
            None,
            None,
        );

        assert!(config.binary_url.is_some());
        assert!(config.install_script.contains("curl"));
        assert!(
            config
                .install_script
                .contains("https://example.com/devcon-agent")
        );
    }

    #[test]
    fn test_agent_with_git_repository() {
        let config = AgentConfig::new(
            false,
            None,
            Some("https://github.com/custom/repo.git".to_string()),
            Some("develop".to_string()),
        );

        assert!(config.binary_url.is_none());
        assert!(config.install_script.contains("git clone"));
        assert!(
            config
                .install_script
                .contains("https://github.com/custom/repo.git")
        );
        assert!(config.install_script.contains("git checkout develop"));
    }

    #[test]
    fn test_agent_default_values() {
        let config = AgentConfig::default();

        assert!(config.binary_url.is_none());
        assert!(config.git_repository.is_none());
        assert!(config.git_branch.is_none());
        assert!(config.install_script.contains("curl"));
    }

    #[test]
    fn test_agent_with_binary_url_wont_install_dependencies() {
        let config = AgentConfig::new(
            true,
            Some("https://example.com/devcon-agent".to_string()),
            None,
            None,
        );

        assert!(config.binary_url.is_some());
        let mut agent = Agent::new(config);
        let path = agent.generate().expect("Failed to generate configuration");
        let content = std::fs::read_to_string(path.join("devcontainer-feature.json"))
            .expect("Failed to read feature JSON");

        assert!(!content.contains("ghcr.io/devcontainers/features/rust"));
        assert!(!content.contains("ghcr.io/devcontainers-extra/features/protoc"));
    }

    #[test]
    fn test_agent_with_agent_compile_will_install_dependencies() {
        let config = AgentConfig::new(false, None, None, None);

        assert!(config.binary_url.is_none());
        let mut agent = Agent::new(config);
        let path = agent.generate().expect("Failed to generate configuration");
        let content = std::fs::read_to_string(path.join("devcontainer-feature.json"))
            .expect("Failed to read feature JSON");

        assert!(content.contains("ghcr.io/devcontainers/features/rust"));
        assert!(content.contains("ghcr.io/devcontainers-extra/features/protoc"));
    }
}
