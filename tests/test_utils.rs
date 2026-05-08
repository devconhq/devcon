use std::process::Command;
use tempfile::TempDir;

/// Represents a container runtime type
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Runtime {
    Docker,
    Apple,
}

/// Get the runtime to use for tests from environment variable
pub fn get_runtime() -> Runtime {
    match std::env::var("CONTAINER_RUNTIME")
        .unwrap_or_else(|_| "docker".to_string())
        .as_str()
    {
        "apple" => Runtime::Apple,
        _ => Runtime::Docker,
    }
}

/// Get the runtime command name
pub fn runtime_cmd(runtime: Runtime) -> &'static str {
    match runtime {
        Runtime::Docker => "docker",
        Runtime::Apple => "container",
    }
}

/// Check if a runtime is available
pub fn is_runtime_available(runtime: Runtime) -> bool {
    Command::new(runtime_cmd(runtime))
        .arg("--version")
        .output()
        .is_ok()
}

/// Create an empty test config file in a temp directory
/// Returns the path to the config file
pub fn create_test_config() -> std::path::PathBuf {
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("test-config.yaml");

    // Create an empty or minimal config
    std::fs::write(&config_path, "# Test config\nagents:\n    disable: true")
        .expect("Failed to write test config");

    // We need to leak the temp_dir to keep it alive for the test duration
    // This is acceptable for tests as they're short-lived
    std::mem::forget(temp_dir);

    config_path
}

/// Create a test devcontainer with the given configuration
pub fn create_test_devcontainer(name: &str, image: &str, features: Option<&str>) -> TempDir {
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let devcontainer_path = temp_dir.path().join(".devcontainer");
    std::fs::create_dir_all(&devcontainer_path).expect("Failed to create .devcontainer dir");

    let features_json = features.unwrap_or("{}");
    let container_content = format!(
        r#"{{
    "name": "{}",
    "image": "{}",
    "features": {}
}}"#,
        name, image, features_json
    );

    std::fs::write(
        devcontainer_path.join("devcontainer.json"),
        container_content,
    )
    .expect("Failed to write devcontainer.json");

    temp_dir
}

/// Create a test devcontainer with a Dockerfile
pub fn create_test_devcontainer_with_dockerfile(name: &str, dockerfile_content: &str) -> TempDir {
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let devcontainer_path = temp_dir.path().join(".devcontainer");
    std::fs::create_dir_all(&devcontainer_path).expect("Failed to create .devcontainer dir");

    let container_content = format!(
        r#"{{
    "name": "{}",
    "build": {{
        "dockerfile": "Dockerfile"
    }}
}}"#,
        name
    );

    std::fs::write(
        devcontainer_path.join("devcontainer.json"),
        container_content,
    )
    .expect("Failed to write devcontainer.json");

    std::fs::write(devcontainer_path.join("Dockerfile"), dockerfile_content)
        .expect("Failed to write Dockerfile");

    temp_dir
}

/// Create a test devcontainer with lifecycle hooks
pub fn create_test_devcontainer_with_hooks(
    name: &str,
    image: &str,
    on_create: Option<&str>,
    post_create: Option<&str>,
) -> TempDir {
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let devcontainer_path = temp_dir.path().join(".devcontainer");
    std::fs::create_dir_all(&devcontainer_path).expect("Failed to create .devcontainer dir");

    let mut config = serde_json::json!({
        "name": name,
        "image": image,
    });

    if let Some(cmd) = on_create {
        config["onCreateCommand"] = serde_json::json!(cmd);
    }

    if let Some(cmd) = post_create {
        config["postCreateCommand"] = serde_json::json!(cmd);
    }

    let container_content =
        serde_json::to_string_pretty(&config).expect("Failed to serialize config");

    std::fs::write(
        devcontainer_path.join("devcontainer.json"),
        container_content,
    )
    .expect("Failed to write devcontainer.json");

    temp_dir
}

/// Verify that a container image exists
pub fn verify_image_exists(runtime: Runtime, image_name: &str) -> bool {
    let cmd = runtime_cmd(runtime);
    let format = match runtime {
        Runtime::Docker => "{{.Repository}}:{{.Tag}}",
        Runtime::Apple => "json",
    };

    let output = Command::new(cmd)
        .arg("image")
        .arg("list")
        .arg("--format")
        .arg(format)
        .output()
        .expect("Failed to list images");

    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout.lines().any(|line| line.contains(image_name))
}

/// Get the container name/ID from devcon output
#[allow(dead_code)]
pub fn extract_container_name(output: &str) -> Option<String> {
    // Look for container name in output - this is a simple heuristic
    // May need to be adjusted based on actual devcon output format
    for line in output.lines() {
        if line.contains("Container") || line.contains("container") {
            // Extract container name/ID - adjust pattern as needed
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(name) = parts.last() {
                return Some(name.to_string());
            }
        }
    }
    None
}

/// Stop a running container
#[allow(dead_code)]
pub fn stop_container(runtime: Runtime, container_id: &str) {
    let cmd = runtime_cmd(runtime);
    let _ = Command::new(cmd)
        .arg("stop")
        .arg(container_id)
        .output();
}

/// Remove all containers and images belonging to a devcon test project.
///
/// Stops and force-removes any containers labelled `devcon.project=<project_name>`,
/// then removes all images whose repository matches `devcon-<project_name>`.
/// Call this at the start of tests that create containers so stale state from
/// previous runs does not interfere.
#[allow(dead_code)]
pub fn cleanup_test_artifacts(runtime: Runtime, project_name: &str) {
    let cmd = runtime_cmd(runtime);
    let label = format!("devcon.project={}", project_name);
    let image_prefix = format!("devcon-{}", project_name);

    match runtime {
        Runtime::Docker => {
            // Find all containers (running or stopped) for this project
            let ps_output = Command::new(cmd)
                .args(["ps", "-a", "--filter", &format!("label={}", label), "--format", "{{.ID}}"])
                .output();
            if let Ok(out) = ps_output {
                let ids = String::from_utf8_lossy(&out.stdout);
                for id in ids.lines().map(str::trim).filter(|s| !s.is_empty()) {
                    let _ = Command::new(cmd).args(["rm", "-f", id]).output();
                }
            }

            // Remove all images for this project (latest + any build-* tags)
            let img_output = Command::new(cmd)
                .args(["image", "ls", "--format", "{{.Repository}}:{{.Tag}}"])
                .output();
            if let Ok(out) = img_output {
                let tags = String::from_utf8_lossy(&out.stdout);
                for tag in tags.lines().map(str::trim).filter(|t| t.starts_with(&image_prefix)) {
                    let _ = Command::new(cmd).args(["rmi", "-f", tag]).output();
                }
            }
        }
        Runtime::Apple => {
            // Apple: list all containers and filter by name prefix
            let ls_output = Command::new(cmd)
                .args(["container", "list", "--all", "--format", "json"])
                .output();
            if let Ok(out) = ls_output
                && let Ok(entries) = serde_json::from_slice::<Vec<serde_json::Value>>(&out.stdout)
            {
                for entry in entries {
                    let name = entry["name"].as_str().unwrap_or("");
                    // devcon container name is devcon.<project_name>
                    if name == format!("devcon.{}", project_name) {
                        let _ = Command::new(cmd).args(["container", "rm", "-f", name]).output();
                    }
                }
            }
            // Remove images
            let img_output = Command::new(cmd).args(["image", "list", "--format", "json"]).output();
            if let Ok(out) = img_output
                && let Ok(entries) = serde_json::from_slice::<Vec<serde_json::Value>>(&out.stdout)
            {
                for entry in entries {
                    let repo = entry["repository"].as_str().unwrap_or("");
                    let tag = entry["tag"].as_str().unwrap_or("");
                    let full = format!("{}:{}", repo, tag);
                    if full.starts_with(&image_prefix) {
                        let _ = Command::new(cmd).args(["image", "rm", "-f", &full]).output();
                    }
                }
            }
        }
    }
}

/// Clean up a container by name
#[allow(dead_code)]
pub fn cleanup_container(runtime: Runtime, container_name: &str) {
    let cmd = runtime_cmd(runtime);
    let _ = Command::new(cmd)
        .arg("rm")
        .arg("-f")
        .arg(container_name)
        .output();
}

/// Clean up an image by name
#[allow(dead_code)]
pub fn cleanup_image(runtime: Runtime, image_name: &str) {
    let cmd = runtime_cmd(runtime);
    let subcommand = match runtime {
        Runtime::Docker => "rmi",
        Runtime::Apple => "image",
    };

    let mut cmd_builder = Command::new(cmd);
    cmd_builder.arg(subcommand);

    if runtime == Runtime::Apple {
        cmd_builder.arg("rm");
    }

    cmd_builder.arg("-f").arg(image_name);
    let _ = cmd_builder.output();
}

/// Execute a command inside a running container
pub fn exec_in_container(
    runtime: Runtime,
    container_name: &str,
    command: &[&str],
) -> Result<String, String> {
    let cmd = runtime_cmd(runtime);
    let mut cmd_builder = Command::new(cmd);
    cmd_builder.arg("exec").arg(container_name);

    for arg in command {
        cmd_builder.arg(arg);
    }

    let output = cmd_builder
        .output()
        .map_err(|e| format!("Failed to execute command: {}", e))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

/// Get the image ID for a given image tag, returns None if not found
#[allow(dead_code)]
pub fn get_image_id(runtime: Runtime, image_tag: &str) -> Option<String> {
    let cmd = runtime_cmd(runtime);
    let output = Command::new(cmd)
        .arg("image")
        .arg("inspect")
        .arg(image_tag)
        .arg("--format")
        .arg("{{.Id}}")
        .output()
        .ok()?;

    if output.status.success() {
        let id = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if id.is_empty() { None } else { Some(id) }
    } else {
        None
    }
}

/// Check if a container is running
#[allow(dead_code)]
pub fn is_container_running(runtime: Runtime, container_name: &str) -> bool {
    let cmd = runtime_cmd(runtime);
    let output = Command::new(cmd)
        .arg("ps")
        .arg("--filter")
        .arg(format!("name={}", container_name))
        .arg("--format")
        .arg("{{.Names}}")
        .output()
        .expect("Failed to check running containers");

    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout.lines().any(|line| line == container_name)
}

/// Generate a unique test image name
#[allow(dead_code)]
pub fn generate_test_image_name(test_name: &str) -> String {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    format!("devcon-test-{}:{}", test_name, timestamp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_runtime_default() {
        // Default should be docker
        unsafe {
            std::env::remove_var("CONTAINER_RUNTIME");
        }
        assert_eq!(get_runtime(), Runtime::Docker);
    }

    #[test]
    fn test_runtime_cmd() {
        assert_eq!(runtime_cmd(Runtime::Docker), "docker");
        assert_eq!(runtime_cmd(Runtime::Apple), "container");
    }
}
