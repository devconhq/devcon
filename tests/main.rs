mod test_utils;

use assert_cmd::cargo::cargo_bin_cmd;
use test_utils::*;

#[test]
fn test_build_simple() {
    let runtime = get_runtime();
    if !is_runtime_available(runtime) {
        println!("Skipping test: {:?} runtime not available", runtime);
        return;
    }

    let test_config = create_test_config();
    let temp_dir = create_test_devcontainer(
        "test-simple",
        "mcr.microsoft.com/devcontainers/base:ubuntu",
        None,
    );

    let mut cmd = cargo_bin_cmd!("devcon");
    let result = cmd
        .arg("--config")
        .arg(&test_config)
        .arg("build")
        .arg(temp_dir.path().to_str().unwrap())
        .output();

    assert!(result.is_ok(), "Failed to execute build command");
    let output = result.unwrap();
    assert!(
        output.status.success(),
        "Build command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_build_with_features() {
    let runtime = get_runtime();
    if !is_runtime_available(runtime) {
        println!("Skipping test: {:?} runtime not available", runtime);
        return;
    }

    let test_config = create_test_config();
    let features = r#"{"ghcr.io/devcontainers/features/node": {"version": "18"}}"#;
    let temp_dir = create_test_devcontainer(
        "test-features",
        "mcr.microsoft.com/devcontainers/base:ubuntu",
        Some(features),
    );

    let mut cmd = cargo_bin_cmd!("devcon");
    let result = cmd
        .arg("--config")
        .arg(&test_config)
        .arg("build")
        .arg(temp_dir.path().to_str().unwrap())
        .output();

    assert!(result.is_ok(), "Failed to execute build command");
    let output = result.unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "Build command failed.\nStdout: {}\nStderr: {}",
        stdout,
        stderr
    );

    // Verify that the feature was processed
    let combined = format!("{}\n{}", stdout, stderr);
    assert!(
        combined.contains("node") || combined.contains("Node"),
        "Build output does not mention node feature"
    );
}

#[test]
fn test_build_with_name() {
    let runtime = get_runtime();
    if !is_runtime_available(runtime) {
        println!("Skipping test: {:?} runtime not available", runtime);
        return;
    }

    let test_config = create_test_config();
    let temp_dir = create_test_devcontainer(
        "Test Devcontainer Name",
        "mcr.microsoft.com/devcontainers/base:ubuntu",
        None,
    );

    let mut cmd = cargo_bin_cmd!("devcon");
    let result = cmd
        .arg("--config")
        .arg(&test_config)
        .arg("build")
        .arg(temp_dir.path().to_str().unwrap())
        .output();

    assert!(result.is_ok(), "Failed to execute build command");
    let output = result.unwrap();
    assert!(
        output.status.success(),
        "Build command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_build_and_verify_image() {
    let runtime = get_runtime();
    if !is_runtime_available(runtime) {
        println!("Skipping test: {:?} runtime not available", runtime);
        return;
    }
    let test_config = create_test_config();

    let temp_dir = create_test_devcontainer(
        "test-verify",
        "mcr.microsoft.com/devcontainers/base:ubuntu",
        None,
    );

    let mut cmd = cargo_bin_cmd!("devcon");
    let result = cmd
        .arg("--config")
        .arg(&test_config)
        .arg("build")
        .arg(temp_dir.path().to_str().unwrap())
        .output();

    assert!(result.is_ok(), "Failed to execute build command");
    let output = result.unwrap();
    assert!(
        output.status.success(),
        "Build command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(verify_image_exists(runtime, "devcon-test-verify:latest"));
}

#[test]
fn test_build_with_dockerfile() {
    let runtime = get_runtime();
    if !is_runtime_available(runtime) {
        println!("Skipping test: {:?} runtime not available", runtime);
        return;
    }
    let test_config = create_test_config();

    let dockerfile_content = r#"FROM mcr.microsoft.com/devcontainers/base:ubuntu
RUN echo "Custom Dockerfile build" > /custom-marker.txt
"#;

    let temp_dir = create_test_devcontainer_with_dockerfile("test-dockerfile", dockerfile_content);

    let mut cmd = cargo_bin_cmd!("devcon");
    let result = cmd
        .arg("--config")
        .arg(&test_config)
        .arg("--output")
        .arg("json")
        .arg("up")
        .arg(temp_dir.path().to_str().unwrap())
        .output();

    assert!(result.is_ok(), "Failed to execute build command");
    let output = result.unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "Build command failed.\nStdout: {}\nStderr: {}",
        stdout,
        stderr
    );

    let output_json =
        serde_json::from_str::<serde_json::Value>(&stdout).expect("Output is not valid JSON");

    let container_id = output_json["container_id"]
        .as_str()
        .expect("Output JSON does not contain container_id");

    let container_output =
        exec_in_container(runtime, &container_id, &["cat", "/custom-marker.txt"]);
    assert!(
        container_output.is_ok(),
        "Failed to execute command in container"
    );
    let marker_content = &container_output.unwrap();
    assert!(
        marker_content.contains("Custom Dockerfile build"),
        "Dockerfile changes not present in container"
    );

    drop(temp_dir);
}

#[test]
fn test_build_with_lifecycle_hooks() {
    let runtime = get_runtime();
    if !is_runtime_available(runtime) {
        println!("Skipping test: {:?} runtime not available", runtime);
        return;
    }
    let test_config = create_test_config();

    let temp_dir = create_test_devcontainer_with_hooks(
        "test-hooks",
        "mcr.microsoft.com/devcontainers/base:ubuntu",
        Some("echo 'onCreate executed'"),
        Some("echo 'postCreate executed'"),
    );

    let mut cmd = cargo_bin_cmd!("devcon");
    let result = cmd
        .arg("--config")
        .arg(&test_config)
        .arg("build")
        .arg(temp_dir.path().to_str().unwrap())
        .output();

    assert!(result.is_ok(), "Failed to execute build command");
    let output = result.unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "Build command failed.\nStdout: {}\nStderr: {}",
        stdout,
        stderr
    );
}

#[test]
fn test_build_multiple_features() {
    let runtime = get_runtime();
    if !is_runtime_available(runtime) {
        println!("Skipping test: {:?} runtime not available", runtime);
        return;
    }
    let test_config = create_test_config();

    let features = r#"{
        "ghcr.io/devcontainers/features/git": {},
        "ghcr.io/devcontainers/features/github-cli": {}
    }"#;
    let temp_dir = create_test_devcontainer(
        "test-multi-features",
        "mcr.microsoft.com/devcontainers/base:ubuntu",
        Some(features),
    );

    let mut cmd = cargo_bin_cmd!("devcon");
    let result = cmd
        .arg("--config")
        .arg(&test_config)
        .arg("build")
        .arg(temp_dir.path().to_str().unwrap())
        .output();

    assert!(result.is_ok(), "Failed to execute build command");
    let output = result.unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "Build command failed.\nStdout: {}\nStderr: {}",
        stdout,
        stderr
    );

    // Verify both features were processed
    let combined = format!("{}\n{}", stdout, stderr);
    assert!(
        combined.contains("git") || combined.contains("Git"),
        "Build output does not mention git feature"
    );
}

#[test]
#[cfg(target_os = "macos")]
fn test_build_apple_runtime() {
    let runtime = Runtime::Apple;
    if !is_runtime_available(runtime) {
        println!("Skipping test: Apple runtime not available");
        return;
    }

    unsafe {
        std::env::set_var("CONTAINER_RUNTIME", "apple");
    }

    let test_config = create_test_config();
    let temp_dir = create_test_devcontainer(
        "test-apple",
        "mcr.microsoft.com/devcontainers/base:ubuntu",
        None,
    );

    // Apple container runtime has a bug with default temp directories
    // Use home directory as build path
    let home_dir = std::env::var("HOME").expect("HOME env var not set");

    let mut cmd = cargo_bin_cmd!("devcon");
    let result = cmd
        .arg("--config")
        .arg(&test_config)
        .arg("build")
        .arg("--build-path")
        .arg(&home_dir)
        .arg(temp_dir.path().to_str().unwrap())
        .output();

    unsafe {
        std::env::remove_var("CONTAINER_RUNTIME");
    }

    assert!(result.is_ok(), "Failed to execute build command");
    let output = result.unwrap();
    assert!(
        output.status.success(),
        "Build command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[cfg(target_os = "macos")]
fn test_build_apple_runtime_with_features() {
    let runtime = Runtime::Apple;
    if !is_runtime_available(runtime) {
        println!("Skipping test: Apple runtime not available");
        return;
    }
    let test_config = create_test_config();

    unsafe {
        std::env::set_var("CONTAINER_RUNTIME", "apple");
    }

    let features = r#"{"ghcr.io/devcontainers/features/git": {}}"#;
    let temp_dir = create_test_devcontainer(
        "test-apple-features",
        "mcr.microsoft.com/devcontainers/base:ubuntu",
        Some(features),
    );

    // Apple container runtime has a bug with default temp directories
    // Use home directory as build path
    let home_dir = std::env::var("HOME").expect("HOME env var not set");

    let mut cmd = cargo_bin_cmd!("devcon");
    let result = cmd
        .arg("--config")
        .arg(&test_config)
        .arg("build")
        .arg("--build-path")
        .arg(&home_dir)
        .arg(temp_dir.path().to_str().unwrap())
        .output();

    unsafe {
        std::env::remove_var("CONTAINER_RUNTIME");
    }

    assert!(result.is_ok(), "Failed to execute build command");
    let output = result.unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "Build command failed.\nStdout: {}\nStderr: {}",
        stdout,
        stderr
    );
}
