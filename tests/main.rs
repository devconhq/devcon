mod test_utils;

use assert_cmd::cargo::cargo_bin_cmd;
use serde_json::json;
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
    cleanup_test_artifacts(runtime, "test-dockerfile");
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
        .arg("-ddddd")
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

    let container_output = exec_in_container(runtime, container_id, &["cat", "/custom-marker.txt"]);
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
        Some(json!("echo 'onCreate executed'")),
        Some(json!("echo 'postCreate executed'")),
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
fn test_up_on_create_array_command_executes_without_shell_joining() {
    let runtime = get_runtime();
    if !is_runtime_available(runtime) {
        println!("Skipping test: {:?} runtime not available", runtime);
        return;
    }

    cleanup_test_artifacts(runtime, "test-array-hook");
    let test_config = create_test_config();
    let temp_dir = create_test_devcontainer_with_hooks(
        "test-array-hook",
        "mcr.microsoft.com/devcontainers/base:ubuntu",
        Some(json!(["touch", "/tmp/devcon-array-&&-literal"])),
        None,
    );

    let mut cmd = cargo_bin_cmd!("devcon");
    let result = cmd
        .arg("--config")
        .arg(&test_config)
        .arg("--output")
        .arg("json")
        .arg("up")
        .arg(temp_dir.path().to_str().unwrap())
        .output();

    assert!(result.is_ok(), "Failed to execute up command");
    let output = result.unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "Up command failed.\nStdout: {}\nStderr: {}",
        stdout,
        stderr
    );

    let output_json =
        serde_json::from_str::<serde_json::Value>(&stdout).expect("Output is not valid JSON");
    let container_id = output_json["container_id"]
        .as_str()
        .expect("Output JSON does not contain container_id");

    let file_check = exec_in_container(
        runtime,
        container_id,
        &["test", "-f", "/tmp/devcon-array-&&-literal"],
    );
    assert!(
        file_check.is_ok(),
        "Array lifecycle command should be passed through as literal argv, not shell text"
    );

    drop(temp_dir);
}

#[test]
fn test_up_on_create_object_array_values_execute_directly() {
    let runtime = get_runtime();
    if !is_runtime_available(runtime) {
        println!("Skipping test: {:?} runtime not available", runtime);
        return;
    }

    cleanup_test_artifacts(runtime, "test-object-hook");
    let test_config = create_test_config();
    let temp_dir = create_test_devcontainer_with_hooks(
        "test-object-hook",
        "mcr.microsoft.com/devcontainers/base:ubuntu",
        Some(json!({
            "first": ["touch", "/tmp/devcon-object-first-&&-literal"],
            "second": ["touch", "/tmp/devcon-object-second-&&-literal"]
        })),
        None,
    );

    let mut cmd = cargo_bin_cmd!("devcon");
    let result = cmd
        .arg("--config")
        .arg(&test_config)
        .arg("--output")
        .arg("json")
        .arg("up")
        .arg(temp_dir.path().to_str().unwrap())
        .output();

    assert!(result.is_ok(), "Failed to execute up command");
    let output = result.unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "Up command failed.\nStdout: {}\nStderr: {}",
        stdout,
        stderr
    );

    let output_json =
        serde_json::from_str::<serde_json::Value>(&stdout).expect("Output is not valid JSON");
    let container_id = output_json["container_id"]
        .as_str()
        .expect("Output JSON does not contain container_id");

    for path in [
        "/tmp/devcon-object-first-&&-literal",
        "/tmp/devcon-object-second-&&-literal",
    ] {
        let file_check = exec_in_container(runtime, container_id, &["test", "-f", path]);
        assert!(
            file_check.is_ok(),
            "Object lifecycle array value should execute directly for path {}",
            path
        );
    }

    drop(temp_dir);
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

/// Regression test for https://github.com/devconhq/devcon/issues/82.
///
/// `mcr.microsoft.com/devcontainers/base:ubuntu` sets `Config.User = "root"` in its Docker image
/// metadata but embeds `"remoteUser": "vscode"` in the OCI label `devcontainer.metadata`.
/// devcon must read that label so the container's `_REMOTE_USER` resolves to `"vscode"`, not
/// `"root"`.
#[test]
fn test_up_microsoft_devcontainer_base_resolves_remote_user() {
    let runtime = get_runtime();
    if !is_runtime_available(runtime) {
        println!("Skipping test: {:?} runtime not available", runtime);
        return;
    }

    cleanup_test_artifacts(runtime, "test-remote-user-base");
    let test_config = create_test_config();
    let temp_dir = create_test_devcontainer(
        "test-remote-user-base",
        "mcr.microsoft.com/devcontainers/base:ubuntu",
        None,
    );

    let mut cmd = cargo_bin_cmd!("devcon");
    let result = cmd
        .arg("--config")
        .arg(&test_config)
        .arg("--output")
        .arg("json")
        .arg("up")
        .arg(temp_dir.path().to_str().unwrap())
        .output();

    assert!(result.is_ok(), "Failed to execute up command");
    let output = result.unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "Up command failed.\nStdout: {}\nStderr: {}",
        stdout,
        stderr
    );

    let output_json =
        serde_json::from_str::<serde_json::Value>(&stdout).expect("Output is not valid JSON");
    let container_id = output_json["container_id"]
        .as_str()
        .expect("Output JSON does not contain container_id");

    // The Dockerfile layer written by devcon injects `ENV _REMOTE_USER=<resolved_user>`.
    // For this image the devcontainer.metadata label specifies remoteUser=vscode, so devcon
    // must resolve to "vscode" rather than falling back to the raw Config.User value ("root").
    let user_output = exec_in_container(runtime, container_id, &["printenv", "_REMOTE_USER"]);
    assert!(
        user_output.is_ok(),
        "Failed to read _REMOTE_USER inside container"
    );
    let remote_user = user_output.unwrap().trim().to_string();
    assert_eq!(
        remote_user, "vscode",
        "Expected _REMOTE_USER='vscode' (from devcontainer.metadata label) but got '{}'",
        remote_user
    );

    drop(temp_dir);
}

#[test]
fn test_up_with_custom_agent_ssh_port_uses_2222() {
    let runtime = get_runtime();
    if !is_runtime_available(runtime) {
        println!("Skipping test: {:?} runtime not available", runtime);
        return;
    }

    cleanup_test_artifacts(runtime, "test-ssh-port-override");
    let test_config = create_test_config_with_contents(
        "agents:\n  disable: false\n  sshPort: 2222\n  skipSshSetup: false\n",
    );
    let temp_dir = create_test_devcontainer(
        "test-ssh-port-override",
        "mcr.microsoft.com/devcontainers/base:ubuntu",
        None,
    );

    let mut up_cmd = cargo_bin_cmd!("devcon");
    let up_result = up_cmd
        .arg("--config")
        .arg(&test_config)
        .arg("--output")
        .arg("json")
        .arg("up")
        .arg(temp_dir.path().to_str().unwrap())
        .output();

    assert!(up_result.is_ok(), "Failed to execute up command");
    let up_output = up_result.unwrap();
    assert!(
        up_output.status.success(),
        "Up command failed: {}",
        String::from_utf8_lossy(&up_output.stderr)
    );

    let mut ssh_proxy_ok_cmd = cargo_bin_cmd!("devcon");
    let ssh_proxy_ok = ssh_proxy_ok_cmd
        .arg("--config")
        .arg(&test_config)
        .arg("ssh")
        .arg("connect")
        .arg(temp_dir.path().to_str().unwrap())
        .arg("--proxy")
        .output();

    assert!(
        ssh_proxy_ok.is_ok(),
        "Failed to execute ssh connect --proxy"
    );
    let ssh_proxy_ok_output = ssh_proxy_ok.unwrap();
    assert!(
        ssh_proxy_ok_output.status.success(),
        "ssh connect --proxy with sshPort=2222 failed: {}",
        String::from_utf8_lossy(&ssh_proxy_ok_output.stderr)
    );

    let wrong_port_config = create_test_config_with_contents("agents:\n  disable: false\n");
    let mut ssh_proxy_fail_cmd = cargo_bin_cmd!("devcon");
    let ssh_proxy_fail = ssh_proxy_fail_cmd
        .arg("--config")
        .arg(&wrong_port_config)
        .arg("ssh")
        .arg("connect")
        .arg(temp_dir.path().to_str().unwrap())
        .arg("--proxy")
        .output();

    assert!(
        ssh_proxy_fail.is_ok(),
        "Failed to execute ssh connect --proxy with wrong port config"
    );
    let ssh_proxy_fail_output = ssh_proxy_fail.unwrap();
    assert!(
        !ssh_proxy_fail_output.status.success(),
        "ssh connect --proxy unexpectedly succeeded when looking for port 22"
    );
    assert!(
        String::from_utf8_lossy(&ssh_proxy_fail_output.stderr)
            .contains("Container SSH port 22 is not mapped"),
        "Expected missing port 22 mapping error, got: {}",
        String::from_utf8_lossy(&ssh_proxy_fail_output.stderr)
    );

    drop(temp_dir);
}

#[test]
fn test_up_with_skip_agent_ssh_setup_skips_forwarding_and_sshd() {
    let runtime = get_runtime();
    if !is_runtime_available(runtime) {
        println!("Skipping test: {:?} runtime not available", runtime);
        return;
    }

    cleanup_test_artifacts(runtime, "test-skip-ssh-setup");
    let test_config =
        create_test_config_with_contents("agents:\n  disable: false\n  skipSshSetup: true\n");
    let temp_dir = create_test_devcontainer(
        "test-skip-ssh-setup",
        "mcr.microsoft.com/devcontainers/base:ubuntu",
        None,
    );

    let mut up_cmd = cargo_bin_cmd!("devcon");
    let up_result = up_cmd
        .arg("--config")
        .arg(&test_config)
        .arg("up")
        .arg(temp_dir.path().to_str().unwrap())
        .output();

    assert!(up_result.is_ok(), "Failed to execute up command");
    let up_output = up_result.unwrap();
    let stdout = String::from_utf8_lossy(&up_output.stdout);
    let stderr = String::from_utf8_lossy(&up_output.stderr);
    assert!(
        up_output.status.success(),
        "Up command failed.\nStdout: {}\nStderr: {}",
        stdout,
        stderr
    );
    let container_id = get_running_container_id(runtime, "test-skip-ssh-setup")
        .expect("Failed to resolve running container id for test-skip-ssh-setup");

    let mut ssh_proxy_cmd = cargo_bin_cmd!("devcon");
    let ssh_proxy_result = ssh_proxy_cmd
        .arg("--config")
        .arg(&test_config)
        .arg("ssh")
        .arg("connect")
        .arg(temp_dir.path().to_str().unwrap())
        .arg("--proxy")
        .output();

    assert!(
        ssh_proxy_result.is_ok(),
        "Failed to execute ssh connect --proxy"
    );
    let ssh_proxy_output = ssh_proxy_result.unwrap();
    assert!(
        !ssh_proxy_output.status.success(),
        "ssh connect --proxy unexpectedly succeeded when SSH setup is skipped"
    );
    assert!(
        String::from_utf8_lossy(&ssh_proxy_output.stderr)
            .contains("Container SSH port 22 is not mapped"),
        "Expected missing SSH mapping error, got: {}",
        String::from_utf8_lossy(&ssh_proxy_output.stderr)
    );

    let sshd_running = exec_in_container(
        runtime,
        &container_id,
        &["sh", "-lc", "ps -ef | grep -q '[s]shd'"],
    );
    assert!(
        sshd_running.is_err(),
        "sshd should not be running when agents.skipSshSetup=true"
    );

    drop(temp_dir);
}

/// Regression test for the `devcon start` command always creating a new container.
///
/// `list()` calls `docker ps` (no `-a` flag), which only returns *running*
/// containers.  When the container is stopped, `start_with_features` cannot
/// find it and calls `docker run` again, spawning a duplicate container.
/// The correct behaviour is to restart the existing stopped container and
/// return its original ID.
#[test]
fn test_start_reuses_stopped_container() {
    let runtime = get_runtime();
    if !is_runtime_available(runtime) {
        println!("Skipping test: {:?} runtime not available", runtime);
        return;
    }

    let test_config = create_test_config();
    cleanup_test_artifacts(runtime, "test-start-reuse");
    let temp_dir = create_test_devcontainer(
        "test-start-reuse",
        "mcr.microsoft.com/devcontainers/base:ubuntu",
        None,
    );

    // First `up` — build and start the container.
    let mut cmd = cargo_bin_cmd!("devcon");
    let result = cmd
        .arg("--config")
        .arg(&test_config)
        .arg("--output")
        .arg("json")
        .arg("up")
        .arg(temp_dir.path().to_str().unwrap())
        .output();

    assert!(result.is_ok(), "Failed to execute up command");
    let output = result.unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "Up command failed.\nStdout: {}\nStderr: {}",
        stdout,
        stderr
    );

    let up_json =
        serde_json::from_str::<serde_json::Value>(&stdout).expect("up output is not valid JSON");
    let container_id_after_up = up_json["container_id"]
        .as_str()
        .expect("up output JSON does not contain container_id")
        .to_string();

    // Stop the container so it is in an exited (not running) state.
    stop_container(runtime, &container_id_after_up);

    // `devcon start` — must restart the existing stopped container, not spawn a new one.
    let mut cmd = cargo_bin_cmd!("devcon");
    let result = cmd
        .arg("--config")
        .arg(&test_config)
        .arg("--output")
        .arg("json")
        .arg("start")
        .arg(temp_dir.path().to_str().unwrap())
        .output();

    assert!(result.is_ok(), "Failed to execute start command");
    let output = result.unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "Start command failed.\nStdout: {}\nStderr: {}",
        stdout,
        stderr
    );

    let start_json =
        serde_json::from_str::<serde_json::Value>(&stdout).expect("start output is not valid JSON");
    let container_id_after_start = start_json["container_id"]
        .as_str()
        .expect("start output JSON does not contain container_id")
        .to_string();

    assert_eq!(
        container_id_after_up, container_id_after_start,
        "devcon start created a new container instead of restarting the existing stopped one"
    );

    drop(temp_dir);
}

/// Regression test for https://github.com/devconhq/devcon/issues/85.
///
/// Running `devcon up` a second time on an already-built image must reuse the
/// cached image rather than rebuilding it from scratch.  If the image ID
/// reported by the runtime changes between two consecutive `up` invocations
/// (with no changes to the devcontainer configuration), the cache is broken.
#[test]
fn test_up_does_not_rebuild_existing_image() {
    let runtime = get_runtime();
    if !is_runtime_available(runtime) {
        println!("Skipping test: {:?} runtime not available", runtime);
        return;
    }

    let test_config = create_test_config();
    cleanup_test_artifacts(runtime, "test-no-rebuild");
    let temp_dir = create_test_devcontainer(
        "test-no-rebuild",
        "mcr.microsoft.com/devcontainers/base:ubuntu",
        None,
    );

    // First `up` — builds and starts the container.
    let mut cmd = cargo_bin_cmd!("devcon");
    let result = cmd
        .arg("--config")
        .arg(&test_config)
        .arg("up")
        .arg(temp_dir.path().to_str().unwrap())
        .output();

    assert!(result.is_ok(), "Failed to execute first up command");
    let output = result.unwrap();
    assert!(
        output.status.success(),
        "First up command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let image_id_after_first_up = get_image_id(runtime, "devcon-test-no-rebuild:latest")
        .expect("Image devcon-test-no-rebuild:latest not found after first up");

    // Second `up` — must reuse the cached image, not rebuild it.
    let mut cmd = cargo_bin_cmd!("devcon");
    let result = cmd
        .arg("--config")
        .arg(&test_config)
        .arg("up")
        .arg(temp_dir.path().to_str().unwrap())
        .output();

    assert!(result.is_ok(), "Failed to execute second up command");
    let output = result.unwrap();
    assert!(
        output.status.success(),
        "Second up command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let image_id_after_second_up = get_image_id(runtime, "devcon-test-no-rebuild:latest")
        .expect("Image devcon-test-no-rebuild:latest not found after second up");

    assert_eq!(
        image_id_after_first_up, image_id_after_second_up,
        "Image was rebuilt on second 'devcon up' even though nothing changed (issue #85)"
    );

    drop(temp_dir);
}

#[test]
fn test_up_rebuilds_when_config_changes() {
    let runtime = get_runtime();
    if !is_runtime_available(runtime) {
        println!("Skipping test: {:?} runtime not available", runtime);
        return;
    }

    let test_config = create_test_config();
    cleanup_test_artifacts(runtime, "test-rebuild-on-change");
    let temp_dir = create_test_devcontainer(
        "test-rebuild-on-change",
        "mcr.microsoft.com/devcontainers/base:ubuntu",
        None,
    );

    // First `up` — builds the image with the initial config hash label.
    let mut cmd = cargo_bin_cmd!("devcon");
    let result = cmd
        .arg("--config")
        .arg(&test_config)
        .arg("up")
        .arg(temp_dir.path().to_str().unwrap())
        .output();

    assert!(result.is_ok(), "Failed to execute first up command");
    let output = result.unwrap();
    assert!(
        output.status.success(),
        "First up command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let image_id_after_first_up = get_image_id(runtime, "devcon-test-rebuild-on-change:latest")
        .expect("Image not found after first up");

    // Mutate devcontainer.json so the config hash changes.
    let devcontainer_path = temp_dir
        .path()
        .join(".devcontainer")
        .join("devcontainer.json");
    std::fs::write(
        &devcontainer_path,
        r#"{
    "name": "test-rebuild-on-change",
    "image": "mcr.microsoft.com/devcontainers/base:ubuntu",
    "remoteEnv": { "DEVCON_TEST_CHANGE": "1" }
}"#,
    )
    .expect("Failed to update devcontainer.json");

    // Second `up` — config changed, must rebuild the image.
    let mut cmd = cargo_bin_cmd!("devcon");
    let result = cmd
        .arg("--config")
        .arg(&test_config)
        .arg("up")
        .arg(temp_dir.path().to_str().unwrap())
        .output();

    assert!(result.is_ok(), "Failed to execute second up command");
    let output = result.unwrap();
    assert!(
        output.status.success(),
        "Second up command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let image_id_after_second_up = get_image_id(runtime, "devcon-test-rebuild-on-change:latest")
        .expect("Image not found after second up");

    assert_ne!(
        image_id_after_first_up, image_id_after_second_up,
        "Image was NOT rebuilt after devcontainer.json changed"
    );

    drop(temp_dir);
}

#[test]
fn test_up_force_rebuild() {
    let runtime = get_runtime();
    if !is_runtime_available(runtime) {
        println!("Skipping test: {:?} runtime not available", runtime);
        return;
    }

    let test_config = create_test_config();
    cleanup_test_artifacts(runtime, "test-force-rebuild");
    let temp_dir = create_test_devcontainer(
        "test-force-rebuild",
        "mcr.microsoft.com/devcontainers/base:ubuntu",
        None,
    );

    // First `up` — builds the image normally.
    let mut cmd = cargo_bin_cmd!("devcon");
    let result = cmd
        .arg("--config")
        .arg(&test_config)
        .arg("up")
        .arg(temp_dir.path().to_str().unwrap())
        .output();

    assert!(result.is_ok(), "Failed to execute first up command");
    let output = result.unwrap();
    assert!(
        output.status.success(),
        "First up command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let image_id_after_first_up = get_image_id(runtime, "devcon-test-force-rebuild:latest")
        .expect("Image not found after first up");

    // Second `up` with --force-rebuild — config is unchanged, but must rebuild anyway.
    let mut cmd = cargo_bin_cmd!("devcon");
    let result = cmd
        .arg("--config")
        .arg(&test_config)
        .arg("up")
        .arg("--force-rebuild")
        .arg(temp_dir.path().to_str().unwrap())
        .output();

    assert!(result.is_ok(), "Failed to execute second up command");
    let output = result.unwrap();
    assert!(
        output.status.success(),
        "Second up command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let image_id_after_force_rebuild = get_image_id(runtime, "devcon-test-force-rebuild:latest")
        .expect("Image not found after force rebuild");

    assert_ne!(
        image_id_after_first_up, image_id_after_force_rebuild,
        "Image was NOT rebuilt when --force-rebuild was passed"
    );

    drop(temp_dir);
}

#[test]
#[cfg(target_os = "macos")]
fn test_build_container_runtime() {
    let runtime = Runtime::Container;
    if !is_runtime_available(runtime) {
        println!("Skipping test: Container runtime not available");
        return;
    }

    unsafe {
        std::env::set_var("CONTAINER_RUNTIME", "container");
    }

    let test_config = create_test_config();
    let temp_dir = create_test_devcontainer(
        "test-container",
        "mcr.microsoft.com/devcontainers/base:ubuntu",
        None,
    );

    // The container runtime has a bug with default temp directories
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
fn test_build_container_runtime_with_features() {
    let runtime = Runtime::Container;
    if !is_runtime_available(runtime) {
        println!("Skipping test: Container runtime not available");
        return;
    }
    let test_config = create_test_config();

    unsafe {
        std::env::set_var("CONTAINER_RUNTIME", "container");
    }

    let features = r#"{"ghcr.io/devcontainers/features/git": {}}"#;
    let temp_dir = create_test_devcontainer(
        "test-container-features",
        "mcr.microsoft.com/devcontainers/base:ubuntu",
        Some(features),
    );

    // The container runtime has a bug with default temp directories
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
