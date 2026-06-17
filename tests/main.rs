mod test_utils;

use serde_json::json;
use serial_test::serial;
use test_utils::*;

// ─────────────────────────────────────────────────────────────────────────────
// Build-only tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_build_simple() {
    skip_if_unavailable!(get_runtime());
    let config = TestConfig::agents_disabled();
    let workspace = DevcontainerBuilder::new("test-simple").build();
    DevconRun::build(workspace.path(), &config).assert_success();
}

#[test]
fn test_build_with_name() {
    skip_if_unavailable!(get_runtime());
    let config = TestConfig::agents_disabled();
    let workspace = DevcontainerBuilder::new("Test Devcontainer Name").build();
    DevconRun::build(workspace.path(), &config).assert_success();
}

#[test]
fn test_build_and_verify_image() {
    let runtime = get_runtime();
    skip_if_unavailable!(runtime);
    let config = TestConfig::agents_disabled();
    let workspace = DevcontainerBuilder::new("test-verify").build();
    let out = DevconRun::build(workspace.path(), &config);
    out.assert_success();
    assert!(
        verify_image_exists(runtime, "devcon-test-verify:latest"),
        "Image devcon-test-verify:latest does not exist after build (Stdout: {}, Stderr: {})",
        out.stdout,
        out.stderr
    );
}

#[test]
fn test_build_with_features() {
    skip_if_unavailable!(get_runtime());
    let config = TestConfig::agents_disabled();
    let workspace = DevcontainerBuilder::new("test-features")
        .feature("ghcr.io/devcontainers/features/node", &[("version", "18")])
        .build();
    let out = DevconRun::build(workspace.path(), &config);
    out.assert_success();
    out.assert_output_contains("Evaluated feature order:");
    out.assert_output_contains("Evaluated environment summary:");
    out.assert_output_contains("Feature build progress:");
}

#[test]
fn test_build_multiple_features() {
    skip_if_unavailable!(get_runtime());
    let config = TestConfig::agents_disabled();
    let workspace = DevcontainerBuilder::new("test-multi-features")
        .feature("ghcr.io/devcontainers/features/git", &[])
        .feature("ghcr.io/devcontainers/features/github-cli", &[])
        .build();
    DevconRun::build(workspace.path(), &config).assert_success();
}

#[test]
fn test_build_with_lifecycle_hooks() {
    skip_if_unavailable!(get_runtime());
    let config = TestConfig::agents_disabled();
    let workspace = DevcontainerBuilder::new("test-hooks")
        .on_create("echo 'onCreate executed'")
        .post_create("echo 'postCreate executed'")
        .build();
    DevconRun::build(workspace.path(), &config).assert_success();
}

// ─────────────────────────────────────────────────────────────────────────────
// Up (build + start) tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_build_with_dockerfile() {
    let runtime = get_runtime();
    skip_if_unavailable!(runtime);
    cleanup_test_artifacts(runtime, "test-dockerfile");
    let config = TestConfig::agents_disabled();
    let workspace = DevcontainerBuilder::new("test-dockerfile")
        .dockerfile(
            "FROM mcr.microsoft.com/devcontainers/base:ubuntu\n\
             RUN echo \"Custom Dockerfile build\" > /custom-marker.txt\n",
        )
        .build();

    let out = DevconRun::up_verbose(workspace.path(), &config);
    out.assert_success();
    ContainerHandle::new(out.container_id(), runtime)
        .assert_exec_contains(&["cat", "/custom-marker.txt"], "Custom Dockerfile build");
}

#[test]
fn test_up_on_create_array_command_executes_without_shell_joining() {
    let runtime = get_runtime();
    skip_if_unavailable!(runtime);
    cleanup_test_artifacts(runtime, "test-array-hook");
    let config = TestConfig::agents_disabled();
    let workspace = DevcontainerBuilder::new("test-array-hook")
        .on_create_value(json!(["touch", "/tmp/devcon-array-&&-literal"]))
        .build();

    let out = DevconRun::up(workspace.path(), &config);
    out.assert_success();
    ContainerHandle::new(out.container_id(), runtime)
        .assert_file_exists("/tmp/devcon-array-&&-literal");
}

#[test]
fn test_up_on_create_object_array_values_execute_directly() {
    let runtime = get_runtime();
    skip_if_unavailable!(runtime);
    cleanup_test_artifacts(runtime, "test-object-hook");
    let config = TestConfig::agents_disabled();
    let workspace = DevcontainerBuilder::new("test-object-hook")
        .on_create_value(json!({
            "first":  ["touch", "/tmp/devcon-object-first-&&-literal"],
            "second": ["touch", "/tmp/devcon-object-second-&&-literal"],
        }))
        .build();

    let out = DevconRun::up(workspace.path(), &config);
    out.assert_success();
    let container = ContainerHandle::new(out.container_id(), runtime);
    container.assert_file_exists("/tmp/devcon-object-first-&&-literal");
    container.assert_file_exists("/tmp/devcon-object-second-&&-literal");
}

/// Regression test for https://github.com/devconhq/devcon/issues/82.
///
/// `mcr.microsoft.com/devcontainers/base:ubuntu` sets `Config.User = "root"` in its Docker
/// image metadata but embeds `"remoteUser": "vscode"` in the OCI label `devcontainer.metadata`.
/// devcon must read that label so `_REMOTE_USER` resolves to `"vscode"`, not `"root"`.
#[test]
fn test_up_microsoft_devcontainer_base_resolves_remote_user() {
    let runtime = get_runtime();
    skip_if_unavailable!(runtime);
    cleanup_test_artifacts(runtime, "test-remote-user-base");
    let config = TestConfig::agents_disabled();
    let workspace = DevcontainerBuilder::new("test-remote-user-base").build();

    let out = DevconRun::up(workspace.path(), &config);
    out.assert_success();
    ContainerHandle::new(out.container_id(), runtime).assert_env("_REMOTE_USER", "vscode");
}

#[test]
#[serial]
fn test_up_with_custom_agent_ssh_port_uses_2222() {
    let runtime = get_runtime();
    skip_if_unavailable!(runtime);
    cleanup_test_artifacts(runtime, "test-ssh-port-override");

    let config = TestConfig::with_ssh_port(2222);
    let workspace = DevcontainerBuilder::new("test-ssh-port-override").build();

    DevconRun::up(workspace.path(), &config).assert_success();

    // Port 2222 should be mapped → --proxy succeeds.
    DevconRun::ssh_proxy(workspace.path(), &config).assert_success();

    // A config expecting port 22 should fail because 22 is not mapped.
    let wrong_config = TestConfig::agents_enabled();
    let out = DevconRun::ssh_proxy(workspace.path(), &wrong_config);
    out.assert_failure();
    out.assert_stderr_contains("Container SSH port 22 is not mapped");
}

#[test]
#[serial]
fn test_up_with_skip_agent_ssh_setup_skips_forwarding_and_sshd() {
    let runtime = get_runtime();
    skip_if_unavailable!(runtime);
    cleanup_test_artifacts(runtime, "test-skip-ssh-setup");

    let config = TestConfig::skip_ssh_setup();
    let workspace = DevcontainerBuilder::new("test-skip-ssh-setup").build();

    DevconRun::up(workspace.path(), &config).assert_success();

    let container_id = get_running_container_id(runtime, "test-skip-ssh-setup")
        .expect("Failed to resolve running container id");

    let out = DevconRun::ssh_proxy(workspace.path(), &config);
    out.assert_failure();
    out.assert_stderr_contains("Container SSH port 22 is not mapped");

    let sshd_running = exec_in_container(
        runtime,
        &container_id,
        &["sh", "-lc", "ps -ef | grep -q '[s]shd'"],
    );
    assert!(
        sshd_running.is_err(),
        "sshd should not be running when agents.skipSshSetup=true"
    );
}

/// Regression: `devcon start` must restart a stopped container, not spawn a new one.
#[test]
fn test_start_reuses_stopped_container() {
    let runtime = get_runtime();
    skip_if_unavailable!(runtime);
    cleanup_test_artifacts(runtime, "test-start-reuse");

    let config = TestConfig::agents_disabled();
    let workspace = DevcontainerBuilder::new("test-start-reuse").build();

    let up_out = DevconRun::up(workspace.path(), &config);
    up_out.assert_success();
    let id_after_up = up_out.container_id();

    stop_container(runtime, &id_after_up);

    let start_out = DevconRun::start(workspace.path(), &config);
    start_out.assert_success();
    let id_after_start = start_out.container_id();

    // Workaround in Container Runtime
    if runtime == Runtime::Docker {
        assert_eq!(
            id_after_up, id_after_start,
            "devcon start created a new container instead of restarting the stopped one"
        );
    }
}

/// Regression (#85): second `devcon up` without config changes must not rebuild the image.
#[test]
fn test_up_does_not_rebuild_existing_image() {
    let runtime = get_runtime();
    skip_if_unavailable!(runtime);
    cleanup_test_artifacts(runtime, "test-no-rebuild");

    let config = TestConfig::agents_disabled();
    let workspace = DevcontainerBuilder::new("test-no-rebuild").build();

    DevconRun::up(workspace.path(), &config).assert_success();
    let id_first = get_image_id(runtime, "devcon-test-no-rebuild:latest")
        .expect("Image not found after first up");

    DevconRun::up(workspace.path(), &config).assert_success();
    let id_second = get_image_id(runtime, "devcon-test-no-rebuild:latest")
        .expect("Image not found after second up");

    assert_eq!(
        id_first, id_second,
        "Image was rebuilt on second `devcon up` even though nothing changed (issue #85)"
    );
}

#[test]
fn test_up_rebuilds_when_config_changes() {
    let runtime = get_runtime();
    skip_if_unavailable!(runtime);
    cleanup_test_artifacts(runtime, "test-rebuild-on-change");

    let config = TestConfig::agents_disabled();
    let workspace = DevcontainerBuilder::new("test-rebuild-on-change").build();

    DevconRun::up(workspace.path(), &config).assert_success();
    let id_before = get_image_id(runtime, "devcon-test-rebuild-on-change:latest")
        .expect("Image not found after first up");

    // Mutate devcontainer.json so the config hash changes.
    let dc_path = workspace
        .path()
        .join(".devcontainer")
        .join("devcontainer.json");
    std::fs::write(
        &dc_path,
        r#"{
    "name": "test-rebuild-on-change",
    "image": "mcr.microsoft.com/devcontainers/base:ubuntu",
    "remoteEnv": { "DEVCON_TEST_CHANGE": "1" }
}"#,
    )
    .expect("Failed to update devcontainer.json");

    DevconRun::up(workspace.path(), &config).assert_success();
    let id_after = get_image_id(runtime, "devcon-test-rebuild-on-change:latest")
        .expect("Image not found after second up");

    assert_ne!(
        id_before, id_after,
        "Image was NOT rebuilt after devcontainer.json changed"
    );
}

#[test]
fn test_up_force_rebuild() {
    let runtime = get_runtime();
    skip_if_unavailable!(runtime);
    cleanup_test_artifacts(runtime, "test-force-rebuild");

    let config = TestConfig::agents_disabled();
    let workspace = DevcontainerBuilder::new("test-force-rebuild").build();

    DevconRun::up(workspace.path(), &config).assert_success();
    let id_first = get_image_id(runtime, "devcon-test-force-rebuild:latest")
        .expect("Image not found after first up");

    DevconRun::up_force_rebuild(workspace.path(), &config).assert_success();
    let id_after = get_image_id(runtime, "devcon-test-force-rebuild:latest")
        .expect("Image not found after force rebuild");

    assert_ne!(
        id_first, id_after,
        "Image was NOT rebuilt when --force-rebuild was passed"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// New feature scenario tests  (verify binaries are present in the container)
// ─────────────────────────────────────────────────────────────────────────────

/// python feature installs python3 into the container.
#[test]
fn test_feature_python_installs_python3() {
    let runtime = get_runtime();
    skip_if_unavailable!(runtime);
    cleanup_test_artifacts(runtime, "test-feature-python");

    let config = TestConfig::agents_disabled();
    let workspace = DevcontainerBuilder::new("test-feature-python")
        .feature(
            "ghcr.io/devcontainers/features/python",
            &[("version", "3.12")],
        )
        .build();

    let out = DevconRun::up(workspace.path(), &config);
    out.assert_success();
    ContainerHandle::new(out.container_id(), runtime)
        .assert_exec_contains(&["sh", "-lc", "python3 --version"], "Python 3");
}

/// rust feature installs rustup / rustc into the container.
#[test]
#[serial]
fn test_feature_rust_installs_rustc() {
    let runtime = get_runtime();
    skip_if_unavailable!(runtime);
    cleanup_test_artifacts(runtime, "test-feature-rust");

    let config = TestConfig::agents_disabled();
    let workspace = DevcontainerBuilder::new("test-feature-rust")
        .feature(
            "ghcr.io/devcontainers/features/rust",
            &[("version", "latest")],
        )
        .build();

    let out = DevconRun::up(workspace.path(), &config);
    out.assert_success();
    ContainerHandle::new(out.container_id(), runtime)
        .assert_exec_contains(&["sh", "-lc", "rustc --version"], "rustc");
}

/// node feature with a pinned version installs that exact major version.
#[test]
fn test_feature_node_with_version_option() {
    let runtime = get_runtime();
    skip_if_unavailable!(runtime);
    cleanup_test_artifacts(runtime, "test-feature-node-version");

    let config = TestConfig::agents_disabled();
    let workspace = DevcontainerBuilder::new("test-feature-node-version")
        .feature("ghcr.io/devcontainers/features/node", &[("version", "20")])
        .build();

    let out = DevconRun::up(workspace.path(), &config);
    out.assert_success();
    ContainerHandle::new(out.container_id(), runtime)
        .assert_exec_contains(&["sh", "-lc", "node --version"], "v20.");
}

/// Combined features: git + github-cli + node must all be present.
#[test]
fn test_feature_combined_git_gh_node() {
    let runtime = get_runtime();
    skip_if_unavailable!(runtime);
    cleanup_test_artifacts(runtime, "test-feature-combined");

    let config = TestConfig::agents_disabled();
    let workspace = DevcontainerBuilder::new("test-feature-combined")
        .feature("ghcr.io/devcontainers/features/git", &[])
        .feature("ghcr.io/devcontainers/features/github-cli", &[])
        .feature("ghcr.io/devcontainers/features/node", &[("version", "lts")])
        .build();

    let out = DevconRun::up(workspace.path(), &config);
    out.assert_success();
    let container = ContainerHandle::new(out.container_id(), runtime);
    container.assert_exec_contains(&["sh", "-lc", "git --version"], "git version");
    container.assert_exec_contains(&["sh", "-lc", "gh --version"], "gh version");
    container.assert_exec_contains(&["sh", "-lc", "node --version"], "v");
}

// ─────────────────────────────────────────────────────────────────────────────
// macOS `container` runtime tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
#[cfg(target_os = "macos")]
fn test_build_container_runtime() {
    let runtime = Runtime::Container;
    skip_if_unavailable!(runtime);
    cleanup_test_artifacts(runtime, "test-container");

    let config = TestConfig::agents_disabled();
    let workspace = DevcontainerBuilder::new("test-container").build();

    // Pass CONTAINER_RUNTIME only to the child process so this test does not
    // mutate the parent process's environment (which would race with parallel tests).
    use assert_cmd::cargo::cargo_bin_cmd;
    let out = cargo_bin_cmd!("devcon")
        .env("CONTAINER_RUNTIME", "container")
        .arg("--config")
        .arg(&config.path)
        .arg("build")
        .arg(workspace.path())
        .output()
        .expect("Failed to execute build command");

    assert!(
        out.status.success(),
        "Build command failed.\nStdout:\n{}\nStderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
#[cfg(target_os = "macos")]
fn test_build_container_runtime_with_features() {
    let runtime = Runtime::Container;
    skip_if_unavailable!(runtime);
    cleanup_test_artifacts(runtime, "test-container-features");

    let config = TestConfig::agents_disabled();
    let workspace = DevcontainerBuilder::new("test-container-features")
        .feature("ghcr.io/devcontainers/features/git", &[])
        .build();

    use assert_cmd::cargo::cargo_bin_cmd;
    let out = cargo_bin_cmd!("devcon")
        .env("CONTAINER_RUNTIME", "container")
        .arg("--config")
        .arg(&config.path)
        .arg("build")
        .arg(workspace.path())
        .output()
        .expect("Failed to execute build command");

    assert!(
        out.status.success(),
        "Build command failed.\nStdout:\n{}\nStderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Serve / agent / dotfiles / local feature / env var tests
// ─────────────────────────────────────────────────────────────────────────────

/// `devcon serve` accepts connections from the in-container agent.
///
/// Starts a background serve process on a dynamic port, injects that port via
/// `containerEnv`, runs `devcon up`, then confirms the `devcon-agent` process
/// is running inside the container.
#[test]
#[serial]
fn test_serve_connection_works() {
    let runtime = get_runtime();
    skip_if_unavailable!(runtime);
    cleanup_test_artifacts(runtime, "test-serve-connection");

    let config = TestConfig::agents_enabled();
    let (_serve, port) = DevconRun::serve_in_background(&config);

    let workspace = DevcontainerBuilder::new("test-serve-connection")
        .container_env("DEVCON_CONTROL_PORT", port.to_string())
        .build();

    let out = DevconRun::up(workspace.path(), &config);
    out.assert_success();

    let container = ContainerHandle::new(out.container_id(), runtime);

    // Debug: print all env vars visible inside the container so CI logs show
    // whether DEVCON_CONTROL_PORT and DEVCON_CONTROL_HOST were injected.
    match container.exec(&["printenv"]) {
        Ok(env_output) => eprintln!("[debug] container env:\n{}", env_output),
        Err(e) => eprintln!("[debug] printenv failed: {}", e),
    }

    container.assert_exec_contains(
        &["sh", "-lc", "ps -ef | grep '[d]evcon-agent'"],
        "devcon-agent",
    );
}

/// SSH agent socket is forwarded into the container when `agentForwarding.sshEnabled` is set.
///
/// Skips automatically when no SSH agent is running on the host.
#[test]
#[serial]
fn test_ssh_agent_forwarding() {
    let runtime = get_runtime();
    skip_if_unavailable!(runtime);
    skip_if_no_ssh_agent!();
    cleanup_test_artifacts(runtime, "test-ssh-agent");

    let config = TestConfig::with_ssh_forwarding();
    let (_serve, port) = DevconRun::serve_in_background(&config);

    let workspace = DevcontainerBuilder::new("test-ssh-agent")
        .container_env("DEVCON_CONTROL_PORT", port.to_string())
        .build();

    let out = DevconRun::up(workspace.path(), &config);
    out.assert_success();

    ContainerHandle::new(out.container_id(), runtime).assert_env_set("SSH_AUTH_SOCK");
}

/// GPG agent socket is forwarded into the container when `agentForwarding.gpgEnabled` is set.
///
/// Skips automatically when no GPG agent is running on the host.
#[test]
#[serial]
fn test_gpg_agent_forwarding() {
    let runtime = get_runtime();
    skip_if_unavailable!(runtime);
    skip_if_no_gpg_agent!();
    cleanup_test_artifacts(runtime, "test-gpg-agent");

    let config = TestConfig::with_gpg_forwarding();
    let (_serve, port) = DevconRun::serve_in_background(&config);

    let workspace = DevcontainerBuilder::new("test-gpg-agent")
        .container_env("DEVCON_CONTROL_PORT", port.to_string())
        .build();

    let out = DevconRun::up(workspace.path(), &config);
    out.assert_success();

    // GPG forwarding mounts the host agent socket at ~/.gnupg/S.gpg-agent inside
    // the container.  GPG_AGENT_INFO is a legacy env var deprecated since GPG 2.1
    // and is never set by devcon — the socket path is the canonical signal.
    ContainerHandle::new(out.container_id(), runtime)
        .assert_socket_exists("/home/vscode/.gnupg/S.gpg-agent");
}

/// `dotfilesRepository` in config causes the repo to be cloned into `~/.dotfiles`
/// inside the container during the build.
#[test]
fn test_dotfiles_repo_clones() {
    let runtime = get_runtime();
    skip_if_unavailable!(runtime);
    cleanup_test_artifacts(runtime, "test-dotfiles");

    let config = TestConfig::with_dotfiles("https://github.com/octocat/Hello-World");
    let workspace = DevcontainerBuilder::new("test-dotfiles").build();

    let out = DevconRun::up(workspace.path(), &config);
    out.assert_success();

    // Confirm the repo was cloned — a valid git clone always has .git/config.
    ContainerHandle::new(out.container_id(), runtime)
        .assert_exec_contains(&["sh", "-lc", "ls ~/.dotfiles/.git"], "config");
}

/// A feature referenced by a local path (`"./dir"`) is installed into the container.
#[test]
fn test_local_feature_installs() {
    let runtime = get_runtime();
    skip_if_unavailable!(runtime);
    cleanup_test_artifacts(runtime, "test-local-feature");

    let config = TestConfig::agents_disabled();
    let workspace = DevcontainerBuilder::new("test-local-feature")
        .local_feature(
            "hello-feature",
            "#!/bin/sh\nset -e\ntouch /tmp/local-feature-installed\n",
            &[],
        )
        .build();

    let out = DevconRun::up(workspace.path(), &config);
    out.assert_success();

    ContainerHandle::new(out.container_id(), runtime)
        .assert_file_exists("/tmp/local-feature-installed");
}

/// `containerEnv` variables are injected into the container at start-up and
/// visible in every exec context without needing agents.
#[test]
fn test_container_env_variable_is_set() {
    let runtime = get_runtime();
    skip_if_unavailable!(runtime);
    cleanup_test_artifacts(runtime, "test-container-env");

    let config = TestConfig::agents_disabled();
    let workspace = DevcontainerBuilder::new("test-container-env")
        .container_env("DEVCON_CONTAINER_VAR", "container-value")
        .build();

    let out = DevconRun::up(workspace.path(), &config);
    out.assert_success();

    ContainerHandle::new(out.container_id(), runtime)
        .assert_env("DEVCON_CONTAINER_VAR", "container-value");
}

/// `remoteEnv` variables are written to `~/.ssh/environment` by devcon's SSH
/// setup so they are visible to SSH sessions.  This test needs agents enabled
/// (SSH setup runs) and a running `devcon serve` so the agent can connect and
/// the full start-up path executes reliably.
#[test]
#[serial]
fn test_remote_env_written_to_ssh_environment() {
    let runtime = get_runtime();
    skip_if_unavailable!(runtime);
    cleanup_test_artifacts(runtime, "test-remote-env");

    let config = TestConfig::agents_enabled();
    let (_serve, port) = DevconRun::serve_in_background(&config);

    let workspace = DevcontainerBuilder::new("test-remote-env")
        .container_env("DEVCON_CONTROL_PORT", port.to_string())
        .remote_env("DEVCON_REMOTE_VAR", "remote-value")
        .build();

    let out = DevconRun::up(workspace.path(), &config);
    out.assert_success();

    ContainerHandle::new(out.container_id(), runtime).assert_file_contains(
        "/home/vscode/.ssh/environment",
        "DEVCON_REMOTE_VAR=remote-value",
    );
}
