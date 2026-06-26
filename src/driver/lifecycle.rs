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

//! # Lifecycle Command Execution
//!
//! Helpers for running devcontainer lifecycle hooks inside a running container.
//! Some hooks are guarded by idempotency markers so they execute once per
//! container instance, while others should run on every start or attach.

use crate::devcontainer::{LifecycleCommand, LifecycleCommandValue};
use crate::driver::runtime::{ContainerHandle, ContainerRuntime};
use crate::error::Result;
use crate::workspace::Workspace;

/// Returns the in-container path for a lifecycle marker file.
pub(crate) fn lifecycle_marker_path(marker_name: &str) -> String {
    format!("/var/lib/devcon/lifecycle-markers/{}", marker_name)
}

/// Checks whether a lifecycle marker file already exists inside the container.
pub(crate) fn lifecycle_marker_exists(
    runtime: &dyn ContainerRuntime,
    handle: &dyn ContainerHandle,
    marker_name: &str,
) -> bool {
    let marker = lifecycle_marker_path(marker_name);
    runtime
        .exec(
            handle,
            vec!["sudo", "test", "-f", &marker],
            &[],
            false,
            false,
        )
        .is_ok()
}

/// Creates the lifecycle marker file inside the container, indicating the hook succeeded.
pub(crate) fn create_lifecycle_marker(
    runtime: &dyn ContainerRuntime,
    handle: &dyn ContainerHandle,
    marker_name: &str,
) -> Result<()> {
    let marker = lifecycle_marker_path(marker_name);
    let marker_dir = "/var/lib/devcon/lifecycle-markers";

    runtime.exec(
        handle,
        vec!["sudo", "mkdir", "-p", marker_dir],
        &[],
        false,
        false,
    )?;
    runtime.exec(handle, vec!["sudo", "touch", &marker], &[], false, false)?;

    Ok(())
}

/// Runs a shell-string lifecycle command inside the container.
fn exec_shell_lifecycle_command(
    runtime: &dyn ContainerRuntime,
    handle: &dyn ContainerHandle,
    _devcontainer_workspace: &Workspace,
    cmd: &str,
    env_vars: &[String],
    attach_stdin: bool,
    attach_stdout: bool,
) -> Result<()> {
    runtime.exec(
        handle,
        vec!["bash", "-c", "-i", cmd],
        env_vars,
        attach_stdin,
        attach_stdout,
    )
}

/// Runs an argv-style lifecycle command inside the container.
fn exec_argv_lifecycle_command(
    runtime: &dyn ContainerRuntime,
    handle: &dyn ContainerHandle,
    cmd: &[String],
    env_vars: &[String],
    attach_stdin: bool,
    attach_stdout: bool,
) -> Result<()> {
    let args: Vec<&str> = cmd.iter().map(String::as_str).collect();
    runtime.exec(handle, args, env_vars, attach_stdin, attach_stdout)
}

fn exec_lifecycle_value(
    runtime: &dyn ContainerRuntime,
    handle: &dyn ContainerHandle,
    devcontainer_workspace: &Workspace,
    value: &LifecycleCommandValue,
    env_vars: &[String],
    attach_stdin: bool,
    attach_stdout: bool,
) -> Result<()> {
    match value {
        LifecycleCommandValue::String(cmd) => exec_shell_lifecycle_command(
            runtime,
            handle,
            devcontainer_workspace,
            cmd,
            env_vars,
            attach_stdin,
            attach_stdout,
        ),
        LifecycleCommandValue::Array(cmd) => {
            exec_argv_lifecycle_command(runtime, handle, cmd, env_vars, attach_stdin, attach_stdout)
        }
    }
}

fn execute_lifecycle_command(
    runtime: &dyn ContainerRuntime,
    handle: &dyn ContainerHandle,
    devcontainer_workspace: &Workspace,
    command: &LifecycleCommand,
    attach_stdin: bool,
    attach_stdout: bool,
) -> Result<()> {
    match command {
        LifecycleCommand::String(cmd) => exec_shell_lifecycle_command(
            runtime,
            handle,
            devcontainer_workspace,
            cmd,
            &[],
            attach_stdin,
            attach_stdout,
        )?,
        LifecycleCommand::Array(cmd) => {
            exec_argv_lifecycle_command(runtime, handle, cmd, &[], attach_stdin, attach_stdout)?
        }
        LifecycleCommand::Object(map) => {
            // Parallel object execution is a future enhancement.
            // Preserve direct argv execution for array values, but run the
            // object entries sequentially for now.
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by_key(|(left, _)| *left);

            for (_, value) in entries {
                exec_lifecycle_value(
                    runtime,
                    handle,
                    devcontainer_workspace,
                    value,
                    &[],
                    attach_stdin,
                    attach_stdout,
                )?;
            }
        }
    }

    Ok(())
}

/// Runs a lifecycle command hook inside the container, guarded by an idempotency marker.
///
/// If the marker already exists the command is skipped. On success the marker is
/// created so the command will not run again.
pub(crate) fn run_lifecycle_command_once(
    runtime: &dyn ContainerRuntime,
    handle: &dyn ContainerHandle,
    devcontainer_workspace: &Workspace,
    command: &LifecycleCommand,
    marker_name: &str,
    attach_stdin: bool,
    attach_stdout: bool,
) -> Result<()> {
    if lifecycle_marker_exists(runtime, handle, marker_name) {
        return Ok(());
    }

    execute_lifecycle_command(
        runtime,
        handle,
        devcontainer_workspace,
        command,
        attach_stdin,
        attach_stdout,
    )?;

    create_lifecycle_marker(runtime, handle, marker_name)
}

/// Runs a lifecycle command hook inside the container every time it is invoked.
pub(crate) fn run_lifecycle_command_always(
    runtime: &dyn ContainerRuntime,
    handle: &dyn ContainerHandle,
    devcontainer_workspace: &Workspace,
    command: &LifecycleCommand,
    attach_stdin: bool,
    attach_stdout: bool,
) -> Result<()> {
    execute_lifecycle_command(
        runtime,
        handle,
        devcontainer_workspace,
        command,
        attach_stdin,
        attach_stdout,
    )
}

/// Wraps a shell command string so it runs at most once inside the container,
/// guarded by a marker file at `/var/lib/devcon/lifecycle-markers/{marker_name}`.
///
/// The marker is created only when the command succeeds (`&&`). With `--rm`
/// (current default) the container filesystem is discarded on stop, so the guard
/// has no effect today. Once containers are persisted across stop/start cycles the
/// marker will survive and prevent the command from re-running on subsequent starts.
pub(crate) fn guard_with_marker(cmd: &str, marker_name: &str) -> String {
    let marker = lifecycle_marker_path(marker_name);
    format!(
        "MARKER='{}'; if [ ! -f \"$MARKER\" ]; then {}; sudo mkdir -p \"$(dirname \"$MARKER\")\" && sudo touch \"$MARKER\"; fi",
        marker, cmd
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lifecycle_marker_path_contains_marker_name() {
        assert!(lifecycle_marker_path("foo").contains("foo"));
    }

    #[test]
    fn test_guard_with_marker_contains_marker_path() {
        let result = guard_with_marker("echo hello", "myMarker");
        assert!(result.contains("myMarker"));
        assert!(result.contains("echo hello"));
    }

    #[test]
    fn test_guard_with_marker_distinct_names() {
        let r1 = guard_with_marker("cmd1", "marker1");
        let r2 = guard_with_marker("cmd2", "marker2");
        assert!(r1.contains("marker1"));
        assert!(!r1.contains("marker2"));
        assert!(r2.contains("marker2"));
        assert!(!r2.contains("marker1"));
        assert!(r1.contains("cmd1"));
        assert!(r2.contains("cmd2"));
    }

    #[test]
    fn test_guard_with_marker_touch_after_success() {
        let result = guard_with_marker("my_command", "testMarker");
        assert!(result.contains("sudo touch"));
    }
}
