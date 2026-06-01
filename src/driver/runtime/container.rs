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

//! # Container CLI Runtime
//!
//! Implementation of ContainerRuntime trait for the `container` CLI.

use std::{
    path::Path,
    process::{Command, Stdio},
    time::Duration,
};

use crate::error::Error;
use crate::error::Result;

use crate::config::ContainerRuntimeConfig;
use crate::driver::runtime::RuntimeParameters;
use tracing::{debug, trace};

use super::{ContainerRuntime, stream_build_output};

/// Extract container-side port from a ForwardPort
fn extract_container_port(port: &crate::devcontainer::ForwardPort) -> Option<u16> {
    use crate::devcontainer::ForwardPort;
    match port {
        ForwardPort::Port(p) => Some(*p),
        ForwardPort::HostPort(mapping) => {
            // Format is "host:container", we want the container port
            mapping.split(':').nth(1).and_then(|s| {
                s.parse::<u16>().ok().or_else(|| {
                    tracing::warn!("Failed to parse container port from mapping: {}", mapping);
                    None
                })
            })
        }
    }
}

/// `container` CLI runtime implementation.
pub struct ContainerCliRuntime {
    config: ContainerRuntimeConfig,
}

/// Handle for a container instance.
pub struct ContainerCliHandle {
    id: String,
}

impl super::ContainerHandle for ContainerCliHandle {
    fn id(&self) -> &str {
        &self.id
    }
}

impl ContainerCliRuntime {
    pub fn new(config: ContainerRuntimeConfig) -> Self {
        Self { config }
    }

    /// Extracts `remoteUser` from the `devcontainer.metadata` OCI label embedded in the image.
    ///
    /// The container runtime's inspect JSON uses both lowercase (`config.labels`) and
    /// Docker-style (`Config.Labels`) key names — we check both.
    fn remote_user_from_metadata_label(inspect: &serde_json::Value) -> Option<String> {
        let label_str = inspect
            .get("Config")
            .or_else(|| inspect.get("config"))
            .and_then(|v| v.get("Labels").or_else(|| v.get("labels")))
            .and_then(|v| v.get("devcontainer.metadata"))
            .and_then(|v| v.as_str())?;

        let entries: serde_json::Value = serde_json::from_str(label_str).ok()?;
        entries.as_array()?.iter().rev().find_map(|entry| {
            entry
                .get("remoteUser")
                .and_then(|u| u.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToString::to_string)
        })
    }

    /// Probes the home directory of `user` by running a throwaway container.
    fn probe_home_for_user(image_tag: &str, user: &str) -> Option<String> {
        let probe_cmd = "printf '%s' \"$HOME\"";
        let probes: [Vec<&str>; 2] = [
            vec![
                "run",
                "--rm",
                "--user",
                user,
                "--entrypoint",
                "sh",
                image_tag,
                "-lc",
                probe_cmd,
            ],
            vec![
                "run",
                "--rm",
                "--user",
                user,
                "--entrypoint",
                "/bin/sh",
                image_tag,
                "-lc",
                probe_cmd,
            ],
        ];

        for probe in probes {
            let output = Command::new("container").args(probe).output().ok()?;
            if !output.status.success() {
                continue;
            }
            let home = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !home.is_empty() {
                return Some(home);
            }
        }

        None
    }

    /// Returns the conventional home directory path for `user`.
    fn default_home_for_user(user: &str) -> String {
        if user == "root" {
            "/root".to_string()
        } else {
            format!("/home/{}", user)
        }
    }

    fn metadata_user(inspect: &serde_json::Value) -> Option<String> {
        // The devcontainer.metadata OCI label takes precedence over config.user / Config.User.
        Self::remote_user_from_metadata_label(inspect)
            .or_else(|| {
                inspect
                    .get("config")
                    .and_then(|v| v.get("user"))
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .map(ToString::to_string)
            })
            .or_else(|| {
                inspect
                    .get("Config")
                    .and_then(|v| v.get("User"))
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .map(ToString::to_string)
            })
    }

    fn metadata_home(inspect: &serde_json::Value) -> Option<String> {
        let env_arrays = [
            inspect
                .get("config")
                .and_then(|v| v.get("env"))
                .and_then(|v| v.as_array()),
            inspect
                .get("Config")
                .and_then(|v| v.get("Env"))
                .and_then(|v| v.as_array()),
        ];

        for envs in env_arrays.into_iter().flatten() {
            if let Some(home) = envs.iter().find_map(|v| {
                let env = v.as_str()?;
                env.strip_prefix("HOME=")
                    .map(str::trim)
                    .filter(|h| !h.is_empty())
                    .map(ToString::to_string)
            }) {
                return Some(home);
            }
        }

        None
    }

    fn probe_image_user_and_home(image_tag: &str) -> Option<(String, String)> {
        let probe_cmd = "id -un; printf '\n'; printf '%s' \"$HOME\"";
        let probes: [Vec<&str>; 2] = [
            vec![
                "run",
                "--rm",
                "--entrypoint",
                "sh",
                image_tag,
                "-lc",
                probe_cmd,
            ],
            vec![
                "run",
                "--rm",
                "--entrypoint",
                "/bin/sh",
                image_tag,
                "-lc",
                probe_cmd,
            ],
        ];

        for probe in probes {
            let output = Command::new("container").args(probe).output().ok();
            let Some(output) = output else {
                continue;
            };

            if !output.status.success() {
                continue;
            }

            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut lines = stdout.lines();
            let user = lines.next().unwrap_or_default().trim().to_string();
            let home = lines.next().unwrap_or_default().trim().to_string();
            if !user.is_empty() && !home.is_empty() {
                return Some((user, home));
            }
        }

        None
    }

    /// Shared implementation for `list` and `list_all`.
    ///
    /// When `all` is `true`, stopped/exited containers are included in addition to
    /// running ones.
    #[allow(clippy::type_complexity)]
    fn list_containers(
        &self,
        all: bool,
    ) -> Result<Vec<(String, String, Box<dyn super::ContainerHandle>)>> {
        let output = Command::new("container")
            .arg("list")
            .arg("--format")
            .arg("json")
            .output()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let containers: Vec<serde_json::Value> = serde_json::from_str(&stdout)?;

        let result: Vec<(String, String, Box<dyn super::ContainerHandle>)> = containers
            .iter()
            .filter_map(|container| {
                trace!("Inspecting container: {}", container);

                let state = container["status"].as_str().unwrap_or_default();
                if !all && state != "running" {
                    return None;
                }

                let project_name = container["configuration"]["labels"]["devcon.project"]
                    .as_str()
                    .unwrap_or_default();

                trace!("Container project name: {}", project_name);
                if project_name.is_empty() {
                    return None;
                }

                let id = container["configuration"]["id"]
                    .as_str()
                    .unwrap_or_default()
                    .trim()
                    .to_string();

                debug!("Found container with ID: {}", id);

                let image_tag = container["configuration"]["image"]
                    .as_str()
                    .unwrap_or_default()
                    .trim()
                    .to_string();

                let container_name = format!("devcon.{}", project_name);
                let handle = ContainerCliHandle { id };
                Some((
                    container_name,
                    image_tag,
                    Box::new(handle) as Box<dyn super::ContainerHandle>,
                ))
            })
            .collect();

        Ok(result)
    }
}

impl ContainerRuntime for ContainerCliRuntime {
    fn build(
        &self,
        dockerfile_path: &Path,
        context_path: &Path,
        image_tag: Vec<&str>,
        silent: bool,
    ) -> Result<()> {
        self.build_with_args(
            dockerfile_path,
            context_path,
            image_tag,
            &None,
            &None,
            &None,
            silent,
        )
    }

    fn build_with_args(
        &self,
        dockerfile_path: &Path,
        context_path: &Path,
        image_tag: Vec<&str>,
        args: &Option<std::collections::HashMap<String, String>>,
        target: &Option<String>,
        options: &Option<Vec<String>>,
        silent: bool,
    ) -> Result<()> {
        let mut cmd = Command::new("container");
        cmd.arg("build");

        // Add memory limit if configured (default: 4g)
        let memory = self.config.build_memory.as_deref().unwrap_or("4g");
        cmd.arg("--memory").arg(memory);

        // Add CPU limit if configured
        if let Some(cpu) = &self.config.build_cpu {
            cmd.arg("--cpus").arg(cpu);
        }

        cmd.arg("-f").arg(dockerfile_path);
        for tag in image_tag {
            cmd.arg("-t").arg(tag);
        }

        // Add build arguments
        if let Some(build_args) = args {
            for (key, value) in build_args {
                cmd.arg("--build-arg").arg(format!("{}={}", key, value));
            }
        }

        // Add target stage if specified
        if let Some(target_stage) = target {
            cmd.arg("--target").arg(target_stage);
        }

        // Add additional options
        if let Some(opts) = options {
            for opt in opts {
                cmd.arg(opt);
            }
        }

        cmd.arg(context_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let child = cmd.spawn()?;

        let result = stream_build_output(child, silent)?;

        if !result.success() {
            return Err(Error::runtime("Container build command failed"));
        }

        Ok(())
    }

    fn run(
        &self,
        image_tag: &str,
        volume_mount: &str,
        label: &str,
        env_vars: &[String],
        runtime_parameters: RuntimeParameters,
    ) -> Result<Box<dyn super::ContainerHandle>> {
        let mut cmd = Command::new("container");
        cmd.arg("run")
            .arg("-d")
            .arg("--rosetta") // TODO: autodetect / cli param to set this argument
            .arg("-v")
            .arg(volume_mount)
            .arg("-l")
            .arg(label);

        // Add CPU and memory limits from config
        let memory = self.config.run_memory.as_deref().unwrap_or("8g");
        cmd.arg("--memory").arg(memory);
        let cpu = self.config.run_cpu.as_deref().unwrap_or("2");
        cmd.arg("--cpus").arg(cpu);

        // Add privileged flag if required
        if runtime_parameters.requires_privileged {
            cmd.arg("--virtualization");
        }

        // Add environment variables
        for env_var in env_vars {
            cmd.arg("-e").arg(env_var);
        }

        // Add excluded ports environment variable for agent
        let excluded_ports: Vec<String> = runtime_parameters
            .ports
            .iter()
            .filter_map(extract_container_port)
            .map(|p| p.to_string())
            .collect();
        if !excluded_ports.is_empty() {
            let excluded_ports_str = excluded_ports.join(",");
            cmd.arg("-e")
                .arg(format!("DEVCON_FORWARDED_PORTS={}", excluded_ports_str));
        }

        // Add additional mounts from features and devcontainer config
        for mount in runtime_parameters.additional_mounts {
            match mount {
                crate::devcontainer::Mount::String(mount_str) => {
                    cmd.arg("-v").arg(mount_str);
                }
                crate::devcontainer::Mount::Structured(structured) => {
                    let mount_arg = match &structured.mount_type {
                        crate::devcontainer::MountType::Bind => {
                            if let Some(source) = &structured.source {
                                format!("type=bind,source={},target={}", source, structured.target)
                            } else {
                                continue; // Skip bind mounts without source
                            }
                        }
                        crate::devcontainer::MountType::Volume => {
                            if let Some(source) = &structured.source {
                                format!(
                                    "type=volume,source={},target={}",
                                    source, structured.target
                                )
                            } else {
                                format!("type=volume,target={}", structured.target)
                            }
                        }
                    };
                    cmd.arg("--mount").arg(mount_arg);
                }
            }
        }

        // Add port forwards
        for port in runtime_parameters.ports {
            let port_number = match port {
                crate::devcontainer::ForwardPort::Port(port_number) => {
                    format!("{}:{}", port_number, port_number)
                }
                crate::devcontainer::ForwardPort::HostPort(port) => port,
            };
            cmd.arg("-p").arg(port_number);
        }

        cmd.arg(image_tag);

        let result = cmd.output()?;

        if result.status.code() != Some(0) {
            return Err(Error::runtime(format!(
                "Container start command failed: {}",
                &String::from_utf8(result.stderr).unwrap()
            )));
        }
        std::thread::sleep(Duration::from_secs(10));

        Ok(Box::new(ContainerCliHandle {
            id: String::from_utf8_lossy(&result.stdout).trim().to_string(),
        }))
    }

    fn exec(
        &self,
        container_handle: &dyn super::ContainerHandle,
        command: Vec<&str>,
        env_vars: &[String],
        attach_stdin: bool,
        attach_stdout: bool,
    ) -> Result<()> {
        let mut cmd = Command::new("container");
        cmd.arg("exec");

        if attach_stdout {
            cmd.arg("-t");
        }

        if attach_stdin {
            cmd.arg("-i");
        }

        for env_var in env_vars {
            cmd.arg("-e").arg(env_var);
        }

        cmd.stdout(if attach_stdout {
            Stdio::inherit()
        } else {
            Stdio::piped()
        })
        .stderr(if attach_stdout {
            Stdio::inherit()
        } else {
            Stdio::piped()
        })
        .stdin(if attach_stdin {
            Stdio::inherit()
        } else {
            Stdio::null()
        });

        cmd.arg(container_handle.id()).args(command);

        debug!("Executing container exec command: {:?}", cmd);
        let result = cmd.output()?;

        if result.status.code() != Some(0) {
            return Err(Error::runtime(format!(
                "Container exec command failed: {}",
                &String::from_utf8(result.stderr).unwrap()
            )));
        }

        Ok(())
    }

    fn list(&self) -> Result<Vec<(String, String, Box<dyn super::ContainerHandle>)>> {
        self.list_containers(false)
    }

    fn list_all(&self) -> Result<Vec<(String, String, Box<dyn super::ContainerHandle>)>> {
        self.list_containers(true)
    }

    fn start_container(&self, container_id: &str) -> Result<Box<dyn super::ContainerHandle>> {
        let output = Command::new("container")
            .arg("start")
            .arg(container_id)
            .output()?;

        if !output.status.success() {
            return Err(Error::runtime(format!(
                "container start failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        Ok(Box::new(ContainerCliHandle {
            id: container_id.to_string(),
        }))
    }

    fn images(&self) -> Result<Vec<String>> {
        let output = Command::new("container")
            .arg("image")
            .arg("list")
            .arg("--format")
            .arg("json")
            .output()?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        let images: Vec<serde_json::Value> = serde_json::from_str(&stdout)?;

        let result: Vec<String> = images
            .iter()
            .filter_map(|image| {
                trace!("Inspecting image: {}", image);
                let name = &image["reference"];
                if name.is_null() {
                    return None;
                }

                if name.as_str().unwrap_or_default().starts_with("devcon") {
                    Some(name.as_str().unwrap_or_default().trim().to_string())
                } else {
                    None
                }
            })
            .collect();

        Ok(result)
    }

    fn image_id(&self, image_tag: &str) -> Result<Option<String>> {
        let output = Command::new("container")
            .arg("image")
            .arg("inspect")
            .arg("--format")
            .arg("json")
            .arg(image_tag)
            .output()?;

        if !output.status.success() {
            return Ok(None);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let image: serde_json::Value =
            serde_json::from_str(&stdout).unwrap_or(serde_json::Value::Null);
        let id = image["digest"].as_str().unwrap_or("").trim().to_string();
        if id.is_empty() {
            Ok(None)
        } else {
            Ok(Some(id))
        }
    }

    fn inspect_image(&self, image_tag: &str) -> Result<Option<serde_json::Value>> {
        let output = Command::new("container")
            .arg("image")
            .arg("inspect")
            .arg("--format")
            .arg("json")
            .arg(image_tag)
            .output()?;

        if !output.status.success() {
            return Ok(None);
        }

        let mut inspect: serde_json::Value = serde_json::from_slice(&output.stdout)?;

        let has_valid_user = Self::metadata_user(&inspect).is_some();
        let has_valid_home = Self::metadata_home(&inspect).is_some();

        if let serde_json::Value::Object(ref mut map) = inspect
            && (!has_valid_user || !has_valid_home)
            && let Some((user, home)) = Self::probe_image_user_and_home(image_tag)
        {
            map.insert(
                "_devconDetectedUser".to_string(),
                serde_json::Value::String(user),
            );
            map.insert(
                "_devconDetectedHome".to_string(),
                serde_json::Value::String(home),
            );
        }

        // The devcontainer.metadata label is authoritative for the remote user.
        // Override whatever the probe detected so that images with Config.User=root
        // but a metadata label remoteUser resolve to the correct user and home.
        if let Some(label_user) = Self::remote_user_from_metadata_label(&inspect)
            && let serde_json::Value::Object(ref mut map) = inspect
        {
            let home = Self::probe_home_for_user(image_tag, &label_user)
                .unwrap_or_else(|| Self::default_home_for_user(&label_user));
            map.insert(
                "_devconDetectedUser".to_string(),
                serde_json::Value::String(label_user),
            );
            map.insert(
                "_devconDetectedHome".to_string(),
                serde_json::Value::String(home),
            );
        }

        Ok(Some(inspect))
    }

    fn image_label(&self, image_tag: &str, label_key: &str) -> Result<Option<String>> {
        let inspect = self.inspect_image(image_tag)?;
        // Container's inspect JSON uses both lowercase and Docker-style key names.
        let value = inspect
            .as_ref()
            .and_then(|v| v.get("Config").or_else(|| v.get("config")))
            .and_then(|v| v.get("Labels").or_else(|| v.get("labels")))
            .and_then(|v| v.get(label_key))
            .and_then(|v| v.as_str())
            .map(ToString::to_string);
        Ok(value)
    }

    fn get_host_address(&self) -> String {
        "host.container.internal".to_string()
    }
}
