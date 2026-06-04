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

//! # Docker Runtime
//!
//! Implementation of ContainerRuntime trait for Docker CLI.

use std::{
    path::Path,
    process::{Command, Stdio},
};

use crate::error::Error;
use crate::error::Result;
use tracing::{debug, trace};

use crate::config::DockerRuntimeConfig;
use crate::driver::runtime::RuntimeParameters;

use super::{ContainerImageConfig, ContainerImageInfo, ContainerRuntime, stream_build_output};

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

fn parse_host_port(output: &str) -> Option<u16> {
    output.lines().find_map(|line| {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return None;
        }

        trimmed
            .rsplit(':')
            .next()
            .and_then(|port| port.parse::<u16>().ok())
    })
}

/// Docker CLI runtime implementation.
pub struct DockerRuntime {
    config: DockerRuntimeConfig,
}

impl DockerRuntime {
    pub fn new(config: DockerRuntimeConfig) -> Self {
        Self { config }
    }

    fn probe_image_info_inner(
        image_tag: &str,
        user: Option<&str>,
    ) -> Option<super::ContainerProbeInfo> {
        const PROBE_CMD: &str =
            "printf '%s\\n%s\\n%s\\n%s' \"$(id -un)\" \"$HOME\" \"$PATH\" \"$(uname -m)\"";
        let shells = ["sh", "/bin/sh", "bash", "/bin/bash"];
        debug!(
            "Probing docker image runtime environment for image '{}' with user hint {:?}",
            image_tag, user
        );
        for shell in shells {
            trace!(
                "Attempting docker probe with shell '{}' for image '{}'",
                shell, image_tag
            );
            let mut cmd = Command::new("docker");
            cmd.arg("run").arg("--rm");
            if let Some(u) = user {
                cmd.arg("--user").arg(u);
            }
            cmd.arg("--entrypoint")
                .arg(shell)
                .arg(image_tag)
                .arg("-lc")
                .arg(PROBE_CMD);

            let output = match cmd.output() {
                Ok(output) => output,
                Err(err) => {
                    debug!(
                        "Docker probe execution failed for shell '{}' on image '{}': {}",
                        shell, image_tag, err
                    );
                    continue;
                }
            };
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                trace!(
                    "Docker probe failed for shell '{}' on image '{}' with status {:?}, stderr: {}",
                    shell,
                    image_tag,
                    output.status.code(),
                    stderr.trim()
                );
                continue;
            }
            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut lines = stdout.lines();
            let probe_user = lines.next().unwrap_or_default().trim().to_string();
            let home = lines.next().unwrap_or_default().trim().to_string();
            let path = lines.next().unwrap_or_default().trim().to_string();
            let architecture = lines
                .next()
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(ToString::to_string);
            if !probe_user.is_empty() {
                debug!(
                    "Docker probe succeeded for image '{}' using shell '{}': user='{}', home='{}', path_present={}, architecture={:?}",
                    image_tag,
                    shell,
                    probe_user,
                    home,
                    !path.is_empty(),
                    architecture
                );
                return Some(super::ContainerProbeInfo {
                    user: probe_user,
                    home,
                    path,
                    architecture,
                });
            }

            trace!(
                "Docker probe output for shell '{}' on image '{}' did not include a runtime user",
                shell, image_tag
            );
        }

        debug!(
            "Docker probe did not find a suitable shell/runtime user for image '{}'",
            image_tag
        );
        None
    }

    /// Shared implementation for `list` and `list_all`.
    ///
    /// When `all` is `true`, stopped containers are included (equivalent to `docker ps -a`).
    #[allow(clippy::type_complexity)]
    fn list_containers(
        &self,
        all: bool,
    ) -> Result<Vec<(String, String, Box<dyn super::ContainerHandle>)>> {
        let mut cmd = Command::new("docker");
        cmd.arg("ps")
            .arg("--no-trunc")
            .arg("--filter")
            .arg("label=devcon.project")
            .arg("--format")
            .arg("{{json .}}");

        if all {
            cmd.arg("--all");
        }

        let output = cmd.output()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut result: Vec<(String, String, Box<dyn super::ContainerHandle>)> = Vec::new();

        for line in stdout.lines() {
            if line.trim().is_empty() {
                continue;
            }

            let container: serde_json::Value = serde_json::from_str(line)?;

            // Labels format: "key1=value1,key2=value2"
            let labels = container["Labels"].as_str().unwrap_or_default();
            let mut container_name = String::new();
            for label_pair in labels.split(',') {
                if let Some((key, value)) = label_pair.split_once('=')
                    && key == "devcon.project"
                {
                    container_name = format!("devcon.{}", value);
                    break;
                }
            }

            let id = container["ID"]
                .as_str()
                .unwrap_or_default()
                .trim()
                .to_string();

            let image_tag = container["Image"]
                .as_str()
                .unwrap_or_default()
                .trim()
                .to_string();

            if !container_name.is_empty() {
                let handle = DockerContainerHandle { id: id.clone() };
                result.push((container_name, image_tag, Box::new(handle)));
            }
        }

        Ok(result)
    }
}

/// Handle for a Docker container instance.
pub struct DockerContainerHandle {
    id: String,
}

impl super::ContainerHandle for DockerContainerHandle {
    fn id(&self) -> &str {
        &self.id
    }
}

impl ContainerRuntime for DockerRuntime {
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
        let mut cmd = Command::new("docker");
        cmd.arg("build").arg("-f").arg(dockerfile_path);

        // Add memory limit if configured
        if let Some(memory) = &self.config.build_memory {
            cmd.arg("--memory").arg(memory);
        }

        // Add CPU limit if configured
        if let Some(cpu) = &self.config.build_cpu {
            cmd.arg("--cpus").arg(cpu);
        }

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
            return Err(Error::runtime("Docker build command failed"));
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
        trace!("Running Docker container with image: {}", image_tag);
        let mut cmd = Command::new("docker");
        cmd.arg("run").arg("-d");

        if runtime_parameters.platform_architecture_translation {
            cmd.arg("--platform").arg("linux/amd64");
        }

        cmd.arg("-v").arg(volume_mount).arg("--label").arg(label);

        // Add privileged flag if required
        if runtime_parameters.requires_privileged {
            cmd.arg("--privileged");
        }

        // Add memory and CPU limits from config
        if let Some(memory) = &self.config.run_memory {
            cmd.arg("--memory").arg(memory);
        }
        if let Some(cpu) = &self.config.run_cpu {
            cmd.arg("--cpus").arg(cpu);
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
            cmd.arg("-p").arg(port.to_string());
        }

        cmd.arg(image_tag);

        trace!("Executing Docker command: {:?}", cmd);

        let result = cmd.output()?;

        if result.status.code() != Some(0) {
            let exit_code = result
                .status
                .code()
                .map_or("terminated by signal".to_string(), |code| {
                    format!("exit code {}", code)
                });
            let stderr = String::from_utf8_lossy(&result.stderr).trim().to_string();
            let stdout = String::from_utf8_lossy(&result.stdout).trim().to_string();

            let mut details = format!("Docker run command failed ({})", exit_code);
            if !stderr.is_empty() {
                details.push_str(&format!("\nstderr: {}", stderr));
            }
            if !stdout.is_empty() {
                details.push_str(&format!("\nstdout: {}", stdout));
            }

            return Err(Error::runtime(details));
        }

        Ok(Box::new(DockerContainerHandle {
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
        let mut cmd = Command::new("docker");
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
                "Docker exec command failed: {}",
                &String::from_utf8(result.stderr).unwrap()
            )));
        }

        Ok(())
    }

    fn mapped_host_port(&self, container_id: &str, container_port: u16) -> Result<Option<u16>> {
        let output = Command::new("docker")
            .arg("port")
            .arg(container_id)
            .arg(format!("{}/tcp", container_port))
            .output()?;

        if !output.status.success() {
            return Ok(None);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(parse_host_port(&stdout))
    }

    fn list(&self) -> Result<Vec<(String, String, Box<dyn super::ContainerHandle>)>> {
        self.list_containers(false)
    }

    fn list_all(&self) -> Result<Vec<(String, String, Box<dyn super::ContainerHandle>)>> {
        self.list_containers(true)
    }

    fn start_container(&self, container_id: &str) -> Result<Box<dyn super::ContainerHandle>> {
        let output = Command::new("docker")
            .arg("start")
            .arg(container_id)
            .output()?;

        if !output.status.success() {
            return Err(Error::runtime(format!(
                "docker start failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        Ok(Box::new(DockerContainerHandle {
            id: container_id.to_string(),
        }))
    }

    fn images(&self) -> Result<Vec<String>> {
        let output = Command::new("docker")
            .arg("image")
            .arg("list")
            .arg("--format")
            .arg("{{json .}}")
            .output()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut result: Vec<String> = Vec::new();
        // Docker outputs one JSON object per line, not an array
        for line in stdout.lines() {
            if line.trim().is_empty() {
                continue;
            }

            let image: serde_json::Value = serde_json::from_str(line)?;
            let repository = image["Repository"].as_str().unwrap_or_default();
            let tag = image["Tag"].as_str().unwrap_or_default();
            // Assuming devcon-built images have "devcon" in their repository name
            if repository.starts_with("devcon") {
                result.push(format!("{}:{}", repository, tag));
            }
        }

        Ok(result)
    }

    fn image_id(&self, image_tag: &str) -> Result<Option<String>> {
        let output = Command::new("docker")
            .arg("image")
            .arg("inspect")
            .arg("--format")
            .arg("{{.Id}}")
            .arg(image_tag)
            .output()?;

        if !output.status.success() {
            return Ok(None);
        }

        let id = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if id.is_empty() {
            Ok(None)
        } else {
            Ok(Some(id))
        }
    }

    fn inspect_image(&self, image_tag: &str) -> Result<Option<ContainerImageInfo>> {
        let output = Command::new("docker")
            .arg("image")
            .arg("inspect")
            .arg(image_tag)
            .output()?;

        if !output.status.success() {
            return Ok(None);
        }

        let parsed: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        let inspect = match parsed {
            serde_json::Value::Array(mut items) => items.pop().unwrap_or(serde_json::Value::Null),
            value => value,
        };

        let architecture = inspect
            .get("Architecture")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(ToString::to_string);

        let labels = inspect
            .get("Config")
            .and_then(|v| v.get("Labels"))
            .and_then(|v| v.as_object())
            .map(|obj| {
                obj.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default();

        let env = inspect
            .get("Config")
            .and_then(|v| v.get("Env"))
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(ToString::to_string))
                    .collect()
            })
            .unwrap_or_default();

        Ok(Some(ContainerImageInfo {
            architecture,
            config: ContainerImageConfig { labels, env },
        }))
    }

    fn image_label(&self, image_tag: &str, label_key: &str) -> Result<Option<String>> {
        let inspect = self.inspect_image(image_tag)?;
        let value = inspect
            .as_ref()
            .and_then(|v| v.config.labels.get(label_key))
            .cloned();
        Ok(value)
    }

    fn probe_image_info(
        &self,
        image_tag: &str,
        user: Option<&str>,
    ) -> Result<Option<super::ContainerProbeInfo>> {
        Ok(Self::probe_image_info_inner(image_tag, user))
    }

    fn get_host_address(&self) -> String {
        "host.docker.internal".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_host_port_ipv4() {
        assert_eq!(parse_host_port("0.0.0.0:49152\n"), Some(49152));
    }

    #[test]
    fn test_parse_host_port_ipv6() {
        assert_eq!(parse_host_port(":::49152\n"), Some(49152));
    }

    #[test]
    fn test_parse_host_port_empty() {
        assert_eq!(parse_host_port(""), None);
    }
}
