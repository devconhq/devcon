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
use tracing::trace;

use crate::config::DockerRuntimeConfig;
use crate::driver::runtime::RuntimeParameters;

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

/// Docker CLI runtime implementation.
pub struct DockerRuntime {
    #[allow(dead_code)]
    config: DockerRuntimeConfig,
}

impl DockerRuntime {
    pub fn new(config: DockerRuntimeConfig) -> Self {
        Self { config }
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
        cmd.arg("run")
            .arg("-d")
            .arg("-v")
            .arg(volume_mount)
            .arg("--label")
            .arg(label);

        // Add privileged flag if required
        if runtime_parameters.requires_privileged {
            cmd.arg("--privileged");
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
            return Err(Error::runtime("Docker run command failed"));
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

        let result = cmd.arg(container_handle.id()).args(command).output()?;

        if result.status.code() != Some(0) {
            return Err(Error::runtime("Docker exec command failed"));
        }

        Ok(())
    }

    fn list(&self) -> Result<Vec<(String, String, Box<dyn super::ContainerHandle>)>> {
        let output = Command::new("docker")
            .arg("ps")
            .arg("--filter")
            .arg("label=devcon.project")
            .arg("--format")
            .arg("{{json .}}")
            .output()?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        let mut result: Vec<(String, String, Box<dyn super::ContainerHandle>)> = Vec::new();

        // Docker outputs one JSON object per line, not an array
        for line in stdout.lines() {
            if line.trim().is_empty() {
                continue;
            }

            let container: serde_json::Value = serde_json::from_str(line)?;

            // Parse labels to find devcon.project label value
            let labels = container["Labels"].as_str().unwrap_or_default();
            let mut container_name = String::new();

            // Labels format: "key1=value1,key2=value2"
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

    fn get_host_address(&self) -> String {
        "host.docker.internal".to_string()
    }
}
