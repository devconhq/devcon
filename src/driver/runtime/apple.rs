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

//! # Apple Container Runtime
//!
//! Implementation of ContainerRuntime trait for Apple's `container` CLI.

use std::{
    path::Path,
    process::{Command, Stdio},
    time::Duration,
};

use crate::error::Error;
use crate::error::Result;

use crate::config::AppleRuntimeConfig;
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

/// Apple's container CLI runtime implementation.
pub struct AppleRuntime {
    config: AppleRuntimeConfig,
}

/// Handle for an Apple container instance.
pub struct AppleContainerHandle {
    id: String,
}

impl super::ContainerHandle for AppleContainerHandle {
    fn id(&self) -> &str {
        &self.id
    }
}

impl AppleRuntime {
    pub fn new(config: AppleRuntimeConfig) -> Self {
        Self { config }
    }
}

impl ContainerRuntime for AppleRuntime {
    fn build(
        &self,
        dockerfile_path: &Path,
        context_path: &Path,
        image_tag: &str,
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
        image_tag: &str,
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

        cmd.arg("-f").arg(dockerfile_path).arg("-t").arg(image_tag);

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

        Ok(Box::new(AppleContainerHandle {
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

        cmd.arg(container_handle.id()).args(command);

        debug!("Executing container exec command: {:?}", cmd);
        let result = cmd.status()?;

        if result.code() != Some(0) {
            return Err(Error::runtime("Container exec command failed"));
        }

        Ok(())
    }

    fn list(&self) -> Result<Vec<(String, String, Box<dyn super::ContainerHandle>)>> {
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
                let handle = AppleContainerHandle { id };
                Some((
                    container_name,
                    image_tag,
                    Box::new(handle) as Box<dyn super::ContainerHandle>,
                ))
            })
            .collect();

        Ok(result)
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

    fn get_host_address(&self) -> String {
        "host.container.internal".to_string()
    }
}
