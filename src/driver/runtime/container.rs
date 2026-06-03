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
    collections::HashSet,
    path::Path,
    process::{Command, Stdio},
};

use crate::error::Error;
use crate::error::Result;

use crate::config::ContainerRuntimeConfig;
use crate::driver::runtime::RuntimeParameters;
use tracing::{debug, trace, warn};

use super::{ContainerImageConfig, ContainerImageInfo, ContainerRuntime, stream_build_output};

const AUTO_HOST_PORT_MIN: u16 = 30001;
const AUTO_HOST_PORT_PICK_ATTEMPTS: usize = 128;
const CONTAINER_START_MAX_ATTEMPTS: usize = 3;

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

fn parse_host_port_from_text(output: &str) -> Option<u16> {
    output.lines().find_map(|line| {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return None;
        }

        // Handles formats such as:
        // - 0.0.0.0:49152
        // - :::49152
        // - 127.0.0.1:49152->22/tcp
        let candidate = trimmed
            .split_once("->")
            .map(|(left, _)| left)
            .unwrap_or(trimmed);

        candidate
            .rsplit(':')
            .next()
            .and_then(|port| port.parse::<u16>().ok())
    })
}

fn parse_host_port_from_mapping(mapping: &str) -> Option<u16> {
    mapping
        .split(':')
        .next()
        .and_then(|s| s.parse::<u16>().ok())
}

fn allocate_auto_host_port_with_picker<F>(
    used_host_ports: &HashSet<u16>,
    mut picker: F,
) -> Result<u16>
where
    F: FnMut() -> Option<u16>,
{
    for _ in 0..AUTO_HOST_PORT_PICK_ATTEMPTS {
        let candidate = match picker() {
            Some(port) => port,
            None => continue,
        };

        if candidate < AUTO_HOST_PORT_MIN || used_host_ports.contains(&candidate) {
            continue;
        }

        return Ok(candidate);
    }

    Err(Error::runtime(format!(
        "Failed to allocate an unused host port above {}",
        AUTO_HOST_PORT_MIN - 1
    )))
}

fn resolve_container_runtime_ports(
    ports: &[crate::devcontainer::ForwardPort],
) -> Result<Vec<crate::devcontainer::ForwardPort>> {
    resolve_container_runtime_ports_with_picker(ports, || {
        openport::pick_unused_port(AUTO_HOST_PORT_MIN..=u16::MAX)
    })
}

fn resolve_container_runtime_ports_with_picker<F>(
    ports: &[crate::devcontainer::ForwardPort],
    mut picker: F,
) -> Result<Vec<crate::devcontainer::ForwardPort>>
where
    F: FnMut() -> Option<u16>,
{
    use crate::devcontainer::ForwardPort;

    let mut used_host_ports = HashSet::new();
    for port in ports {
        if let ForwardPort::HostPort(mapping) = port
            && let Some(host_port) = parse_host_port_from_mapping(mapping)
        {
            used_host_ports.insert(host_port);
        }
    }

    let mut resolved = Vec::with_capacity(ports.len());
    for port in ports {
        match port {
            ForwardPort::Port(container_port) => {
                let host_port = allocate_auto_host_port_with_picker(&used_host_ports, &mut picker)?;
                used_host_ports.insert(host_port);
                resolved.push(ForwardPort::HostPort(format!(
                    "{}:{}",
                    host_port, container_port
                )));
            }
            ForwardPort::HostPort(mapping) => resolved.push(ForwardPort::HostPort(mapping.clone())),
        }
    }

    Ok(resolved)
}

fn is_host_port_conflict_error(stderr: &str, stdout: &str) -> bool {
    let combined = format!("{}\n{}", stderr, stdout).to_ascii_lowercase();
    [
        "address already in use",
        "already allocated",
        "port is in use",
        "failed to expose port",
        "port conflict",
    ]
    .iter()
    .any(|needle| combined.contains(needle))
}

fn extract_mapped_port_from_value(value: &serde_json::Value, container_port: u16) -> Option<u16> {
    match value {
        serde_json::Value::Object(map) => {
            // Match common schema keys used by container runtimes.
            if let (Some(container), Some(host)) = (
                map.get("containerPort")
                    .or_else(|| map.get("container_port")),
                map.get("hostPort").or_else(|| map.get("host_port")),
            ) {
                let container = container
                    .as_u64()
                    .and_then(|v| u16::try_from(v).ok())
                    .or_else(|| container.as_str().and_then(|v| v.parse::<u16>().ok()));
                let host = host
                    .as_u64()
                    .and_then(|v| u16::try_from(v).ok())
                    .or_else(|| host.as_str().and_then(|v| v.parse::<u16>().ok()));

                if container == Some(container_port) {
                    return host;
                }
            }

            map.values()
                .find_map(|nested| extract_mapped_port_from_value(nested, container_port))
        }
        serde_json::Value::Array(items) => items
            .iter()
            .find_map(|item| extract_mapped_port_from_value(item, container_port)),
        serde_json::Value::String(s) => {
            if s.contains("->") && s.ends_with(&format!("{}{}", container_port, "/tcp")) {
                parse_host_port_from_text(s)
            } else {
                None
            }
        }
        _ => None,
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

    fn probe_image_info_inner(
        image_tag: &str,
        user: Option<&str>,
    ) -> Option<super::ContainerProbeInfo> {
        const PROBE_CMD: &str = "printf '%s\\n%s\\n%s' \"$(id -un)\" \"$HOME\" \"$PATH\"";
        let shells = ["sh", "/bin/sh", "bash", "/bin/bash"];
        for shell in shells {
            let mut cmd = Command::new("container");
            cmd.arg("run").arg("--rm");
            if let Some(u) = user {
                cmd.arg("--user").arg(u);
            }
            cmd.arg("--entrypoint")
                .arg(shell)
                .arg(image_tag)
                .arg("-lc")
                .arg(PROBE_CMD);

            let output = cmd.output().ok()?;
            if !output.status.success() {
                continue;
            }
            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut lines = stdout.lines();
            let probe_user = lines.next().unwrap_or_default().trim().to_string();
            let home = lines.next().unwrap_or_default().trim().to_string();
            let path = lines.next().unwrap_or_default().trim().to_string();
            if !probe_user.is_empty() {
                return Some(super::ContainerProbeInfo {
                    user: probe_user,
                    home,
                    path,
                });
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
        let RuntimeParameters {
            additional_mounts,
            ports,
            requires_privileged,
            platform_architecture_translation,
        } = runtime_parameters;

        let mut last_error = None;

        for attempt in 1..=CONTAINER_START_MAX_ATTEMPTS {
            let resolved_ports = resolve_container_runtime_ports(&ports)?;
            debug!(
                "Container runtime port mappings (attempt {}): {:?}",
                attempt, resolved_ports
            );

            let mut cmd = Command::new("container");

            cmd.arg("run").arg("-d");

            if platform_architecture_translation {
                cmd.arg("--rosetta");
            }

            cmd.arg("-v").arg(volume_mount).arg("-l").arg(label);

            // Add CPU and memory limits from config
            let memory = self.config.run_memory.as_deref().unwrap_or("8g");
            cmd.arg("--memory").arg(memory);
            let cpu = self.config.run_cpu.as_deref().unwrap_or("2");
            cmd.arg("--cpus").arg(cpu);

            // Add privileged flag if required
            if requires_privileged {
                cmd.arg("--virtualization");
            }

            // Add environment variables
            for env_var in env_vars {
                cmd.arg("-e").arg(env_var);
            }

            // Add excluded ports environment variable for agent
            let excluded_ports: Vec<String> = resolved_ports
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
            for mount in additional_mounts.clone() {
                match mount {
                    crate::devcontainer::Mount::String(mount_str) => {
                        cmd.arg("-v").arg(mount_str);
                    }
                    crate::devcontainer::Mount::Structured(structured) => {
                        let mount_arg = match &structured.mount_type {
                            crate::devcontainer::MountType::Bind => {
                                if let Some(source) = &structured.source {
                                    format!(
                                        "type=bind,source={},target={}",
                                        source, structured.target
                                    )
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
            for port in resolved_ports {
                let port_number = match port {
                    crate::devcontainer::ForwardPort::Port(port_number) => port_number.to_string(),
                    crate::devcontainer::ForwardPort::HostPort(port) => port,
                };
                cmd.arg("-p").arg(port_number);
            }

            cmd.arg(image_tag);

            let result = cmd.output()?;

            if result.status.code() == Some(0) {
                let container_id = String::from_utf8_lossy(&result.stdout).trim().to_string();
                if container_id.is_empty() {
                    return Err(Error::runtime(
                        "Container start command succeeded but returned an empty container id"
                            .to_string(),
                    ));
                }
                return Ok(Box::new(ContainerCliHandle { id: container_id }));
            }

            let exit_code = result
                .status
                .code()
                .map_or("terminated by signal".to_string(), |code| {
                    format!("exit code {}", code)
                });
            let stderr = String::from_utf8_lossy(&result.stderr).trim().to_string();
            let stdout = String::from_utf8_lossy(&result.stdout).trim().to_string();

            let mut details = format!("Container start command failed ({})", exit_code);
            if !stderr.is_empty() {
                details.push_str(&format!("\nstderr: {}", stderr));
            }
            if !stdout.is_empty() {
                details.push_str(&format!("\nstdout: {}", stdout));
            }

            let err = Error::runtime(details);
            if attempt < CONTAINER_START_MAX_ATTEMPTS
                && is_host_port_conflict_error(&stderr, &stdout)
            {
                warn!(
                    "Container start failed due to host port conflict (attempt {}/{}), retrying with new host ports",
                    attempt, CONTAINER_START_MAX_ATTEMPTS
                );
                last_error = Some(err);
                continue;
            }

            return Err(err);
        }

        Err(last_error
            .unwrap_or_else(|| Error::runtime("Container start failed after retries".to_string())))
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
            let stderr = String::from_utf8_lossy(&result.stderr).trim().to_string();
            return Err(Error::runtime(format!(
                "Container exec command failed: {}",
                stderr
            )));
        }

        Ok(())
    }

    fn mapped_host_port(&self, container_id: &str, container_port: u16) -> Result<Option<u16>> {
        let direct = Command::new("container")
            .arg("port")
            .arg(container_id)
            .arg(format!("{}/tcp", container_port))
            .output();

        if let Ok(output) = direct
            && output.status.success()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(port) = parse_host_port_from_text(&stdout) {
                return Ok(Some(port));
            }
        }

        let output = Command::new("container")
            .arg("list")
            .arg("--format")
            .arg("json")
            .output()?;

        if !output.status.success() {
            return Ok(None);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let parsed: serde_json::Value = serde_json::from_str(&stdout)?;

        let container = parsed.as_array().and_then(|items| {
            items.iter().find(|item| {
                item.get("configuration")
                    .and_then(|cfg| cfg.get("id"))
                    .and_then(|id| id.as_str())
                    .map(|id| id == container_id)
                    .unwrap_or(false)
            })
        });

        let mapped =
            container.and_then(|item| extract_mapped_port_from_value(item, container_port));
        Ok(mapped)
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

    fn inspect_image(&self, image_tag: &str) -> Result<Option<ContainerImageInfo>> {
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

        let inspect: serde_json::Value = serde_json::from_slice(&output.stdout)?;

        let architecture = inspect
            .get("architecture")
            .or_else(|| inspect.get("Architecture"))
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(ToString::to_string);

        let config = inspect.get("config").or_else(|| inspect.get("Config"));

        let labels = config
            .and_then(|v| v.get("labels").or_else(|| v.get("Labels")))
            .and_then(|v| v.as_object())
            .map(|obj| {
                obj.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default();

        let env = config
            .and_then(|v| v.get("env").or_else(|| v.get("Env")))
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
        // Container's inspect JSON uses both lowercase and Docker-style key names.
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
        "host.container.internal".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_host_port_from_mapping() {
        assert_eq!(parse_host_port_from_mapping("49152:22"), Some(49152));
        assert_eq!(parse_host_port_from_mapping("not-a-port:22"), None);
    }

    #[test]
    fn test_resolve_container_runtime_ports_maps_plain_ports_above_30000() {
        let input = vec![
            crate::devcontainer::ForwardPort::Port(22),
            crate::devcontainer::ForwardPort::Port(3000),
        ];

        let mut picks = vec![Some(29999), Some(40001), Some(40002)].into_iter();
        let resolved =
            resolve_container_runtime_ports_with_picker(&input, || picks.next().flatten())
                .expect("resolve ports");
        assert_eq!(resolved.len(), 2);

        for mapped in resolved {
            match mapped {
                crate::devcontainer::ForwardPort::HostPort(mapping) => {
                    let parts: Vec<&str> = mapping.split(':').collect();
                    assert_eq!(parts.len(), 2);
                    let host_port = parts[0].parse::<u16>().expect("host port number");
                    assert!(host_port >= AUTO_HOST_PORT_MIN);
                }
                crate::devcontainer::ForwardPort::Port(_) => {
                    panic!("expected host:container mapping")
                }
            }
        }
    }

    #[test]
    fn test_resolve_container_runtime_ports_preserves_explicit_mappings() {
        let input = vec![crate::devcontainer::ForwardPort::HostPort(
            "40000:22".to_string(),
        )];
        let resolved = resolve_container_runtime_ports_with_picker(&input, || Some(40001))
            .expect("resolve ports");

        assert_eq!(resolved.len(), 1);
        assert!(matches!(
            &resolved[0],
            crate::devcontainer::ForwardPort::HostPort(mapping) if mapping == "40000:22"
        ));
    }

    #[test]
    fn test_resolve_container_runtime_ports_avoids_explicit_host_port_collision() {
        let input = vec![
            crate::devcontainer::ForwardPort::HostPort("41000:8080".to_string()),
            crate::devcontainer::ForwardPort::Port(3000),
        ];
        let mut picks = vec![Some(41000), Some(42000)].into_iter();
        let resolved =
            resolve_container_runtime_ports_with_picker(&input, || picks.next().flatten())
                .expect("resolve ports");

        assert_eq!(resolved.len(), 2);
        assert!(matches!(
            &resolved[0],
            crate::devcontainer::ForwardPort::HostPort(mapping) if mapping == "41000:8080"
        ));
        assert!(matches!(
            &resolved[1],
            crate::devcontainer::ForwardPort::HostPort(mapping) if mapping == "42000:3000"
        ));
    }

    #[test]
    fn test_is_host_port_conflict_error() {
        assert!(is_host_port_conflict_error(
            "bind: address already in use",
            ""
        ));
        assert!(!is_host_port_conflict_error("failed to pull image", ""));
    }

    #[test]
    fn test_parse_host_port_from_text_arrow_format() {
        assert_eq!(
            parse_host_port_from_text("127.0.0.1:49152->22/tcp"),
            Some(49152)
        );
    }

    #[test]
    fn test_extract_mapped_port_from_value_common_shape() {
        let value = serde_json::json!({
            "ports": [
                {"containerPort": 22, "hostPort": 49152}
            ]
        });

        assert_eq!(extract_mapped_port_from_value(&value, 22), Some(49152));
    }
}
