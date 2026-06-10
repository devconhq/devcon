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
    net::TcpListener,
    path::Path,
    process::{Command, Stdio},
};

use crate::error::Error;
use crate::error::Result;

use crate::config::ContainerRuntimeConfig;
use crate::driver::runtime::RuntimeParameters;
use tracing::{debug, trace};

use super::{
    ContainerImageConfig, ContainerImageInfo, ContainerRuntime, FeatureProgressItem,
    stream_build_output,
};

const AUTO_HOST_PORT_MIN: u16 = 30001;
const AUTO_HOST_PORT_PICK_ATTEMPTS: usize = 128;

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
    let mut picker_none = 0usize;
    let mut rejected_below_min = Vec::new();
    let mut rejected_used = Vec::new();
    let mut rejected_unbindable = Vec::new();

    let probe_bindable = |port: u16| -> bool { TcpListener::bind(("0.0.0.0", port)).is_ok() };

    let find_next_bindable = |start_port: u16| -> Option<u16> {
        let mut candidate = start_port.max(AUTO_HOST_PORT_MIN);
        while candidate <= u16::MAX {
            if !used_host_ports.contains(&candidate) && probe_bindable(candidate) {
                return Some(candidate);
            }

            if candidate == u16::MAX {
                break;
            }
            candidate += 1;
        }
        None
    };

    for attempt in 1..=AUTO_HOST_PORT_PICK_ATTEMPTS {
        let candidate = match picker() {
            Some(port) => port,
            None => {
                picker_none += 1;
                trace!(
                    "Host port picker attempt {}/{} returned no candidate",
                    attempt, AUTO_HOST_PORT_PICK_ATTEMPTS
                );
                continue;
            }
        };

        if candidate < AUTO_HOST_PORT_MIN {
            if rejected_below_min.len() < 8 {
                rejected_below_min.push(candidate);
            }
            trace!(
                "Rejected candidate host port {}: below minimum {} (attempt {}/{})",
                candidate, AUTO_HOST_PORT_MIN, attempt, AUTO_HOST_PORT_PICK_ATTEMPTS
            );
            continue;
        }

        if used_host_ports.contains(&candidate) {
            if rejected_used.len() < 8 {
                rejected_used.push(candidate);
            }
            trace!(
                "Rejected candidate host port {}: already used by explicit/selected mapping (attempt {}/{})",
                candidate, attempt, AUTO_HOST_PORT_PICK_ATTEMPTS
            );

            if let Some(next_port) = find_next_bindable(candidate.saturating_add(1)) {
                debug!(
                    "Picker returned already-used port {}; selected next bindable host port {}",
                    candidate, next_port
                );
                return Ok(next_port);
            }

            continue;
        }

        if !probe_bindable(candidate) {
            if rejected_unbindable.len() < 8 {
                rejected_unbindable.push(candidate);
            }
            trace!(
                "Rejected candidate host port {}: not bindable on host interface 0.0.0.0 (attempt {}/{})",
                candidate, attempt, AUTO_HOST_PORT_PICK_ATTEMPTS
            );

            if let Some(next_port) = find_next_bindable(candidate.saturating_add(1)) {
                debug!(
                    "Candidate host port {} not bindable; selected next bindable host port {}",
                    candidate, next_port
                );
                return Ok(next_port);
            }

            continue;
        }

        debug!(
            "Selected host port {} after {} picker attempts (none={}, below_min_rejections={}, used_rejections={}, unbindable_rejections={})",
            candidate,
            attempt,
            picker_none,
            rejected_below_min.len(),
            rejected_used.len(),
            rejected_unbindable.len()
        );
        return Ok(candidate);
    }

    let mut used_ports: Vec<u16> = used_host_ports.iter().copied().collect();
    used_ports.sort_unstable();

    Err(Error::runtime(format!(
        "Failed to allocate an unused host port above {} after {} attempts (picker returned None {} times, below-min rejections sample: {:?}, already-used rejections sample: {:?}, unbindable rejections sample: {:?}, currently reserved host ports: {:?})",
        AUTO_HOST_PORT_MIN - 1,
        AUTO_HOST_PORT_PICK_ATTEMPTS,
        picker_none,
        rejected_below_min,
        rejected_used,
        rejected_unbindable,
        used_ports
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

    debug!("Resolving container runtime ports from config: {:?}", ports);

    let mut used_host_ports = HashSet::new();
    for port in ports {
        if let ForwardPort::HostPort(mapping) = port
            && let Some(host_port) = parse_host_port_from_mapping(mapping)
        {
            used_host_ports.insert(host_port);
        }
    }

    let mut explicit_host_ports: Vec<u16> = used_host_ports.iter().copied().collect();
    explicit_host_ports.sort_unstable();
    debug!(
        "Explicit host ports already reserved before auto-allocation: {:?}",
        explicit_host_ports
    );

    let mut resolved = Vec::with_capacity(ports.len());
    for (index, port) in ports.iter().enumerate() {
        match port {
            ForwardPort::Port(container_port) => {
                let host_port = allocate_auto_host_port_with_picker(&used_host_ports, &mut picker)
                    .map_err(|e| {
                        Error::runtime(format!(
                            "Failed to resolve host port mapping for container port {} at index {}: {}",
                            container_port, index, e
                        ))
                    })?;
                used_host_ports.insert(host_port);
                debug!(
                    "Mapped container port {} to auto-selected host port {}",
                    container_port, host_port
                );
                resolved.push(ForwardPort::HostPort(format!(
                    "{}:{}",
                    host_port, container_port
                )));
            }
            ForwardPort::HostPort(mapping) => {
                trace!(
                    "Keeping explicit host:container mapping '{}' at index {}",
                    mapping, index
                );
                resolved.push(ForwardPort::HostPort(mapping.clone()));
            }
        }
    }

    Ok(resolved)
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

fn parse_devcon_images_from_container_list(parsed: &serde_json::Value) -> Vec<String> {
    let items: Vec<&serde_json::Value> = match parsed {
        serde_json::Value::Array(arr) => arr.iter().collect(),
        serde_json::Value::Object(_) => vec![parsed],
        _ => Vec::new(),
    };

    items
        .iter()
        .filter_map(|image| {
            trace!("Inspecting image: {}", image);

            let reference = image
                .get("reference")
                .or_else(|| image.get("Reference"))
                .or_else(|| image.get("name"))
                .or_else(|| image.get("Name"))
                .and_then(|value| value.as_str())
                .map(str::trim)
                .filter(|value| !value.is_empty())?;

            let last_segment = reference.rsplit('/').next().unwrap_or(reference);
            if last_segment.starts_with("devcon-") {
                Some(reference.to_string())
            } else {
                None
            }
        })
        .collect()
}

fn container_inspect_entry(parsed: &serde_json::Value) -> Option<&serde_json::Value> {
    match parsed {
        serde_json::Value::Array(items) => items.first(),
        serde_json::Value::Object(_) => Some(parsed),
        _ => None,
    }
}

fn extract_container_image_id(parsed: &serde_json::Value) -> Option<String> {
    let entry = container_inspect_entry(parsed)?;

    let id = entry
        .get("id")
        .or_else(|| entry.get("Id"))
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string);

    if id.is_some() {
        return id;
    }

    entry
        .get("configuration")
        .or_else(|| entry.get("Configuration"))
        .and_then(|value| value.get("descriptor").or_else(|| value.get("Descriptor")))
        .and_then(|value| value.get("digest").or_else(|| value.get("Digest")))
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn parse_devcon_container_entry(
    container: &serde_json::Value,
) -> Option<(String, String, String, String)> {
    let state = container
        .get("status")
        .and_then(|value| {
            value
                .as_str()
                .or_else(|| value.get("state").and_then(|state| state.as_str()))
        })
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or_default();

    let project_name = container
        .get("configuration")
        .and_then(|value| value.get("labels"))
        .and_then(|value| value.get("devcon.project"))
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())?;

    let id = container
        .get("configuration")
        .and_then(|value| value.get("id"))
        .or_else(|| container.get("id"))
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())?;

    let image_tag = container
        .get("configuration")
        .and_then(|value| value.get("image"))
        .and_then(|value| {
            value.as_str().or_else(|| {
                value
                    .get("reference")
                    .and_then(|reference| reference.as_str())
            })
        })
        .map(str::trim)
        .filter(|value| !value.is_empty())?;

    Some((
        state.to_string(),
        format!("devcon.{}", project_name),
        id.to_string(),
        image_tag.to_string(),
    ))
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
        const PROBE_CMD: &str =
            "printf '%s\\n%s\\n%s\\n%s' \"$(id -un)\" \"$HOME\" \"$PATH\" \"$(uname -m)\"";
        let shells = ["sh", "/bin/sh", "bash", "/bin/bash"];
        debug!(
            "Probing container image runtime environment for image '{}' with user hint {:?}",
            image_tag, user
        );
        for use_rosetta in [true, false] {
            for shell in shells {
                trace!(
                    "Attempting container probe with shell '{}' for image '{}' (rosetta={})",
                    shell, image_tag, use_rosetta
                );
                let mut cmd = Command::new("container");
                cmd.arg("run");
                if use_rosetta {
                    cmd.arg("--rosetta");
                }
                cmd.arg("--rm");
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
                            "Container probe execution failed for shell '{}' on image '{}' (rosetta={}): {}",
                            shell, image_tag, use_rosetta, err
                        );
                        continue;
                    }
                };
                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    trace!(
                        "Container probe failed for shell '{}' on image '{}' with status {:?} (rosetta={}), stderr: {}",
                        shell,
                        image_tag,
                        output.status.code(),
                        use_rosetta,
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
                        "Container probe succeeded for image '{}' using shell '{}' (rosetta={}): user='{}', home='{}', path_present={}, architecture={:?}",
                        image_tag,
                        shell,
                        use_rosetta,
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
                    "Container probe output for shell '{}' on image '{}' did not include a runtime user (rosetta={})",
                    shell, image_tag, use_rosetta
                );
            }
        }

        debug!(
            "Container probe did not find a suitable shell/runtime user for image '{}'",
            image_tag
        );
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

                let (state, container_name, id, image_tag) =
                    parse_devcon_container_entry(container)?;
                if !all && state != "running" {
                    return None;
                }

                debug!("Found container with ID: {}", id);

                let handle = ContainerCliHandle { id: id.to_string() };
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
        phase_label: Option<&str>,
        feature_progress: Option<&[FeatureProgressItem]>,
        silent: bool,
    ) -> Result<()> {
        self.build_with_args(
            dockerfile_path,
            context_path,
            image_tag,
            &None,
            &None,
            &None,
            phase_label,
            feature_progress,
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
        phase_label: Option<&str>,
        feature_progress: Option<&[FeatureProgressItem]>,
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

        let result = stream_build_output(child, silent, phase_label, feature_progress)?;

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

        trace!(
            "Container start attempt with requested forwards: {:?}",
            ports
        );
        let resolved_ports = resolve_container_runtime_ports(&ports)?;
        debug!("Container runtime port mappings: {:?}", resolved_ports);

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
        for port in resolved_ports {
            let port_number = match port {
                crate::devcontainer::ForwardPort::Port(port_number) => port_number.to_string(),
                crate::devcontainer::ForwardPort::HostPort(port) => port,
            };
            cmd.arg("-p").arg(port_number);
        }

        cmd.arg(image_tag);
        debug!("Executing container start command: {:?}", cmd);

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

        Err(Error::runtime(details))
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

        let parsed: serde_json::Value = serde_json::from_str(&stdout)?;
        Ok(parse_devcon_images_from_container_list(&parsed))
    }

    fn image_id(&self, image_tag: &str) -> Result<Option<String>> {
        let output = Command::new("container")
            .arg("image")
            .arg("inspect")
            .arg(image_tag)
            .output()?;

        if !output.status.success() {
            return Ok(None);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let image: serde_json::Value =
            serde_json::from_str(&stdout).unwrap_or(serde_json::Value::Null);
        Ok(extract_container_image_id(&image))
    }

    fn inspect_image(&self, image_tag: &str) -> Result<Option<ContainerImageInfo>> {
        let output = Command::new("container")
            .arg("image")
            .arg("inspect")
            .arg(image_tag)
            .output()?;

        if !output.status.success() {
            return Ok(None);
        }

        let inspect: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        let entry = match container_inspect_entry(&inspect) {
            Some(entry) => entry,
            None => return Ok(None),
        };

        let variant_config = entry
            .get("variants")
            .or_else(|| entry.get("Variants"))
            .and_then(|value| value.as_array())
            .and_then(|variants| variants.first())
            .and_then(|variant| variant.get("config").or_else(|| variant.get("Config")));

        let architecture = variant_config
            .and_then(|value| {
                value
                    .get("architecture")
                    .or_else(|| value.get("Architecture"))
            })
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(ToString::to_string);

        let config =
            variant_config.and_then(|value| value.get("config").or_else(|| value.get("Config")));

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

        let mapping = match &resolved[1] {
            crate::devcontainer::ForwardPort::HostPort(mapping) => mapping,
            crate::devcontainer::ForwardPort::Port(_) => panic!("expected host:container mapping"),
        };
        let parts: Vec<&str> = mapping.split(':').collect();
        assert_eq!(parts.len(), 2);
        let host_port = parts[0].parse::<u16>().expect("host port number");
        let container_port = parts[1].parse::<u16>().expect("container port number");
        assert_eq!(container_port, 3000);
        assert_ne!(host_port, 41000);
        assert!(host_port >= AUTO_HOST_PORT_MIN);
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

    #[test]
    fn test_parse_devcon_images_from_container_list_matches_registry_prefix() {
        let parsed = serde_json::json!([
            {"reference": "ghcr.io/org/devcon-workspace:latest"},
            {"reference": "mcr.microsoft.com/devcontainers/base:ubuntu"}
        ]);

        let images = parse_devcon_images_from_container_list(&parsed);
        assert_eq!(
            images,
            vec!["ghcr.io/org/devcon-workspace:latest".to_string()]
        );
    }

    #[test]
    fn test_parse_devcon_images_from_container_list_supports_fallback_keys() {
        let parsed = serde_json::json!({"Name": "devcon-sample:latest"});

        let images = parse_devcon_images_from_container_list(&parsed);
        assert_eq!(images, vec!["devcon-sample:latest".to_string()]);
    }

    #[test]
    fn test_extract_container_image_id_prefers_top_level_id() {
        let parsed = serde_json::json!([
            {
                "id": "47b2ebf94dcd70a2761c8fe11c0d4ae67b2c062e6e1325a2123740eb163b2859",
                "configuration": {
                    "descriptor": {
                        "digest": "sha256:47b2ebf94dcd70a2761c8fe11c0d4ae67b2c062e6e1325a2123740eb163b2859"
                    }
                }
            }
        ]);

        let id = extract_container_image_id(&parsed);
        assert_eq!(
            id,
            Some("47b2ebf94dcd70a2761c8fe11c0d4ae67b2c062e6e1325a2123740eb163b2859".to_string())
        );
    }

    #[test]
    fn test_extract_container_image_id_falls_back_to_descriptor_digest() {
        let parsed = serde_json::json!({
            "configuration": {
                "descriptor": {
                    "digest": "sha256:abc123"
                }
            }
        });

        let id = extract_container_image_id(&parsed);
        assert_eq!(id, Some("sha256:abc123".to_string()));
    }

    #[test]
    fn test_parse_devcon_container_entry_supports_status_state_and_image_reference() {
        let parsed = serde_json::json!({
            "configuration": {
                "id": "8212f6e0-4f97-44a5-ba79-5c0468af80f2",
                "labels": {
                    "devcon.project": "terraform-provider-restapi"
                },
                "image": {
                    "reference": "devcon-terraform-provider-restapi:latest"
                }
            },
            "status": {
                "state": "running"
            }
        });

        let entry = parse_devcon_container_entry(&parsed);
        assert_eq!(
            entry,
            Some((
                "running".to_string(),
                "devcon.terraform-provider-restapi".to_string(),
                "8212f6e0-4f97-44a5-ba79-5c0468af80f2".to_string(),
                "devcon-terraform-provider-restapi:latest".to_string(),
            ))
        );
    }

    #[test]
    fn test_parse_devcon_container_entry_returns_none_without_project_label() {
        let parsed = serde_json::json!({
            "configuration": {
                "id": "buildkit",
                "image": {
                    "reference": "ghcr.io/apple/container-builder-shim/builder:0.12.0"
                }
            },
            "status": {
                "state": "running"
            }
        });

        assert_eq!(parse_devcon_container_entry(&parsed), None);
    }
}
