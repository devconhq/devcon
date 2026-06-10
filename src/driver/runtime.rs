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

//! # Container Runtime Abstraction
//!
//! This module provides a trait-based abstraction for container runtimes,
//! allowing DevCon to work with different container CLIs (container,
//! Docker, Podman, etc.).

use std::{
    collections::{HashMap, HashSet},
    io::{BufRead, BufReader, IsTerminal},
    path::Path,
    process::Child,
    sync::atomic::{AtomicBool, Ordering},
    sync::{Arc, Mutex},
    time::Duration,
};

use crate::error::Result;
use console::Style;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};

pub mod container;
pub mod docker;

pub const FEATURE_DONE_MARKER_PREFIX: &str = "DEVCON_FEATURE_DONE::";
const POST_PROCESSING_IMAGE_LABEL: &str = "Post Processing Image";

#[derive(Debug, Clone)]
pub struct FeatureProgressItem {
    pub id: String,
    pub label: String,
}

fn extract_feature_done_marker(line: &str) -> Option<String> {
    let marker_pos = line.find(FEATURE_DONE_MARKER_PREFIX)?;
    let token = &line[(marker_pos + FEATURE_DONE_MARKER_PREFIX.len())..];
    let token = token
        .trim()
        .trim_matches(|c| matches!(c, '"' | '\'' | '`'))
        .trim_end_matches(['"', '\'', '`', ',', ';', ')', ']', '}']);
    if token.is_empty() {
        return None;
    }

    let normalized = token
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .trim_matches(|c| matches!(c, '"' | '\'' | '`'))
        .trim_end_matches(['"', '\'', '`', ',', ';', ')', ']', '}']);

    if normalized.is_empty() {
        None
    } else {
        Some(normalized.to_string())
    }
}

fn active_progress_label(
    progress_items: &[FeatureProgressItem],
    completed: &HashSet<String>,
    post_processing_pending: bool,
) -> Option<String> {
    let next_feature = progress_items
        .iter()
        .find(|item| !completed.contains(&item.id))
        .map(|item| item.label.clone());

    next_feature
        .or_else(|| post_processing_pending.then_some(POST_PROCESSING_IMAGE_LABEL.to_string()))
}

/// Stream build output from a child process, rendering feature progress in-place.
///
/// In interactive terminals a `MultiProgress` is used: each feature gets its own
/// `ProgressBar` row that transitions from `[ ] label` to `[x] label` as the
/// matching `DEVCON_FEATURE_DONE::` marker arrives.  A spinner at the bottom
/// shows the current active feature and a rolling tail of the latest build line.
///
/// In non-interactive / piped mode the same information is emitted with plain
/// `println!` so that test harnesses can capture it.
pub fn stream_build_output(
    mut child: Child,
    silent: bool,
    phase_label: Option<&str>,
    feature_progress: Option<&[FeatureProgressItem]>,
) -> Result<std::process::ExitStatus> {
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

    let phase_label = phase_label.unwrap_or("Building image").to_string();

    let progress_items = feature_progress.unwrap_or(&[]);
    let progress_items_arc: Arc<Vec<FeatureProgressItem>> = Arc::new(progress_items.to_vec());
    let feature_lookup: Arc<HashMap<String, String>> = Arc::new(
        progress_items
            .iter()
            .map(|item| (item.id.clone(), item.label.clone()))
            .collect(),
    );
    let completed_features: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
    let has_feature_progress = !progress_items.is_empty();
    let post_processing_done = Arc::new(AtomicBool::new(!has_feature_progress));

    // Keep latest build line for spinner tail status.
    let latest_line: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));

    // Buffer all output so we can reprint on failure.
    let all_output: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let all_output_clone = Arc::clone(&all_output);

    let interactive = std::io::stdout().is_terminal() && std::io::stderr().is_terminal();

    // ── MultiProgress setup (interactive only) ──────────────────────────────
    //
    // Layout (top → bottom):
    //   "  [ ] feature A"   ← ProgressBar per feature, no animation
    //   "  [ ] feature B"
    //   ...
    //   "⠹ Building … [n/total] Active: X | tail"  ← spinner
    //
    // Each feature bar is updated in-place to "[x] label" when done.
    // In non-interactive mode we fall back to plain println so tests capture it.

    let mp = MultiProgress::new();

    // Per-feature bars (interactive only; empty map otherwise).
    let feature_bars: Arc<HashMap<String, ProgressBar>> = {
        let mut map = HashMap::new();
        if !silent && interactive && !progress_items.is_empty() {
            let style = ProgressStyle::with_template("  {msg}")?;
            for item in progress_items {
                let b = mp.add(ProgressBar::new(1));
                b.set_style(style.clone());
                b.set_message(format!("[ ] {}", item.label));
                map.insert(item.id.clone(), b);
            }
        }
        Arc::new(map)
    };

    let post_processing_bar = if !silent && interactive && has_feature_progress {
        let style = ProgressStyle::with_template("  {msg}")?;
        let bar = mp.add(ProgressBar::new(1));
        bar.set_style(style);
        bar.set_message(format!("[ ] {}", POST_PROCESSING_IMAGE_LABEL));
        Some(bar)
    } else {
        None
    };

    // Spinner bar – always present (hidden when silent).
    let spinner = mp.add(ProgressBar::new_spinner());
    spinner.set_style(ProgressStyle::default_spinner().template("{spinner} {msg}")?);
    if !silent {
        if interactive && has_feature_progress {
            spinner.println("Feature build progress:");
        }
        spinner.enable_steady_tick(Duration::from_millis(100));
        spinner.set_message(format!("{}..", &phase_label));
    }

    // Non-interactive: emit plain-text headers now for test capture.
    if !silent && !interactive {
        println!("{}..", phase_label);
        if !progress_items.is_empty() {
            println!("Feature build progress:");
            for item in progress_items {
                println!("  [ ] {}", item.label);
            }
            println!("  [ ] {}", POST_PROCESSING_IMAGE_LABEL);
        }
    }

    // ── Stdout stream thread ─────────────────────────────────────────────────
    let stdout_thread = stdout.map(|stdout| {
        let all = Arc::clone(&all_output);
        let latest = Arc::clone(&latest_line);
        let feature_labels = Arc::clone(&feature_lookup);
        let completed = Arc::clone(&completed_features);
        let progress = Arc::clone(&progress_items_arc);
        let bars = Arc::clone(&feature_bars);
        let spinner_bar = spinner.clone();
        let post_done = Arc::clone(&post_processing_done);
        let phase = phase_label.clone();
        std::thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line_result in reader.lines() {
                let line = match line_result {
                    Ok(l) => l,
                    Err(_) => continue,
                };
                let clean_line = std::panic::catch_unwind(|| strip_ansi_escapes::strip_str(&line))
                    .unwrap_or_else(|_| line.clone());

                if let Some(feature_id) = extract_feature_done_marker(&clean_line) {
                    if !feature_labels.contains_key(&feature_id) {
                        continue;
                    }
                    let mut completed_guard = completed.lock().unwrap();
                    if completed_guard.insert(feature_id.clone()) {
                        let label = feature_labels
                            .get(&feature_id)
                            .cloned()
                            .unwrap_or_else(|| feature_id.clone());
                        // Update the feature row in-place (interactive) or append (non-interactive).
                        if !silent {
                            if let Some(fb) = bars.get(&feature_id) {
                                fb.finish_with_message(format!("[x] {}", label));
                            } else {
                                println!("  [x] {}", label);
                            }
                        }
                        // Advance the spinner status to the next pending feature.
                        if let Some(active) = active_progress_label(
                            &progress,
                            &completed_guard,
                            !post_done.load(Ordering::Relaxed),
                        ) {
                            let done = completed_guard.len();
                            let total = progress.len() + 1;
                            spinner_bar.set_message(format!(
                                "{phase} [{done}/{total}] Active: {active}",
                                phase = &phase,
                                done = done,
                                total = total,
                                active = active,
                            ));
                        }
                    }
                    continue;
                }

                *latest.lock().unwrap() = clean_line.clone();
                all.lock().unwrap().push(line);
            }
        })
    });

    // ── Stderr stream thread ─────────────────────────────────────────────────
    let stderr_thread = stderr.map(|stderr| {
        let all = Arc::clone(&all_output_clone);
        let latest = Arc::clone(&latest_line);
        let feature_labels = Arc::clone(&feature_lookup);
        let completed = Arc::clone(&completed_features);
        let progress = Arc::clone(&progress_items_arc);
        let bars = Arc::clone(&feature_bars);
        let spinner_bar = spinner.clone();
        let post_done = Arc::clone(&post_processing_done);
        let phase = phase_label.clone();
        std::thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line_result in reader.lines() {
                let line = match line_result {
                    Ok(l) => l,
                    Err(_) => continue,
                };
                let clean_line = std::panic::catch_unwind(|| strip_ansi_escapes::strip_str(&line))
                    .unwrap_or_else(|_| line.clone());

                if let Some(feature_id) = extract_feature_done_marker(&clean_line) {
                    if !feature_labels.contains_key(&feature_id) {
                        continue;
                    }
                    let mut completed_guard = completed.lock().unwrap();
                    if completed_guard.insert(feature_id.clone()) {
                        let label = feature_labels
                            .get(&feature_id)
                            .cloned()
                            .unwrap_or_else(|| feature_id.clone());
                        if !silent {
                            if let Some(fb) = bars.get(&feature_id) {
                                fb.finish_with_message(format!("[x] {}", label));
                            } else {
                                println!("  [x] {}", label);
                            }
                        }
                        if let Some(active) = active_progress_label(
                            &progress,
                            &completed_guard,
                            !post_done.load(Ordering::Relaxed),
                        ) {
                            let done = completed_guard.len();
                            let total = progress.len() + 1;
                            spinner_bar.set_message(format!(
                                "{phase} [{done}/{total}] Active: {active}",
                                phase = &phase,
                                done = done,
                                total = total,
                                active = active,
                            ));
                        }
                    }
                    continue;
                }

                *latest.lock().unwrap() = clean_line.clone();
                all.lock().unwrap().push(line);
            }
        })
    });

    // ── Spinner tail-update thread ───────────────────────────────────────────
    let display_latest = Arc::clone(&latest_line);
    let display_progress = Arc::clone(&progress_items_arc);
    let display_completed = Arc::clone(&completed_features);
    let display_spinner = spinner.clone();
    let display_post_done = Arc::clone(&post_processing_done);
    let display_phase = phase_label.clone();
    let keep_updating = Arc::new(AtomicBool::new(true));
    let keep_updating_thread = Arc::clone(&keep_updating);
    let update_thread = std::thread::spawn(move || {
        let dim = Style::new().dim();
        loop {
            if !keep_updating_thread.load(Ordering::Relaxed) {
                break;
            }
            let tail = display_latest.lock().unwrap().clone();
            let completed_set = display_completed.lock().unwrap().clone();
            let post_done = display_post_done.load(Ordering::Relaxed);
            let done = completed_set.len() + usize::from(post_done && !display_progress.is_empty());
            let total = display_progress.len() + usize::from(!display_progress.is_empty());

            if total > 0 {
                if let Some(active) =
                    active_progress_label(&display_progress, &completed_set, !post_done)
                {
                    if tail.is_empty() {
                        display_spinner.set_message(format!(
                            "{phase} [{done}/{total}] Active: {active}",
                            phase = &display_phase,
                        ));
                    } else {
                        display_spinner.set_message(format!(
                            "{phase} [{done}/{total}] Active: {active} | {tail}",
                            phase = &display_phase,
                            tail = dim.apply_to(&tail),
                        ));
                    }
                } else {
                    display_spinner.set_message(format!(
                        "{phase} [{done}/{total}] Finalizing",
                        phase = &display_phase,
                    ));
                }
            } else if !tail.is_empty() {
                display_spinner.set_message(format!(
                    "{phase} | {tail}",
                    phase = &display_phase,
                    tail = dim.apply_to(&tail),
                ));
            } else {
                display_spinner.set_message(display_phase.to_string());
            }

            std::thread::sleep(Duration::from_millis(100));
        }
    });

    if let Some(h) = stdout_thread {
        let _ = h.join();
    }
    if let Some(h) = stderr_thread {
        let _ = h.join();
    }

    let result = child.wait()?;

    if !silent && has_feature_progress && result.success() {
        post_processing_done.store(true, Ordering::Relaxed);
        if let Some(pb) = post_processing_bar.as_ref() {
            pb.finish_with_message(format!("[x] {}", POST_PROCESSING_IMAGE_LABEL));
        } else if !interactive {
            println!("  [x] {}", POST_PROCESSING_IMAGE_LABEL);
        }
    }

    keep_updating.store(false, Ordering::Relaxed);
    let _ = update_thread.join();
    spinner.finish_and_clear();

    if !result.success() {
        eprintln!("\n=== Build failed! Complete output: ===");
        let full_output = all_output_clone.lock().unwrap();
        for line in full_output.iter() {
            eprintln!("{}", line);
        }
        eprintln!("=== End of output ===\n");
    } else if !silent {
        println!("{} complete", phase_label);
    }

    Ok(result)
}

/// Parameters for container runtime execution.
/// This struct encapsulates additional settings for running containers.
///
///
pub struct RuntimeParameters {
    /// Additional mounts to apply to the container.
    pub additional_mounts: Vec<crate::devcontainer::Mount>,

    /// Port forwards to apply to the container.
    pub ports: Vec<crate::devcontainer::ForwardPort>,

    /// Whether the container requires privileged mode.
    pub requires_privileged: bool,

    /// Whether to enable Rosetta (container CLI) or `--platform linux/amd64` (Docker).
    /// True when the host is ARM and the image architecture is `amd64`.
    pub platform_architecture_translation: bool,
}

/// Trait for container runtime implementations.
///
/// This trait defines the interface for interacting with container runtimes,
/// allowing DevCon to work with different container CLIs transparently.
pub trait ContainerHandle: Send {
    /// Returns the container ID.
    fn id(&self) -> &str;
}

/// Static metadata about a container image returned by [`ContainerRuntime::inspect_image`].
///
/// Each runtime implementation is responsible for extracting these fields from its
/// own CLI output and constructing this struct manually. No serde annotations are
/// placed on the struct so that future runtimes remain free to use any wire format.
#[derive(Debug)]
pub struct ContainerImageInfo {
    /// CPU architecture reported by the image (e.g. `"amd64"`, `"arm64"`).
    pub architecture: Option<String>,
    /// Image configuration section (labels, environment variables, etc.).
    pub config: ContainerImageConfig,
}

/// Configuration section of a [`ContainerImageInfo`].
#[derive(Debug, Default)]
pub struct ContainerImageConfig {
    /// OCI/Docker labels attached to the image.
    pub labels: HashMap<String, String>,
    /// Environment variables baked into the image (`KEY=VALUE` format).
    pub env: Vec<String>,
}

/// Runtime-probed information about a container image.
///
/// Obtained by running a single throwaway container with a shell probe command, capturing
/// the effective user, home directory, and PATH as they are initialised at runtime
/// (shell login scripts, feature-installed env vars, etc.).
#[derive(Debug, Clone)]
pub struct ContainerProbeInfo {
    /// The effective username inside the container (output of `id -un`).
    pub user: String,
    /// The home directory of that user (`$HOME` after login-shell init).
    pub home: String,
    /// The `$PATH` after login-shell init.
    pub path: String,
    /// CPU architecture reported by `uname -m` in the probed runtime shell.
    pub architecture: Option<String>,
}

pub trait ContainerRuntime: Send {
    /// Builds a container image from a Dockerfile.
    ///
    /// # Arguments
    ///
    /// * `dockerfile_path` - Path to the Dockerfile
    /// * `context_path` - Build context directory path
    /// * `image_tag` - Tag to apply to the built image
    /// * `silent` - If true, suppress progress output to stdout
    ///
    /// # Errors
    ///
    /// Returns an error if the build command fails.
    fn build(
        &self,
        dockerfile_path: &Path,
        context_path: &Path,
        image_tag: Vec<&str>,
        phase_label: Option<&str>,
        feature_progress: Option<&[FeatureProgressItem]>,
        silent: bool,
    ) -> Result<()>;

    /// Builds a container image from a Dockerfile with additional build arguments.
    ///
    /// This method supports the full range of build options from the devcontainer spec,
    /// including build arguments, target stages, and custom Docker build options.
    ///
    /// # Arguments
    ///
    /// * `dockerfile_path` - Path to the Dockerfile
    /// * `context_path` - Build context directory path
    /// * `image_tag` - Tag to apply to the built image
    /// * `args` - Build arguments (--build-arg KEY=VALUE)
    /// * `target` - Target build stage (--target STAGE)
    /// * `options` - Additional build options to pass to the build command
    /// * `silent` - If true, suppress progress output to stdout
    ///
    /// # Errors
    ///
    /// Returns an error if the build command fails.
    #[allow(clippy::too_many_arguments)]
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
    ) -> Result<()>;

    /// Starts a container instance.
    ///
    /// # Arguments
    ///
    /// * `image_tag` - Image to run
    /// * `volume_mount` - Volume mount in format "host_path:container_path"
    /// * `label` - Label in format "key=value"
    /// * `env_vars` - Environment variables to set
    /// * `runtime_parameters` - Additional runtime parameters
    ///
    /// # Errors
    ///
    /// Returns an error if the run command fails.
    fn run(
        &self,
        image_tag: &str,
        volume_mount: &str,
        label: &str,
        env_vars: &[String],
        runtime_parameters: RuntimeParameters,
    ) -> Result<Box<dyn ContainerHandle>>;

    /// Executes a command in a running container.
    ///
    /// # Arguments
    ///
    /// * `container_handle` - Handle of the container
    /// * `command` - Command to execute (e.g., shell path)
    /// * `env_vars` - Environment variables to set
    ///
    /// # Errors
    ///
    /// Returns an error if the exec command fails.
    fn exec(
        &self,
        container_handle: &dyn ContainerHandle,
        command: Vec<&str>,
        env_vars: &[String],
        attach_stdin: bool,
        attach_stdout: bool,
    ) -> Result<()>;

    /// Returns the mapped host port for a container TCP port.
    ///
    /// # Arguments
    ///
    /// * `container_id` - The runtime-specific container identifier
    /// * `container_port` - The container-side TCP port (for example 22)
    ///
    /// # Returns
    ///
    /// `Ok(Some(port))` when mapped, `Ok(None)` when not mapped.
    fn mapped_host_port(&self, container_id: &str, container_port: u16) -> Result<Option<u16>>;

    /// Lists running containers.
    ///
    /// # Returns
    ///
    /// A vector of tuples containing (container_name, image_tag, handle) triples.
    /// The container_name is extracted from the "devcon" label.
    /// The image_tag is the image reference the container is running.
    ///
    /// # Errors
    ///
    /// Returns an error if the list command fails or output cannot be parsed.
    #[allow(clippy::type_complexity)]
    fn list(&self) -> Result<Vec<(String, String, Box<dyn ContainerHandle>)>>;

    /// Lists all containers including stopped ones.
    ///
    /// # Returns
    ///
    /// A vector of tuples containing (container_name, image_tag, handle) triples for
    /// all devcon-managed containers regardless of their state.
    ///
    /// # Errors
    ///
    /// Returns an error if the list command fails or output cannot be parsed.
    #[allow(clippy::type_complexity)]
    fn list_all(&self) -> Result<Vec<(String, String, Box<dyn ContainerHandle>)>>;

    /// Starts a previously stopped container.
    ///
    /// # Arguments
    ///
    /// * `container_id` - The ID of the stopped container to start
    ///
    /// # Returns
    ///
    /// A handle to the now-running container.
    ///
    /// # Errors
    ///
    /// Returns an error if the start command fails.
    fn start_container(&self, container_id: &str) -> Result<Box<dyn ContainerHandle>>;

    /// List images.
    ///
    /// # Returns
    ///
    /// A vector of image tags which are built by devcon.
    ///
    /// # Errors
    ///
    /// Returns an error if the list images command fails or output cannot be parsed.
    fn images(&self) -> Result<Vec<String>>;

    /// Get the image ID (digest) for a given image tag.
    ///
    /// # Arguments
    ///
    /// * `image_tag` - The image tag to look up (e.g. "devcon-myproject:latest")
    ///
    /// # Returns
    ///
    /// `Ok(Some(id))` if the image exists, `Ok(None)` if not found.
    ///
    /// # Errors
    ///
    /// Returns an error if the inspect command fails unexpectedly.
    fn image_id(&self, image_tag: &str) -> Result<Option<String>>;

    /// Inspect an image and return image metadata as JSON.
    ///
    /// # Arguments
    ///
    /// * `image_tag` - The image tag to inspect
    ///
    /// # Returns
    ///
    /// `Ok(Some(metadata))` if inspect succeeds, `Ok(None)` if the image does not exist.
    fn inspect_image(&self, image_tag: &str) -> Result<Option<ContainerImageInfo>>;

    /// Read a single label from an image's metadata.
    ///
    /// # Arguments
    ///
    /// * `image_tag` - The image tag to inspect (e.g. "devcon-myproject:latest")
    /// * `label_key` - The label key to look up (e.g. "devcon.config-hash")
    ///
    /// # Returns
    ///
    /// `Ok(Some(value))` if the label exists, `Ok(None)` if the image is absent or the label
    /// is not set.
    fn image_label(&self, image_tag: &str, label_key: &str) -> Result<Option<String>>;

    /// Probe the runtime user, home directory, and PATH by running a single temporary container.
    ///
    /// Runs `printf '%s\n%s\n%s' "$(id -un)" "$HOME" "$PATH"` inside a throwaway container
    /// started from `image_tag`. When `user` is `Some`, the probe runs as that specific user
    /// (needed when `Config.User` is `root` but the intended remote user differs).
    ///
    /// # Returns
    ///
    /// `Ok(Some(info))` on success, `Ok(None)` if no suitable shell was found or the probe
    /// failed.
    fn probe_image_info(
        &self,
        image_tag: &str,
        user: Option<&str>,
    ) -> Result<Option<ContainerProbeInfo>>;

    /// Get the host address for the runtime.
    ///
    /// This is used to configure containers to connect back to the host.
    ///
    /// # Returns
    ///
    /// A string representing the host address.
    fn get_host_address(&self) -> String;
}
