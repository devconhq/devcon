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
//! allowing DevCon to work with different container CLIs (Apple's container,
//! Docker, Podman, etc.).

use std::{
    collections::VecDeque,
    io::{BufRead, BufReader},
    path::Path,
    process::Child,
    sync::{Arc, Mutex},
    time::Duration,
};

use crate::error::Result;
use console::Style;
use indicatif::{ProgressBar, ProgressStyle};

pub mod apple;
pub mod docker;

/// Stream build output from a child process with a rolling window display.
///
/// This function:
/// - Captures stdout and stderr from the child process
/// - Prints all lines as they arrive (permanent output)
/// - Maintains a rolling buffer of the last 10 lines displayed at the bottom
/// - If the process fails, prints the complete output again
///
/// # Arguments
///
/// * `child` - The child process to stream output from
///
/// # Returns
///
/// Returns `Ok(ExitStatus)` if the process completes, `Err` if there's an I/O error
pub fn stream_build_output(mut child: Child, silent: bool) -> Result<std::process::ExitStatus> {
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

    if !silent {
        println!("Building Image..");
    }

    // Buffer for last 10 lines (rolling window)
    let rolling_buffer: Arc<Mutex<VecDeque<String>>> =
        Arc::new(Mutex::new(VecDeque::with_capacity(10)));

    // Buffer for all output (for error reporting)
    let all_output: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

    let rolling_clone = Arc::clone(&rolling_buffer);
    let all_output_clone = Arc::clone(&all_output);

    let bar = ProgressBar::new_spinner();
    bar.set_style(ProgressStyle::default_spinner().template("{spinner} {msg}")?);
    bar.enable_steady_tick(Duration::from_millis(100));

    // Stream stdout in a separate thread
    let stdout_thread = stdout.map(|stdout| {
        let rolling = Arc::clone(&rolling_buffer);
        let all = Arc::clone(&all_output);
        std::thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line_result in reader.lines() {
                // Handle UTF-8 decoding errors gracefully
                let line = match line_result {
                    Ok(l) => l,
                    Err(_) => continue, // Skip lines with UTF-8 errors
                };

                // Try to strip ANSI escapes safely, fall back to original if it fails
                let clean_line = std::panic::catch_unwind(|| strip_ansi_escapes::strip_str(&line))
                    .unwrap_or_else(|_| line.clone());

                // Add to rolling buffer
                let mut roll = rolling.lock().unwrap();
                if roll.len() >= 10 {
                    roll.pop_front();
                }
                roll.push_back(clean_line);
                drop(roll);

                // Add to complete output (with original ANSI codes)
                let mut all_buf = all.lock().unwrap();
                all_buf.push(line);
            }
        })
    });

    // Stream stderr in a separate thread
    let stderr_thread = stderr.map(|stderr| {
        let rolling = Arc::clone(&rolling_clone);
        let all = Arc::clone(&all_output_clone);
        std::thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line_result in reader.lines() {
                // Handle UTF-8 decoding errors gracefully
                let line = match line_result {
                    Ok(l) => l,
                    Err(_) => continue, // Skip lines with UTF-8 errors
                };

                // Try to strip ANSI escapes safely, fall back to original if it fails
                let clean_line = std::panic::catch_unwind(|| strip_ansi_escapes::strip_str(&line))
                    .unwrap_or_else(|_| line.clone());

                // Add to rolling buffer
                let mut roll = rolling.lock().unwrap();
                if roll.len() >= 10 {
                    roll.pop_front();
                }
                roll.push_back(clean_line);
                drop(roll);

                // Add to complete output (with original ANSI codes)
                let mut all_buf = all.lock().unwrap();
                all_buf.push(line);
            }
        })
    });

    // Update progress bar with last 10 lines
    let display_buffer = Arc::clone(&rolling_clone);
    let display_bar = bar.clone();
    let update_thread = std::thread::spawn(move || {
        let grey_style = Style::new().dim();
        loop {
            let buf = display_buffer.lock().unwrap();
            if !buf.is_empty() {
                let display_text = format!(
                    "\n{}",
                    buf.iter()
                        .map(|s| grey_style.apply_to(s).to_string())
                        .collect::<Vec<_>>()
                        .join("\n")
                );
                display_bar.set_message(display_text);
            }
            drop(buf);
            std::thread::sleep(Duration::from_millis(100));
        }
    });

    // Wait for stdout thread to complete
    if let Some(handle) = stdout_thread {
        let _ = handle.join();
    }

    // Wait for stderr thread to complete
    if let Some(handle) = stderr_thread {
        let _ = handle.join();
    }

    let result = child.wait()?;

    // Stop the update thread
    bar.finish_and_clear();
    drop(update_thread);

    // If the build failed, print the complete output for debugging
    if !result.success() {
        eprintln!("\n=== Build failed! Complete output: ===");
        let full_output = all_output_clone.lock().unwrap();
        for line in full_output.iter() {
            eprintln!("{}", line);
        }
        eprintln!("=== End of output ===\n");
    } else if !silent {
        println!("Building image complete");
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
}

/// Trait for container runtime implementations.
///
/// This trait defines the interface for interacting with container runtimes,
/// allowing DevCon to work with different container CLIs transparently.
pub trait ContainerHandle: Send {
    /// Returns the container ID.
    fn id(&self) -> &str;
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

    /// Get the host address for the runtime.
    ///
    /// This is used to configure containers to connect back to the host.
    ///
    /// # Returns
    ///
    /// A string representing the host address.
    fn get_host_address(&self) -> String;
}
