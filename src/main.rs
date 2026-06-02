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

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing::{Level, trace};
use tracing_indicatif::IndicatifLayer;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use devcon::command::*;
use devcon::output::OutputFormat;

#[derive(Parser, Debug)]
#[command(
    name = "devcon",
    author = "devconhq",
    about = "A CLI tool for managing development containers",
    long_about = None,
    version = env!("CARGO_PKG_VERSION")
)]
struct Cli {
    /// Turn debugging information on
    #[arg(short, long, action = clap::ArgAction::Count)]
    debug: u8,

    /// Custom config file path (overrides default config location)
    #[arg(short, long, global = true, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Output format (text or json)
    #[arg(short, long, global = true, default_value = "text", value_enum)]
    output: OutputFormat,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum SshAction {
    /// Connect to a running development container via SSH
    #[command(about = "Connect to a running development container via SSH")]
    Connect {
        /// Path to the project directory containing .devcontainer configuration
        #[arg(
            help = "Path to the project directory. If not provided, uses current directory.",
            value_name = "PATH"
        )]
        path: Option<PathBuf>,

        /// Run in ProxyCommand mode (stdio passthrough to mapped container SSH port)
        #[arg(long, help = "Use stdio passthrough mode for ssh ProxyCommand")]
        proxy: bool,
    },

    /// Create an SSH config entry for the devcontainer in ~/.ssh/config
    #[command(about = "Write a Host block for this devcontainer to ~/.ssh/config")]
    CreateConfig {
        /// Path to the project directory containing .devcontainer configuration
        #[arg(
            help = "Path to the project directory. If not provided, uses current directory.",
            value_name = "PATH"
        )]
        path: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Builds a development container for the specified path
    #[command(about = "Create a development container")]
    Build {
        /// Path to the project directory containing .devcontainer configuration
        #[arg(
            help = "Path to the project directory. If not provided, uses current directory.",
            value_name = "PATH"
        )]
        path: Option<PathBuf>,

        /// Path to the build directory.
        #[arg(short, long, help = "Path to the build directory.")]
        build_path: Option<PathBuf>,
    },

    /// Starts a development container for the specified path
    #[command(about = "Create a development container")]
    Start {
        /// Path to the project directory containing .devcontainer configuration
        #[arg(
            help = "Path to the project directory. If not provided, uses current directory.",
            value_name = "PATH"
        )]
        path: Option<PathBuf>,
    },
    /// Builds and starts a development container for the specified path
    #[command(about = "Build and start a development container (combines build + start)")]
    Up {
        /// Path to the project directory containing .devcontainer configuration
        #[arg(
            help = "Path to the project directory. If not provided, uses current directory.",
            value_name = "PATH"
        )]
        path: Option<PathBuf>,

        /// Path to the build directory.
        #[arg(short, long, help = "Path to the build directory.")]
        build_path: Option<PathBuf>,

        /// Force a rebuild even if the config hash is unchanged.
        #[arg(long, help = "Force a rebuild, ignoring the cached image.")]
        force_rebuild: bool,
    },
    /// Execs a shell in a development container for the specified path
    #[command(about = "Exec a shell in a development container with the devcontainer CLI")]
    Shell {
        /// Path to the project directory containing .devcontainer configuration
        #[arg(
            help = "Path to the project directory. If not provided, uses current directory.",
            value_name = "PATH"
        )]
        path: Option<PathBuf>,

        /// Environment variables which will be processed. Each should be denoted by KEY=VALUE
        #[arg(
            help = "Environment variables which will be processed. Each should be denoted by KEY=VALUE.",
            value_name = "PATH"
        )]
        env: Vec<String>,
    },
    /// Connect to or configure SSH access for a development container
    #[command(about = "Connect to or configure SSH access for a development container")]
    Ssh {
        #[command(subcommand)]
        action: SshAction,
    },
    /// Display information about a devcontainer
    #[command(about = "Display devcontainer status and configuration details")]
    Info {
        /// Path to the project directory containing .devcontainer configuration
        #[arg(
            help = "Path to the project directory. If not provided, uses current directory.",
            value_name = "PATH"
        )]
        path: Option<PathBuf>,
    },
    /// Starts the control server for agent connections
    #[command(about = "Start the control server for managing agent connections")]
    Serve {
        /// Port to listen on
        #[arg(
            help = "Port to listen on for agent connections",
            long,
            short,
            default_value = "15000"
        )]
        port: u16,
    },
}

fn main() -> devcon::error::Result<()> {
    let indicatif_layer = IndicatifLayer::new();
    let cli = Cli::parse();
    let level = match cli.debug {
        0 => Level::WARN,
        1 => Level::INFO,
        2 => Level::DEBUG,
        _ => Level::TRACE,
    };

    // Configure logging: third-party crates only log at trace level, our crate uses the configured level
    let third_party_level = if cli.debug > 3 { "trace" } else { "error" };
    let filter = EnvFilter::new(format!(
        "{}={},reqwest={},hyper={},h2={},tower={}",
        env!("CARGO_PKG_NAME").replace('-', "_"),
        level,
        third_party_level,
        third_party_level,
        third_party_level,
        third_party_level
    ));

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(indicatif_layer.get_stderr_writer()))
        .with(indicatif_layer)
        .with(filter)
        .init();

    trace!("Starting devcon with CLI args: {:?}", cli);

    let config_path = cli.config.clone();
    let output = cli.output.clone();

    match &cli.command {
        Commands::Build { path, build_path } => {
            handle_build_command(
                path.clone().unwrap_or(PathBuf::from(".").to_path_buf()),
                build_path.clone(),
                config_path,
                output,
            )?;
        }
        Commands::Start { path } => {
            handle_start_command(
                path.clone().unwrap_or(PathBuf::from(".").to_path_buf()),
                config_path,
                output,
            )?;
        }
        Commands::Up {
            path,
            build_path,
            force_rebuild,
        } => {
            handle_up_command(
                path.clone().unwrap_or(PathBuf::from(".").to_path_buf()),
                build_path.clone(),
                config_path,
                output,
                *force_rebuild,
            )?;
        }
        Commands::Shell { path, env } => {
            handle_shell_command(
                path.clone().unwrap_or(PathBuf::from(".").to_path_buf()),
                env,
                config_path,
            )?;
        }
        Commands::Ssh { action } => match action {
            SshAction::Connect { path, proxy } => {
                handle_ssh_command(
                    path.clone().unwrap_or(PathBuf::from(".").to_path_buf()),
                    config_path,
                    *proxy,
                )?;
            }
            SshAction::CreateConfig { path } => {
                handle_ssh_create_config_command(
                    path.clone().unwrap_or(PathBuf::from(".").to_path_buf()),
                    config_path,
                )?;
            }
        },
        Commands::Info { path } => {
            handle_info_command(
                path.clone().unwrap_or(PathBuf::from(".").to_path_buf()),
                config_path,
                output,
            )?;
        }
        Commands::Serve { port } => {
            handle_serve_command(*port, config_path, output)?;
        }
    }

    Ok(())
}
