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

#[derive(Parser, Debug)]
#[command(
    name = "devcon",
    author = "kreemer",
    about = "A CLI tool for managing development containers",
    long_about = None,
    version = env!("CARGO_PKG_VERSION")
)]
struct Cli {
    /// Turn debugging information on
    #[arg(short, long, action = clap::ArgAction::Count)]
    debug: u8,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum ConfigAction {
    /// Show the current configuration
    #[command(about = "Display current configuration with all values")]
    Show,

    /// Get a configuration property value
    #[command(about = "Get the value of a configuration property")]
    Get {
        /// Property path in camelCase dot-notation (e.g., agents.binaryUrl)
        #[arg(help = "Property path to get")]
        property: String,
    },

    /// Set a configuration property value
    #[command(about = "Set a configuration property value")]
    Set {
        /// Property path in camelCase dot-notation (e.g., agents.binaryUrl)
        #[arg(help = "Property path to set")]
        property: String,

        /// Value to set
        #[arg(help = "Value to set")]
        value: String,
    },

    /// Unset (remove) a configuration property value
    #[command(about = "Unset a configuration property")]
    Unset {
        /// Property path in camelCase dot-notation (e.g., agents.binaryUrl)
        #[arg(help = "Property path to unset")]
        property: String,
    },

    /// Validate the configuration
    #[command(about = "Validate all configuration values")]
    Validate,

    /// Show the configuration file path
    #[command(about = "Show the configuration file location")]
    Path,

    /// List all available configuration properties
    #[command(about = "List all configuration properties")]
    List {
        /// Filter properties by substring match
        #[arg(help = "Filter properties by substring", long, short)]
        filter: Option<String>,
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
    /// Prints the config file location path
    #[command(about = "Manage DevCon configuration")]
    Config {
        #[command(subcommand)]
        action: ConfigAction,
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

    match &cli.command {
        Commands::Build { path, build_path } => {
            handle_build_command(
                path.clone().unwrap_or(PathBuf::from(".").to_path_buf()),
                build_path.clone(),
            )?;
        }
        Commands::Start { path } => {
            handle_start_command(path.clone().unwrap_or(PathBuf::from(".").to_path_buf()))?;
        }
        Commands::Up { path, build_path } => {
            handle_up_command(
                path.clone().unwrap_or(PathBuf::from(".").to_path_buf()),
                build_path.clone(),
            )?;
        }
        Commands::Shell { path, env } => {
            handle_shell_command(
                path.clone().unwrap_or(PathBuf::from(".").to_path_buf()),
                env,
            )?;
        }
        Commands::Config { action } => match action {
            ConfigAction::Show => {
                handle_config_show()?;
            }
            ConfigAction::Get { property } => {
                handle_config_get(property)?;
            }
            ConfigAction::Set { property, value } => {
                handle_config_set(property, value)?;
            }
            ConfigAction::Unset { property } => {
                handle_config_unset(property)?;
            }
            ConfigAction::Validate => {
                handle_config_validate()?;
            }
            ConfigAction::Path => {
                handle_config_path()?;
            }
            ConfigAction::List { filter } => {
                handle_config_list(filter.as_deref())?;
            }
        },
        Commands::Serve { port } => {
            handle_serve_command(*port)?;
        }
    }

    Ok(())
}
