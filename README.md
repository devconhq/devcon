# DevCon - Development Container Manager

```
██████╗ ███████╗██╗   ██╗ ██████╗ ██████╗ ███╗   ██╗
██╔══██╗██╔════╝██║   ██║██╔════╝██╔═══██╗████╗  ██║
██║  ██║█████╗  ██║   ██║██║     ██║   ██║██╔██╗ ██║
██║  ██║██╔══╝  ╚██╗ ██╔╝██║     ██║   ██║██║╚██╗██║
██████╔╝███████╗ ╚████╔╝ ╚██████╗╚██████╔╝██║ ╚████║
╚═════╝ ╚══════╝  ╚═══╝   ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝

    "DevCon One" - Your Mission-Critical Dev Environment Manager
```

A blazingly fast CLI tool for managing and launching development containers. DevCon parses `devcontainer.json` configurations, downloads OCI features, and orchestrates the full container build/start/shell lifecycle against pluggable container runtimes.

## Features

- **Multi-Runtime Support**: Works with Docker and Apple's native container runtime (macOS)
- **Full Lifecycle Management**: Build, start, shell, SSH, and serve — all from one tool
- **Devcontainer Feature Support**: Automatic download and installation of features from OCI registries (ghcr.io)
- **Lifecycle Hooks**: Full support for `onCreate`, `postCreate`, `postStart`, and `postAttach` commands
- **Dotfiles Integration**: Clone and set up your dotfiles repository automatically inside containers
- **Agent Forwarding**: Forward SSH, GPG, and GitHub CLI credentials into running containers
- **Port Forwarding**: Automatic port forwarding with configurable display modes
- **SSH Access**: Connect to containers via SSH, including `ProxyCommand` support for use in `~/.ssh/config`
- **Flexible Configuration**: User-level YAML config with XDG directory support

## Installation

### Homebrew (recommended)

```bash
brew tap devconhq/tap
brew install devcon
```

### From Source

Requires Rust and `protoc` (Protocol Buffers compiler).

```bash
git clone https://github.com/devconhq/devcon.git
cd devcon
cargo install --path .
```

### From Releases

Download the latest binary for your platform from the [releases page](https://github.com/devconhq/devcon/releases).

### Prerequisites

DevCon requires a container runtime:

- **Docker**: [Docker Desktop](https://www.docker.com/products/docker-desktop/) or Docker Engine
- **Apple Container** (macOS only): [Apple container](https://www.github.com/apple/container)

## Quick Start

Navigate to a project with a `.devcontainer/devcontainer.json` and run:

```bash
# Build and start the container in one step
devcon up

# Open an interactive shell inside the container
devcon shell
```

## Commands

| Command | Description |
|---|---|
| `devcon build [PATH]` | Build the container image |
| `devcon start [PATH]` | Start the container |
| `devcon up [PATH]` | Build and start in one step |
| `devcon shell [PATH]` | Open an interactive shell in the container |
| `devcon ssh [PATH]` | Connect via SSH |
| `devcon info [PATH]` | Display container status and configuration |
| `devcon serve` | Start the control server for agent connections |
| `devcon config <ACTION>` | Manage DevCon configuration |

All commands default to the current directory when `PATH` is not specified.

### Global flags

| Flag | Description |
|---|---|
| `-d` / `--debug` | Increase log verbosity (repeat for more: `-dd` = DEBUG, `-ddd` = TRACE) |
| `-c` / `--config FILE` | Use a custom config file instead of the default location |
| `-o` / `--output text\|json` | Output format (default: `text`) |

### `devcon shell`

```bash
# Pass environment variables into the shell session
devcon shell --env EDITOR=vim --env LANG=en_US.UTF-8
```

### `devcon ssh`

```bash
# Use as an SSH ProxyCommand (for ~/.ssh/config integration)
devcon ssh --proxy
```

Example `~/.ssh/config` entry:

```
Host myproject
  ProxyCommand devcon ssh /path/to/project --proxy
```

## The control server and agent (`devcon serve`)

DevCon uses a host/agent architecture to enable features that require communication between the container and the host machine — primarily **port forwarding** and **URL opening**.

### How it works

When a container is started, DevCon automatically installs a small agent binary (`devcon-agent`) inside it as a devcontainer feature. On startup, this agent connects back to the host over TCP using a protobuf-based protocol.

The host-side counterpart is the **control server**, started with `devcon serve`. It:

- Accepts incoming TCP connections from agents running inside containers
- Receives port-forward requests (`StartPortForward` / `StopPortForward`) and sets up local port bindings on the host
- Handles URL-open requests from inside the container (e.g., when a development server opens a browser link, it is forwarded to the host browser)
- Displays a live table of all active port forwards across all connected containers

### Running the control server

```bash
# Start on the default port (15000) with inline status output
devcon serve

# Use fullscreen mode to display port forwarding status
devcon serve --status-mode fullscreen
```

The control server should be kept running in a separate terminal (or as a background service) while containers are active. Containers that cannot reach the control server will still start and function, but port forwarding and URL opening will not be available.

### Agent installation options

By default, the agent binary is downloaded from GitHub Releases at container build time. You can customize this behaviour via the `agents.*` configuration properties:

```bash
# Point to a custom precompiled binary
devcon config set agents.binaryUrl https://example.com/devcon-agent

# Build the agent from source inside the container instead
devcon config set agents.useAgentBinary false

# Disable the agent entirely (disables port forwarding and URL opening)
devcon config set agents.disable true
```

## Configuration

The configuration file is stored at `~/.config/devcon/config.yaml` (XDG Base Directory). Use the `devcon config` subcommands to manage it without editing YAML by hand.

```bash
devcon config show              # Display current configuration
devcon config path              # Show the config file path
devcon config list              # List all available properties
devcon config list --filter ssh # Filter properties by name
devcon config get <property>    # Read a property value
devcon config set <property> <value>  # Set a property value
devcon config unset <property>  # Remove a property value
devcon config validate          # Validate the configuration
```

Properties use camelCase dot-notation (e.g., `agents.binaryUrl`).

### Configuration reference

#### General

| Property | Type | Description |
|---|---|---|
| `dotfilesRepository` | string | URL of a dotfiles repository to clone into containers |
| `dotfilesInstallCommand` | string | Command used to install dotfiles after cloning |
| `defaultShell` | string | Shell to use when running `devcon shell` |
| `runtime` | string | Container runtime: `auto` (default), `docker`, or `apple` |
| `buildPath` | string | Default build directory path |
| `additionalFeatures` | map | Extra devcontainer features added to every container |
| `envVariables` | list | Environment variables passed to every container (`KEY=value` or bare `KEY`) |

#### Agent settings (`agents.*`)

| Property | Type | Description |
|---|---|---|
| `agents.useAgentBinary` | bool | Use a precompiled binary (`true`) or compile from source (`false`) |
| `agents.binaryUrl` | string | URL to a precompiled agent binary |
| `agents.gitRepository` | string | Git repository URL to build the agent from source |
| `agents.gitBranch` | string | Branch to use when building from source (default: `main`) |
| `agents.disable` | bool | Disable agent installation entirely |

#### Agent forwarding (`agentForwarding.*`)

| Property | Type | Description |
|---|---|---|
| `agentForwarding.sshEnabled` | bool | Forward the SSH agent socket into containers |
| `agentForwarding.gpgEnabled` | bool | Forward the GPG agent socket into containers |
| `agentForwarding.ghEnabled` | bool | Forward GitHub CLI credentials into containers |
| `agentForwarding.sshSocketPath` | string | Override the SSH socket path (auto-detected by default) |
| `agentForwarding.gpgSocketPath` | string | Override the GPG socket path (auto-detected by default) |
| `agentForwarding.ghConfigPath` | string | Override the GitHub CLI config directory (auto-detected by default) |

#### Apple runtime (`runtimeConfig.apple.*`)

| Property | Type | Description |
|---|---|---|
| `runtimeConfig.apple.buildMemory` | string | Memory limit for builds, e.g. `4g`, `512m` (default: `4g`) |
| `runtimeConfig.apple.buildCpu` | string | CPU limit for builds, e.g. `2`, `0.5` |

### Example config file

```yaml
dotfilesRepository: https://github.com/user/dotfiles
runtime: auto
envVariables:
  - EDITOR=vim
  - LANG=en_US.UTF-8
additionalFeatures:
  ghcr.io/devcontainers/features/common-utils:2:
    installZsh: true
agentForwarding:
  sshEnabled: true
  gpgEnabled: true
agents:
  disable: false
```

### Set a value via CLI

```bash
devcon config set dotfilesRepository https://github.com/user/dotfiles
devcon config set agentForwarding.sshEnabled true
devcon config set runtimeConfig.apple.buildMemory 8g
```

## Using the Apple container runtime

DevCon supports Apple's native `container` CLI as an alternative to Docker on macOS. This runtime uses lightweight virtual machines and supports Rosetta 2 for running x86_64 images on Apple Silicon.

### Prerequisites

Apple's `container` CLI must be installed and available on your `PATH`. Refer to Apple's documentation for installation instructions.

### Selecting the Apple runtime

```bash
devcon config set runtime apple
```

Or explicitly per-invocation via the config file:

```yaml
runtime: apple
```

### Required: set a build path outside /tmp

When building a container image, DevCon creates a temporary build context directory. By default this lands in `/tmp`, but Apple's container runtime runs inside a virtual machine that cannot access macOS's `/tmp` filesystem. The build will fail unless you configure a `buildPath` that resolves to a directory the runtime can reach — any path under your home directory works.

```bash
devcon config set buildPath ~/.devcon/build
```

Or in `~/.config/devcon/config.yaml`:

```yaml
buildPath: ~/.devcon/build
runtime: apple
```

DevCon creates the directory automatically if it does not exist.

### Tuning resource limits

By default the Apple runtime uses 4 GB of memory per build. You can raise or lower this and optionally cap CPU usage:

```bash
devcon config set runtimeConfig.apple.buildMemory 8g
devcon config set runtimeConfig.apple.buildCpu 4
```

Accepted memory suffixes are `k`, `m`, and `g`. CPU is a decimal number of cores (e.g. `2` or `0.5`).

### Minimal Apple runtime config

```yaml
runtime: apple
buildPath: ~/.devcon/build
runtimeConfig:
  apple:
    buildMemory: 8g
```

### Notes

- The runtime always passes `--rosetta` when starting containers, enabling Rosetta 2 translation for x86_64 images on Apple Silicon automatically.
- Privileged containers use `--virtualization` instead of Docker's `--privileged` flag.
- The host is reachable from inside the container at `host.container.internal`.

## Building from Source

```bash
# Development build
cargo build

# Run unit tests (no container runtime required)
cargo test --lib --bins

# Run integration tests (requires Docker)
CONTAINER_RUNTIME=docker cargo test --test main

# Lint
cargo clippy --all-targets --all-features --workspace -- -D warnings
```

## License

MIT — see [LICENSE](LICENSE) for details.
