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

- **Multi-Runtime Support**: Works with Docker and the native `container` runtime (macOS)
- **Full Lifecycle Management**: Build, start, shell, SSH, and serve — all from one tool
- **Devcontainer Feature Support**: Automatic download and installation of features from OCI registries (ghcr.io)
- **Lifecycle Hooks**: Full support for `onCreate`, `postCreate`, `postStart`, and `postAttach` commands
- **Dotfiles Integration**: Clone and set up your dotfiles repository automatically inside containers
- **Agent Forwarding**: Forward SSH, GPG, and GitHub CLI credentials into running containers
- **Port Forwarding**: Automatic port forwarding with configurable display modes
- **SSH Access**: Connect to containers via in-container OpenSSH with automatic random host-port mapping and `ProxyCommand` support for `~/.ssh/config`
- **Flexible Configuration**: User-level YAML config with XDG directory support

## Dev Container Spec Compatibility Matrix

Scope: this matrix tracks effective runtime behavior, not just JSON parsing. A property can be parsed from `devcontainer.json` but still be marked `Missing` if it is not applied by runtime/orchestration code.

Status legend:

- `Implemented`: behavior is applied by DevCon today.
- `Partial`: some behavior is implemented, but not all required spec semantics.
- `Missing`: parser-only or not implemented.

### Matrix

| Spec area | Property / Requirement | Status | Notes / Tracking |
|---|---|---|---|
| General | `name` | Implemented | Used for image/container identity and labeling. |
| General | `features` | Implemented | OCI and local features are processed and installed. |
| General | `overrideFeatureInstallOrder` | Implemented | Explicit feature ordering is supported. |
| General | `forwardPorts` | Implemented | Port forwarding/publishing is applied at container start. |
| General | `portsAttributes` | Missing | Parsed, but not used to control forwarding behavior yet. |
| General | `otherPortsAttributes` | Missing | Parsed, but not applied. |
| General | `containerEnv` | Implemented | Merged and applied to container startup environment. |
| General | `remoteEnv` | Implemented | Applied to remote/SSH session processes with merge semantics. |
| General | `remoteUser` | Implemented | Supported, including user probing and runtime resolution. |
| General | `containerUser` | Partial | Used for user resolution; full spec parity still depends on metadata parity work (#106). |
| General | `updateRemoteUserUID` | Missing | Parsed, but no Linux UID/GID sync step is implemented. |
| General | `userEnvProbe` | Missing | Parsed, but no spec-driven probe mode behavior is implemented. |
| General | `overrideCommand` | Missing | Parsed, but runtime command behavior is not controlled by this property. |
| General | `shutdownAction` | Missing | Parsed, but stop behavior is not controlled by this property. |
| General | `init` | Missing | Parsed, but no `--init` equivalent is applied today. |
| General | `privileged` | Implemented | Applied to runtime flags; merged with feature requirements. |
| General | `capAdd` | Implemented | Capability set is applied and merged with feature requirements. |
| General | `securityOpt` | Implemented | Security options are applied and merged with feature requirements. |
| General | `mounts` | Implemented | String and structured mounts are supported. |
| General | `customizations` | Missing | Parsed, but tool-specific customization processing is not implemented. |
| General | `hostRequirements` | Missing | Parsed, but no host requirement validation/enforcement is implemented. |
| Image/Dockerfile | `image` | Implemented | Image-based environments are supported. |
| Image/Dockerfile | `build.dockerfile` / `dockerFile` | Implemented | Dockerfile-based environments are supported. |
| Image/Dockerfile | `build.context` / `context` | Implemented | Build context is resolved and applied. |
| Image/Dockerfile | `build.args` | Implemented | Build arguments are passed through to image build. |
| Image/Dockerfile | `build.options` | Implemented | Additional build options are passed through. |
| Image/Dockerfile | `build.target` | Implemented | Multi-stage build target is supported. |
| Image/Dockerfile | `build.cacheFrom` | Missing | Parsed, but build cache sources are not wired through runtime build call. |
| Image/Dockerfile | `workspaceMount` | Implemented | Workspace mount override is supported (image/dockerfile scenarios). |
| Image/Dockerfile | `workspaceFolder` | Implemented | Workspace folder inside container is supported. |
| Image/Dockerfile | `runArgs` | Missing | Parsed, but not passed through to runtime invocation. |
| Image/Dockerfile | `appPort` | Missing | Parsed, but not actively used for runtime publishing behavior. |
| Compose | `dockerComposeFile` + `service` | Missing | Docker Compose orchestration not implemented yet (#41). |
| Compose | `runServices` | Missing | Not implemented yet (#41). |
| Lifecycle | `initializeCommand` host-side execution | Missing | Parsed, but host initialization phase command is not executed. |
| Lifecycle | `onCreateCommand` | Implemented | Executed in container lifecycle flow. |
| Lifecycle | `updateContentCommand` | Missing | Parsed, but not executed in lifecycle flow. |
| Lifecycle | `postCreateCommand` | Implemented | Executed in container lifecycle flow. |
| Lifecycle | `postStartCommand` | Implemented | Executed in container lifecycle flow (on create/start paths). |
| Lifecycle | `postAttachCommand` | Implemented | Executed on attach workflows. |
| Lifecycle | `waitFor` gating semantics | Missing | Parsed, but command-stage gating behavior is not implemented. |
| Lifecycle | String vs array command semantics | Implemented | Array commands are executed directly without shell; syntax conformance tracked in #91. |
| Lifecycle | Object command parallel execution | Missing | Object commands are currently executed sequentially (#105). |
| Metadata | `devcontainer.metadata` merge semantics | Partial | Metadata label is read for selected behavior (for example user hints), but full spec merge/write parity is pending (#106). |
| Metadata | Metadata write/update support | Missing | Writing/maintaining complete spec metadata is not implemented (#106). |

### Spec Requirements Not Built In Yet

The following implementor-spec requirements are still open and are intentionally tracked as gaps:

- Docker Compose environment support (`dockerComposeFile`, `service`, `runServices`) is not implemented yet (#41).
- Lifecycle object values are not executed in parallel; they currently run sequentially (#105).
- Host-side `initializeCommand` phase is not implemented.
- `updateContentCommand` execution semantics are not implemented.
- `waitFor` stage gating behavior is not implemented.
- Full `devcontainer.metadata` merge/write behavior is not implemented (#106).
- `updateRemoteUserUID` Linux UID/GID sync behavior is not implemented.
- `userEnvProbe`-driven environment probing behavior is not implemented.
- `runArgs`, `init`, `overrideCommand`, and `shutdownAction` are parsed but not applied as spec-defined runtime behavior.
- `customizations`, `hostRequirements`, `portsAttributes`, `otherPortsAttributes`, and `appPort` are parsed but not applied as spec-defined behavior.

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
- **Container CLI** (macOS only): `container`

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
devcon ssh connect --proxy

# Write/update a managed SSH config entry for this workspace
devcon ssh create-config
```

Example `~/.ssh/config` entry:

```
# devcon-managed-start: /path/to/project
Host devcon-myproject
  HostName 127.0.0.1
  User devcon
  ProxyCommand devcon ssh connect /path/to/project --proxy
# devcon-managed-end: /path/to/project
```

DevCon writes managed start/end marker comments around workspace SSH entries so repeated runs can replace the exact managed block instead of appending duplicates.

DevCon also updates `~/.ssh/config` automatically after `devcon start` and `devcon up` successfully start the container.

DevCon ensures the configured container SSH port is published to a random host port when starting containers. By default this is `22/tcp`, configurable via `agents.sshPort`. The `devcon-agent` feature installs and starts OpenSSH server inside supported Linux distributions (unless `agents.skipSshSetup` is enabled), and `devcon ssh connect` discovers the mapped host port and connects directly.

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
# Start on the default port (15000)
devcon serve
```

When a container requests port forwarding, `devcon serve` prints a message on stdout showing the container port and allocated host port. When forwarding stops, it prints a corresponding stop message.

If you run with `--output json`, these notifications are emitted as newline-delimited JSON events.

The control server should be kept running in a separate terminal (or as a background service) while containers are active. Containers that cannot reach the control server will still start and function, but port forwarding and URL opening will not be available.

### Agent installation options

By default, the agent binary is downloaded from GitHub Releases at container build time. You can customize this behaviour in `~/.config/devcon/config.yaml` or by copying the checked-in example at [devcon.example.yaml](devcon.example.yaml):

```yaml
agents:
  binaryUrl: https://example.com/devcon-agent
  useAgentBinary: true
  disable: false
```

## Configuration

The configuration file is stored at `~/.config/devcon/config.yaml` (XDG Base Directory). Copy [devcon.example.yaml](devcon.example.yaml) into that location and edit it directly, or pass a custom file with `--config`.

```bash
devcon --config ./devcon.example.yaml up .
```

Properties use camelCase dot-notation (e.g., `agents.binaryUrl`).

### Configuration reference

#### General

| Property | Type | Description |
|---|---|---|
| `dotfilesRepository` | string | URL of a dotfiles repository to clone into containers |
| `dotfilesInstallCommand` | string | Command used to install dotfiles after cloning |
| `defaultShell` | string | Shell to use when running `devcon shell` |
| `runtime` | string | Container runtime: `auto` (default), `docker`, or `container` |
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
| `agents.sshPort` | number | SSH port to run inside the container (default: `22`) |
| `agents.skipSshSetup` | bool | Skip installing/starting OpenSSH and skip SSH port auto-forwarding |

#### Agent forwarding (`agentForwarding.*`)

| Property | Type | Description |
|---|---|---|
| `agentForwarding.sshEnabled` | bool | Forward the SSH agent socket into containers |
| `agentForwarding.gpgEnabled` | bool | Forward the GPG agent socket into containers |
| `agentForwarding.ghEnabled` | bool | Forward GitHub CLI credentials into containers |
| `agentForwarding.sshSocketPath` | string | Override the SSH socket path (auto-detected by default) |
| `agentForwarding.gpgSocketPath` | string | Override the GPG socket path (auto-detected by default) |
| `agentForwarding.ghConfigPath` | string | Override the GitHub CLI config directory (auto-detected by default) |

#### Docker runtime (`runtimeConfig.docker.*`)

| Property | Type | Description |
|---|---|---|
| `runtimeConfig.docker.buildMemory` | string | Memory limit for Docker builds, e.g. `4g`, `512m` |
| `runtimeConfig.docker.buildCpu` | string | CPU limit for Docker builds, e.g. `2`, `0.5` |
| `runtimeConfig.docker.runMemory` | string | Memory limit for Docker containers, e.g. `8g`, `512m` |
| `runtimeConfig.docker.runCpu` | string | CPU limit for Docker containers, e.g. `2`, `0.5` |

#### Container runtime (`runtimeConfig.container.*`)

| Property | Type | Description |
|---|---|---|
| `runtimeConfig.container.buildMemory` | string | Memory limit for builds, e.g. `4g`, `512m` (default: `4g`) |
| `runtimeConfig.container.buildCpu` | string | CPU limit for builds, e.g. `2`, `0.5` |
| `runtimeConfig.container.runMemory` | string | Memory limit for running containers, e.g. `8g`, `512m` (default: `8g`) |
| `runtimeConfig.container.runCpu` | string | CPU limit for running containers, e.g. `2`, `0.5` (default: `2`) |

### Example config file

The repository includes a complete sample at [devcon.example.yaml](devcon.example.yaml). Start there if you want a working baseline you can copy into your project or home config directory.

The sample shows the full shape of a practical config, including runtime selection, dotfiles, agent forwarding, and resource limits.

## Using the container runtime

DevCon supports the native `container` CLI as an alternative to Docker on macOS. This runtime uses lightweight virtual machines and supports Rosetta 2 for running x86_64 images on ARM64 Macs.

### Prerequisites

The `container` CLI must be installed and available on your `PATH`.

### Selecting the container runtime

Set the runtime in your config file:

```yaml
runtime: container
```

### Required: set a build path outside /tmp

When building a container image, DevCon creates a temporary build context directory. By default this lands in `/tmp`, but the container runtime runs inside a virtual machine that cannot access macOS's `/tmp` filesystem. The build will fail unless you configure a `buildPath` that resolves to a directory the runtime can reach — any path under your home directory works.

Set it in your config file:

```yaml
buildPath: ~/.devcon/build
runtime: container
```

DevCon creates the directory automatically if it does not exist.

### Tuning resource limits

By default the container runtime uses 4 GB of memory per build. You can raise or lower this and optionally cap CPU usage:

```yaml
runtimeConfig:
  container:
    buildMemory: 8g
    buildCpu: 4
```

Accepted memory suffixes are `k`, `m`, and `g`. CPU is a decimal number of cores (e.g. `2` or `0.5`).

### Minimal container runtime config

```yaml
runtime: container
buildPath: ~/.devcon/build
runtimeConfig:
  container:
    buildMemory: 8g
```

### Notes

- The runtime always passes `--rosetta` when starting containers, enabling Rosetta 2 translation for x86_64 images on ARM64 Macs automatically.
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
