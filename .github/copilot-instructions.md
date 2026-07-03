# DevCon Copilot Instructions

## Communication style

Do not use emojis in responses. Be direct and concise when addressing the user.

DevCon is a Rust CLI tool for managing and launching development containers. It parses `devcontainer.json` configuration, downloads OCI features, and orchestrates container build/start/shell lifecycle against pluggable container runtimes (Docker, container).

## Workspace structure

Cargo workspace with four members:
- **`.`** (`devcon`) — main binary and library
- **`agent/`** — in-container agent binary that communicates back to the host
- **`proto/`** — protobuf definitions compiled with `prost-build` (requires `protoc` installed)
- **`schema/`** — schema crate containing `devcontainer.json` models, feature schema types, and lockfile/lifecycle schema logic

## Build, test, and lint

Run these validation steps before considering a change complete. These commands mirror the CI pipeline.

```bash
# Build
cargo build
cargo build --release

# Required format / lint checks (CI parity)
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --workspace -- -D warnings

# Required unit test checks (CI parity)
cargo test --lib --bins --verbose
cargo test --lib --bins --all-features --verbose

# Single unit test
cargo test --lib <test_name>

# Required integration tests (CI parity, requires Docker)
RUST_BACKTRACE=full CONTAINER_RUNTIME=docker cargo test --test main --verbose

# Single integration test
CONTAINER_RUNTIME=docker cargo test --test main test_build_simple
```

Prerequisites: `protoc` is required for builds/tests, and Docker is required for CI-parity integration tests. Integration tests use `CONTAINER_RUNTIME` to choose runtime. Test containers are named `devcon-test-*` and cleaned up after CI runs.

## Architecture

### Main library (`src/`)

| Module | Purpose |
|---|---|
| `command.rs` | Handler functions for each CLI subcommand; loads config, creates runtime/driver, delegates work |
| `config.rs` | User config (YAML at `~/.config/devcon/config.yaml`); properties use camelCase dot-notation (e.g. `agents.binaryUrl`) |
| `devcontainer.rs` | Compatibility module that re-exports devcontainer schema/parsing APIs from `schema` |
| `feature.rs` | Compatibility module that re-exports feature schema types from `schema` |
| `driver/runtime.rs` | `ContainerRuntime` + `ContainerHandle` traits; impls in `driver/runtime/docker.rs` and `driver/runtime/container.rs` |
| `driver/orchestrator.rs` | `ContainerOrchestrator` — orchestrates full build→start→lifecycle-hooks flow |
| `driver/dockerfile.rs` | Build context and Dockerfile generation for feature injection and metadata |
| `driver/environment.rs` | Environment composition/resolution for container start and SSH session env |
| `driver/feature_process.rs` | Downloads and installs devcontainer features from OCI registries (ghcr.io) |
| `driver/lifecycle.rs` | Lifecycle hook execution utilities and marker-guarded command execution |
| `driver/control_server.rs` | TCP server (default port 15000) started by `devcon serve`; manages agent connections |
| `driver/agent.rs` | Host-side agent communication over protobuf |
| `driver/agent_socket.rs` | SSH/GPG agent socket detection and forwarding helpers |
| `error.rs` | Central `Error` enum + `Result<T>` type alias |
| `workspace.rs` | Abstracts the project directory and devcontainer config discovery |
| `output.rs` | `OutputFormat` enum (`text` / `json`); passed through all command handlers |

### Agent (`agent/`)

Binary that runs inside the container. Communicates with the host control server via protobuf messages defined in `proto/agent.proto` (port forwarding, URL opening, tunnel requests).

### Proto compilation

`proto/build.rs` calls `prost_build::compile_protos` on `agent.proto`. Any changes to `agent.proto` require `protoc` to be installed and trigger a rebuild of generated Rust code.

## Key conventions

- **Error handling**: Use `thiserror`-derived `Error` enum with named constructor methods (`Error::config(...)`, `Error::runtime(...)`, `Error::feature(...)`, etc.) rather than `Error::Generic`. Add new variants when a distinct error category is needed.
- **`Result<T>`**: Always import from `crate::error::Result`, not `std::result::Result` directly.
- **Runtime selection**: `ContainerRuntime` is always `Box<dyn ContainerRuntime>`; the concrete type is resolved in `command.rs` via `get_runtime_specific_config()` from the user's config.
- **Logging**: Use `tracing` macros (`trace!`, `debug!`, `warn!`). The `-d` flag maps to log level (1=INFO, 2=DEBUG, 3+=TRACE). Third-party crate logs are suppressed unless `-dddd`.
- **Config property paths**: camelCase dot-notation strings (e.g., `agents.binaryUrl`, `dotfilesRepository`). This convention is enforced in config get/set/unset CLI commands.
- **Integration test helpers**: All test setup goes through functions in `tests/test_utils.rs` (`create_test_devcontainer`, `create_test_config`, etc.). The `CONTAINER_RUNTIME` environment variable selects between `docker` (default) and `container`.
- **Workspace edition**: `edition = "2024"` is set at the workspace level; all crates inherit it.
