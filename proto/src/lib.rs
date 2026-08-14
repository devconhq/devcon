// Re-export generated protobuf code
pub mod agent {
    include!(concat!(env!("OUT_DIR"), "/devcon.rs"));
}

pub use agent::*;

/// Default port the devcon control server listens on for agent connections.
pub const DEFAULT_CONTROL_SERVER_PORT: u16 = 15000;

/// Default port the in-container agent listens on when the host's control server
/// dials into the container instead of the agent dialing out (used for runtimes
/// where a reliable host alias for the agent to dial isn't available).
pub const DEFAULT_AGENT_LISTEN_PORT: u16 = 15001;
