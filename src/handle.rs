//! Capability-handle generation.
//!
//! A handle is an unguessable single-use token (32 random bytes, hex-encoded). Randomness
//! comes from the OS CSPRNG via `/dev/urandom` — no third-party RNG crate, no userspace
//! state to seed. The handle is the agent's *only* reference to a secret (decisions.md D4);
//! it is opaque, short-lived, and bound to the first sandbox that injects it (D5).

use std::fs::File;
use std::io::Read;

pub fn new_handle() -> std::io::Result<String> {
    let mut buf = [0u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut buf)?;
    Ok(buf.iter().map(|b| format!("{:02x}", b)).collect())
}
