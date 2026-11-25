//! byoai-chain 0.2.0: one Rust core for the five BYOAI receipt and hash-chain formats, plus
//! `handoff` (byoai.handoff/0.1), the case handoff receipt with fetch times, re-derivation and taint.
//! Every format reproduces its Python original byte for byte, so receipts and chains
//! already issued keep verifying. See `dialects` for the five formats and `api` for the
//! single JSON-in/JSON-out entry point the CLI, Python wheel, WASM module and JNI share.
extern crate alloc;

pub mod api;
pub mod dialects;
pub mod handoff;
pub mod value;

#[cfg(feature = "python")]
mod python;
#[cfg(feature = "cabi")]
mod wasm;
#[cfg(feature = "jni")]
mod jni_bridge;

pub use api::call_json;
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
