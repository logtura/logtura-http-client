//! Library surface so integration tests in `tests/` can exercise the
//! same modules the binary uses. The binary's `main.rs` re-declares
//! these as `mod` for crate-internal use; everything still lives in
//! one source tree.

pub mod auth;
pub mod config;
pub mod cursor;
pub mod poll;
