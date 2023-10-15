//! API for tofn users
pub type TofnResult<T> = Result<T, TofnFatal>;
pub type BytesVec = Vec<u8>;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TofnFatal;

/// Expose tofn's (de)serialization functions
/// that use the appropriate bincode config options.
pub use super::wire_bytes::{deserialize, serialize};
