//! API for tofn users
pub type TofnResult<T> = Result<T, TofnFatal>;
pub type BytesVec = Vec<u8>;

pub use super::{
    party_share_counts::PartyShareCounts,
    protocol::{Fault, Protocol, ProtocolFaulters, ProtocolOutput},
    round::Round,
};

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TofnFatal;

// TODO make these into const generics wherever they're used
pub const MAX_TOTAL_SHARE_COUNT: usize = 1000;
pub const MAX_PARTY_SHARE_COUNT: usize = MAX_TOTAL_SHARE_COUNT;

/// Expose tofn's (de)serialization functions
/// that use the appropriate bincode config options.
pub use super::wire_bytes::{deserialize, serialize};

#[cfg(feature = "malicious")]
pub use super::wire_bytes::MsgType;
