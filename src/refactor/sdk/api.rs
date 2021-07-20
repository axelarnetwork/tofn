//! API for tofn users
#[derive(Debug)]
pub struct TofnFatal;
pub type TofnResult<T> = Result<T, TofnFatal>;

pub type BytesVec = Vec<u8>;

pub use super::{
    party_share_counts::PartyShareCounts,
    protocol::{Fault, Protocol, ProtocolFaulters, ProtocolOutput},
    round::Round,
};

// TODO make these into const generics wherever they're used
pub const MAX_TOTAL_SHARE_COUNT: usize = 1000;
pub const MAX_PARTY_SHARE_COUNT: usize = MAX_TOTAL_SHARE_COUNT;

#[cfg(feature = "malicious")]
pub use super::wire_bytes::MsgType;
