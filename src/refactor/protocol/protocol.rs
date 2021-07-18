use super::round::Round;
use crate::refactor::collections::FillVecMap;
use serde::{Deserialize, Serialize};

pub enum Protocol<F, K, P> {
    NotDone(Round<F, K, P>),
    Done(ProtocolOutput<F, P>),
}

pub type ProtocolOutput<F, P> = Result<F, ProtocolFaulters<P>>;
pub type ProtocolFaulters<P> = FillVecMap<P, Fault>; // party (not subhsare) faults

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Fault {
    MissingMessage,
    CorruptedMessage,
    ProtocolFault,
}
