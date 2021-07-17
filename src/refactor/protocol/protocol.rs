use super::round::Round;
use serde::{Deserialize, Serialize};

pub enum Protocol<F, K, P> {
    NotDone(Round<F, K, P>),
    Done(ProtocolOutput<F, P>),
}

use crate::refactor::collections::FillVecMap;

pub type ProtocolOutput<F, P> = Result<F, FillVecMap<P, Fault>>; // party (not subhsare) faults

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Fault {
    MissingMessage,
    CorruptedMessage,
    ProtocolFault,
}
