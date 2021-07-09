//! TODO traits only here, rename to `api` or `traits` or something.
use crate::vecmap::{Behave, FillVecMap, HoleVecMap, Index};
use serde::{Deserialize, Serialize};

use super::protocol_round::bcast_and_p2p::executer::RoundExecuterRaw;

pub type TofnResult<T> = Result<T, String>;
pub type BytesVec = Vec<u8>;

pub enum Protocol<F, K>
where
    K: Behave,
{
    NotDone(Box<dyn Round<FinalOutput = F, Index = K>>),
    Done(ProtocolOutput<F, K>),
}

pub type ProtocolOutput<F, K> = Result<F, FillVecMap<K, Fault>>;

// TODO rename to ProtocolRound
pub trait Round: Send + Sync {
    type FinalOutput;
    type Index: Behave;

    fn bcast_out(&self) -> &Option<BytesVec>;
    fn p2ps_out(&self) -> &Option<HoleVecMap<Self::Index, BytesVec>>;
    fn bcast_in(&mut self, from: Index<Self::Index>, bytes: &[u8]);
    fn p2p_in(&mut self, from: Index<Self::Index>, to: Index<Self::Index>, bytes: &[u8]);
    fn expecting_more_msgs_this_round(&self) -> bool;
    fn execute_next_round(self: Box<Self>) -> Protocol<Self::FinalOutput, Self::Index>;
    fn party_count(&self) -> usize;
    fn index(&self) -> Index<Self::Index>;

    // TODO replace with round_as_any and return Any instead of RoundExecuterRaw
    #[cfg(test)]
    fn round(
        &self,
    ) -> &Box<dyn RoundExecuterRaw<FinalOutput = Self::FinalOutput, Index = Self::Index>>;
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Fault {
    MissingMessage,
    CorruptedMessage,
    ProtocolFault,
}
