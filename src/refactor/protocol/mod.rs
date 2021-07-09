//! TODO traits only here, rename to `api` or `traits` or something.
use crate::vecmap::{Behave, FillVecMap, HoleVecMap, Index};
use serde::{Deserialize, Serialize};

use self::executer::RoundExecuterRaw;

use super::BytesVec;

pub enum Protocol<F, K>
where
    K: Behave,
{
    NotDone(Box<dyn ProtocolRoundTrait<FinalOutput = F, Index = K>>),
    Done(ProtocolOutput<F, K>),
}

pub type ProtocolOutput<F, K> = Result<F, FillVecMap<K, Fault>>;

// TODO rename to ProtocolRound
pub trait ProtocolRoundTrait: Send + Sync {
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

    // TODO replace with round_as_any
    #[cfg(test)]
    fn round(
        &self,
    ) -> &Box<dyn RoundExecuterRaw<FinalOutput = Self::FinalOutput, Index = Self::Index>>;
}

pub mod executer;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Fault {
    MissingMessage,
    CorruptedMessage,
    ProtocolFault,
}
