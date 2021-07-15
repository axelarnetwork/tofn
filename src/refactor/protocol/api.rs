use crate::refactor::collections::{Behave, FillVecMap, HoleVecMap, TypedUsize};
use crate::refactor::protocol::round::RoundType;
use serde::{Deserialize, Serialize};
use tracing::warn;

pub type TofnResult<T> = Result<T, ()>;
pub type BytesVec = Vec<u8>;

pub enum Protocol<F, K>
where
    K: Behave,
{
    NotDone(Round<F, K>),
    Done(ProtocolOutput<F, K>),
}

pub use super::round::Round;
pub type ProtocolOutput<F, K> = Result<F, FillVecMap<K, Fault>>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Fault {
    MissingMessage,
    CorruptedMessage,
    ProtocolFault,
}

impl<F, K> Round<F, K>
where
    K: Behave,
{
    pub fn bcast_out(&self) -> Option<&BytesVec> {
        match &self.round_type {
            RoundType::BcastAndP2p(r) => Some(&r.bcast_out),
            RoundType::BcastOnly(r) => Some(&r.bcast_out),
            RoundType::NoMessages(_) => None,
        }
    }
    pub fn p2ps_out(&self) -> Option<&HoleVecMap<K, BytesVec>> {
        match &self.round_type {
            RoundType::BcastAndP2p(r) => Some(&r.p2ps_out),
            RoundType::BcastOnly(_) | RoundType::NoMessages(_) => None,
        }
    }
    pub fn bcast_in(&mut self, from: TypedUsize<K>, bytes: &[u8]) -> TofnResult<()> {
        match &mut self.round_type {
            RoundType::BcastAndP2p(r) => r.bcasts_in.set_warn(from, bytes.to_vec()),
            RoundType::BcastOnly(r) => r.bcasts_in.set_warn(from, bytes.to_vec()),
            RoundType::NoMessages(_) => {
                warn!("`bcast_in` called but no bcasts expected; ignoring `bytes`");
                Ok(())
            }
        }
    }
    pub fn p2p_in(
        &mut self,
        from: TypedUsize<K>,
        to: TypedUsize<K>,
        bytes: &[u8],
    ) -> TofnResult<()> {
        match &mut self.round_type {
            RoundType::BcastAndP2p(r) => r.p2ps_in.set_warn(from, to, bytes.to_vec()),
            RoundType::BcastOnly(_) | RoundType::NoMessages(_) => {
                warn!("`p2p_in` called but no p2ps expected; ignoring `bytes`");
                Ok(())
            }
        }
    }
    pub fn expecting_more_msgs_this_round(&self) -> bool {
        match &self.round_type {
            RoundType::BcastAndP2p(r) => !r.bcasts_in.is_full() || !r.p2ps_in.is_full(),
            RoundType::BcastOnly(r) => !r.bcasts_in.is_full(),
            RoundType::NoMessages(_) => false,
        }
    }
    pub fn execute_next_round(self) -> TofnResult<Protocol<F, K>> {
        match self.round_type {
            RoundType::BcastAndP2p(r) => r
                .round
                .execute_raw(&self.info, r.bcasts_in, r.p2ps_in)?
                .build(self.info),
            RoundType::BcastOnly(r) => r
                .round
                .execute_raw(&self.info, r.bcasts_in)?
                .build(self.info),
            RoundType::NoMessages(r) => r.round.execute(&self.info)?.build(self.info),
        }
    }
    pub fn party_count(&self) -> usize {
        self.info.party_count
    }
    pub fn index(&self) -> TypedUsize<K> {
        self.info.index
    }
}
