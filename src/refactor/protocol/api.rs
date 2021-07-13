use crate::refactor::collections::{Behave, FillVecMap, HoleVecMap, TypedUsize};
use crate::refactor::protocol::round::Round;
use serde::{Deserialize, Serialize};
use tracing::warn;

pub type TofnResult<T> = Result<T, ()>;
pub type BytesVec = Vec<u8>;

pub enum Protocol<F, K>
where
    K: Behave,
{
    NotDone(RoundContainer<F, K>),
    Done(ProtocolOutput<F, K>),
}

// need RoundContainer because we don't want to expose all the variants of Round
pub struct RoundContainer<F, K>
where
    K: Behave,
{
    // party_count, index?
    pub round_type: Round<F, K>,
}

pub type ProtocolOutput<F, K> = Result<F, FillVecMap<K, Fault>>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Fault {
    MissingMessage,
    CorruptedMessage,
    ProtocolFault,
}

impl<F, K> RoundContainer<F, K>
where
    K: Behave,
{
    pub fn bcast_out(&self) -> Option<&BytesVec> {
        match &self.round_type {
            Round::BcastAndP2p(r) => Some(&r.bcast_out),
            Round::BcastOnly(r) => Some(&r.bcast_out),
            Round::NoMessages(_) => None,
        }
    }
    pub fn p2ps_out(&self) -> Option<&HoleVecMap<K, BytesVec>> {
        match &self.round_type {
            Round::BcastAndP2p(r) => Some(&r.p2ps_out),
            Round::BcastOnly(_) | Round::NoMessages(_) => None,
        }
    }
    pub fn bcast_in(&mut self, from: TypedUsize<K>, bytes: &[u8]) -> TofnResult<()> {
        match &mut self.round_type {
            Round::BcastAndP2p(r) => r.bcasts_in.set_warn(from, bytes.to_vec()),
            Round::BcastOnly(r) => r.bcasts_in.set_warn(from, bytes.to_vec()),
            Round::NoMessages(_) => {
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
            Round::BcastAndP2p(r) => r.p2ps_in.set_warn(from, to, bytes.to_vec()),
            Round::BcastOnly(_) | Round::NoMessages(_) => {
                warn!("`p2p_in` called but no p2ps expected; ignoring `bytes`");
                Ok(())
            }
        }
    }
    pub fn expecting_more_msgs_this_round(&self) -> bool {
        match &self.round_type {
            Round::BcastAndP2p(r) => !r.bcasts_in.is_full() || !r.p2ps_in.is_full(),
            Round::BcastOnly(r) => !r.bcasts_in.is_full(),
            Round::NoMessages(_) => false,
        }
    }
    pub fn execute_next_round(self) -> TofnResult<Protocol<F, K>> {
        match self.round_type {
            Round::BcastAndP2p(r) => r
                .round
                .execute_raw(r.party_count, r.index, r.bcasts_in, r.p2ps_in)?
                .build(r.party_count, r.index),
            Round::BcastOnly(r) => r
                .round
                .execute_raw(r.party_count, r.index, r.bcasts_in)?
                .build(r.party_count, r.index),
            Round::NoMessages(r) => r
                .round
                .execute(r.party_count, r.index)?
                .build(r.party_count, r.index),
        }
    }
    pub fn party_count(&self) -> usize {
        match &self.round_type {
            Round::BcastAndP2p(r) => r.party_count,
            Round::BcastOnly(r) => r.party_count,
            Round::NoMessages(r) => r.party_count,
        }
    }
    pub fn index(&self) -> TypedUsize<K> {
        match &self.round_type {
            Round::BcastAndP2p(r) => r.index,
            Round::BcastOnly(r) => r.index,
            Round::NoMessages(r) => r.index,
        }
    }
}
