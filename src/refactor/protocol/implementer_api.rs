use super::api::{BytesVec, Fault, Protocol, TofnResult};
pub use super::round::RoundInfo;
use super::round::{BcastAndP2pRound, BcastOnlyRound, NoMessagesRound};
use super::wire_bytes::{self, MsgType::*};
use crate::refactor::collections::{FillP2ps, FillVecMap, HoleVecMap, TypedUsize};
use crate::refactor::protocol::{
    bcast_and_p2p, bcast_only, no_messages,
    round::{Round, RoundType},
};

pub enum ProtocolBuilder<F, K, P> {
    NotDone(RoundBuilder<F, K, P>),
    Done(ProtocolBuilderOutput<F, K>),
}

impl<F, K, P> ProtocolBuilder<F, K, P> {
    pub fn build(self, info: RoundInfo<K, P>) -> TofnResult<Protocol<F, K, P>> {
        Ok(match self {
            Self::NotDone(builder) => Protocol::NotDone(match builder {
                RoundBuilder::BcastAndP2p {
                    round,
                    bcast_out,
                    p2ps_out,
                } => Round::new_bcast_and_p2p(round, info, bcast_out, p2ps_out)?,
                RoundBuilder::BcastOnly { round, bcast_out } => {
                    Round::new_bcast_only(round, info, bcast_out)?
                }
                RoundBuilder::NoMessages { round } => Round::new_no_messages(round, info)?,
            }),
            Self::Done(output) => Protocol::Done(info.into_party_faults(output)?),
        })
    }
}

pub type ProtocolBuilderOutput<F, K> = Result<F, FillVecMap<K, Fault>>; // subshare faults

pub enum RoundBuilder<F, K, P> {
    BcastAndP2p {
        round: Box<dyn bcast_and_p2p::ExecuterRaw<FinalOutput = F, Index = K, PartyIndex = P>>,
        bcast_out: BytesVec,
        p2ps_out: HoleVecMap<K, BytesVec>,
    },
    BcastOnly {
        round: Box<dyn bcast_only::ExecuterRaw<FinalOutput = F, Index = K, PartyIndex = P>>,
        bcast_out: BytesVec,
    },
    NoMessages {
        round: Box<dyn no_messages::Executer<FinalOutput = F, Index = K, PartyIndex = P>>,
    },
}

impl<F, K, P> Round<F, K, P> {
    pub fn new_bcast_and_p2p(
        round: Box<dyn bcast_and_p2p::ExecuterRaw<FinalOutput = F, Index = K, PartyIndex = P>>,
        info: RoundInfo<K, P>,
        bcast_out: BytesVec,
        p2ps_out: HoleVecMap<K, BytesVec>,
    ) -> TofnResult<Self> {
        // validate args
        if info.index().as_usize() >= info.party_count() {
            error!(
                "index {} out of bounds {}",
                info.index().as_usize(),
                info.party_count()
            );
            return Err(());
        }
        if p2ps_out.len() != info.party_count() {
            error!(
                "p2ps_out length {} differs from party_count {}",
                p2ps_out.len(),
                info.party_count()
            );
            return Err(());
        }

        let bcast_out = wire_bytes::wrap(bcast_out, info.index(), Bcast)?;
        let p2ps_out = p2ps_out
            .map2_result(|(to, payload)| wire_bytes::wrap(payload, info.index(), P2p { to }))?;

        let len = info.party_count(); // squelch build error
        Ok(Self {
            info,
            round_type: RoundType::BcastAndP2p(BcastAndP2pRound {
                round,
                bcast_out,
                p2ps_out,
                bcasts_in: FillVecMap::with_size(len),
                p2ps_in: FillP2ps::with_size(len),
            }),
        })
    }

    pub fn new_bcast_only(
        round: Box<dyn bcast_only::ExecuterRaw<FinalOutput = F, Index = K, PartyIndex = P>>,
        info: RoundInfo<K, P>,
        bcast_out: BytesVec,
    ) -> TofnResult<Self> {
        // validate args
        if info.index().as_usize() >= info.party_count() {
            error!(
                "index {} out of bounds {}",
                info.index().as_usize(),
                info.party_count()
            );
            return Err(());
        }

        let bcast_out = wire_bytes::wrap(bcast_out, info.index(), Bcast)?;

        let len = info.party_count(); // squelch build error
        Ok(Self {
            info,
            round_type: RoundType::BcastOnly(BcastOnlyRound {
                round,
                bcast_out,
                bcasts_in: FillVecMap::with_size(len),
            }),
        })
    }

    pub fn new_no_messages(
        round: Box<dyn no_messages::Executer<FinalOutput = F, Index = K, PartyIndex = P>>,
        info: RoundInfo<K, P>,
    ) -> TofnResult<Self> {
        if info.index().as_usize() >= info.party_count() {
            error!(
                "index {} out of bounds {}",
                info.index().as_usize(),
                info.party_count()
            );
            return Err(());
        }

        Ok(Self {
            info,
            round_type: RoundType::NoMessages(NoMessagesRound { round }),
        })
    }

    #[cfg(test)]
    pub fn round_as_any(&self) -> &dyn std::any::Any {
        match &self.round_type {
            RoundType::BcastAndP2p(r) => r.round.as_any(),
            RoundType::BcastOnly(r) => r.round.as_any(),
            RoundType::NoMessages(r) => r.round.as_any(),
        }
    }
}

use tracing::{error, info, warn};

pub(crate) fn serialize<T: ?Sized>(value: &T) -> TofnResult<BytesVec>
where
    T: serde::Serialize,
{
    match bincode::serialize(value) {
        Ok(bytes) => Ok(bytes),
        Err(err) => {
            error!("serialization failure: {}", err.to_string());
            Err(())
        }
    }
}

pub(crate) fn deserialize<'a, T>(bytes: &'a [u8]) -> TofnResult<T>
where
    T: serde::de::Deserialize<'a>,
{
    match bincode::deserialize(bytes) {
        Ok(value) => Ok(value),
        Err(err) => {
            error!("deserialization failure: {}", err.to_string());
            Err(())
        }
    }
}

pub(crate) fn log_fault_info<K>(me: TypedUsize<K>, faulter: TypedUsize<K>, fault: &str) {
    info!("party {} detect [{}] by {}", me, fault, faulter,);
}

pub(crate) fn log_fault_warn<K>(me: TypedUsize<K>, faulter: TypedUsize<K>, fault: &str) {
    warn!("party {} detect [{}] by {}", me, fault, faulter,);
}

pub(crate) fn log_accuse_warn<K>(me: TypedUsize<K>, faulter: TypedUsize<K>, fault: &str) {
    warn!("party {} accuse {} of [{}]", me, faulter, fault);
}
