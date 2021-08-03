use tracing::{debug, error, warn};

use crate::{
    collections::{FillP2ps, FillVecMap, HoleVecMap, TypedUsize},
    sdk::api::{BytesVec, Fault, Protocol, ProtocolFaulters, TofnFatal, TofnResult},
};

use super::{
    implementer_api::{bcast_and_p2p, bcast_only, no_messages, p2p_only},
    protocol_info::ProtocolInfoDeluxe,
    wire_bytes::{self, MsgType::*, WireBytes},
};

pub struct Round<F, K, P> {
    info: ProtocolInfoDeluxe<K, P>,
    round_type: RoundType<F, K>,
    msg_in_faulters: ProtocolFaulters<P>,
    future_messages: Vec<(TypedUsize<P>, BytesVec)>,
}

enum RoundType<F, K> {
    BcastAndP2p(BcastAndP2pRound<F, K>),
    BcastOnly(BcastOnlyRound<F, K>),
    P2pOnly(P2pOnlyRound<F, K>),
    NoMessages(NoMessagesRound<F, K>),
}

struct NoMessagesRound<F, K> {
    round: Box<dyn no_messages::Executer<FinalOutput = F, Index = K>>,
}

struct BcastOnlyRound<F, K> {
    round: Box<dyn bcast_only::ExecuterRaw<FinalOutput = F, Index = K>>,
    bcast_out: BytesVec,
    bcasts_in: FillVecMap<K, BytesVec>,
}

struct P2pOnlyRound<F, K> {
    round: Box<dyn p2p_only::ExecuterRaw<FinalOutput = F, Index = K>>,
    p2ps_out: HoleVecMap<K, BytesVec>,
    p2ps_in: FillP2ps<K, BytesVec>,
}

struct BcastAndP2pRound<F, K> {
    round: Box<dyn bcast_and_p2p::ExecuterRaw<FinalOutput = F, Index = K>>,
    bcast_out: BytesVec,
    p2ps_out: HoleVecMap<K, BytesVec>,
    bcasts_in: FillVecMap<K, BytesVec>,
    p2ps_in: FillP2ps<K, BytesVec>,
}

// api: Round methods for tofn users
impl<F, K, P> Round<F, K, P> {
    pub fn bcast_out(&self) -> Option<&BytesVec> {
        match &self.round_type {
            RoundType::BcastAndP2p(r) => Some(&r.bcast_out),
            RoundType::BcastOnly(r) => Some(&r.bcast_out),
            RoundType::NoMessages(_) | RoundType::P2pOnly(_) => None,
        }
    }

    pub fn p2ps_out(&self) -> Option<&HoleVecMap<K, BytesVec>> {
        match &self.round_type {
            RoundType::BcastAndP2p(r) => Some(&r.p2ps_out),
            RoundType::P2pOnly(r) => Some(&r.p2ps_out),
            RoundType::BcastOnly(_) | RoundType::NoMessages(_) => None,
        }
    }

    /// we assume message autenticity
    /// thus, it's a fatal error if `from` is out of bounds
    pub fn msg_in(&mut self, from: TypedUsize<P>, bytes: &[u8]) -> TofnResult<()> {
        let share_id = self.info().share_info().share_id();
        let party_id = self.info().party_id();

        // unwrap metadata
        let bytes_meta: WireBytes<K> = match wire_bytes::unwrap(bytes) {
            Some(w) => w,
            None => {
                warn!(
                    "peer {} (party {}) says: deserialization failed for message from party {}",
                    share_id, party_id, from
                );
                self.msg_in_faulters.set(from, Fault::CorruptedMessage)?; // fatal error if `from` is out of bounds
                return Ok(());
            }
        };

        if bytes_meta.round == self.info.round() + 1 {
            debug!(
                "peer {} (party {}) says: received an early message from party {} for the next round {}",
                share_id,
                party_id,
                from,
                self.info.round() + 1
            );

            self.future_messages.push((from, bytes.to_vec()));

            return Ok(());
        } else if bytes_meta.round != self.info.round() {
            warn!(
                "peer {} (party {}) says: received a message from party {} for another round {}",
                share_id, party_id, from, bytes_meta.round,
            );

            self.msg_in_faulters.set(from, Fault::CorruptedMessage)?;

            return Ok(());
        }

        // verify share_id belongs to this party
        match self
            .info
            .party_share_counts()
            .share_to_party_id(bytes_meta.from)
        {
            Ok(from_party_id) if from_party_id == from => (), // happy path
            _ => {
                warn!(
                    "peer {} (party {}) says: share id {} does not belong to party {}",
                    share_id, party_id, bytes_meta.from, from
                );
                self.msg_in_faulters.set(from, Fault::CorruptedMessage)?;
                return Ok(());
            }
        }

        // store message payload according to round type (bcast and/or p2p)
        match &mut self.round_type {
            RoundType::BcastAndP2p(r) => match bytes_meta.msg_type {
                Bcast => {
                    if r.bcasts_in.is_none(bytes_meta.from)? {
                        r.bcasts_in.set(bytes_meta.from, bytes_meta.payload)?;
                    } else {
                        warn!(
                            "peer {} (party {}) says: duplicate message from peer {} (party {})",
                            share_id, party_id, bytes_meta.from, from,
                        );
                        self.msg_in_faulters.set(from, Fault::CorruptedMessage)?;
                    }
                }
                P2p { to } => {
                    if r.p2ps_in.is_none(bytes_meta.from, to)? {
                        r.p2ps_in.set(bytes_meta.from, to, bytes_meta.payload)?;
                    } else {
                        warn!(
                            "peer {} (party {}) says: duplicate message from peer {} (party {})",
                            share_id, party_id, bytes_meta.from, from,
                        );
                        self.msg_in_faulters.set(from, Fault::CorruptedMessage)?;
                    }
                }
            },
            RoundType::BcastOnly(r) => match bytes_meta.msg_type {
                Bcast => {
                    if r.bcasts_in.is_none(bytes_meta.from)? {
                        r.bcasts_in.set(bytes_meta.from, bytes_meta.payload)?;
                    } else {
                        warn!(
                            "peer {} (party {}) says: duplicate message from peer {} (party {})",
                            share_id, party_id, bytes_meta.from, from,
                        );
                        self.msg_in_faulters.set(from, Fault::CorruptedMessage)?;
                    }
                }
                P2p { to } => {
                    warn!(
                        "peer {} (party {}) says: unexpected p2p received from peer {} (party {}) to peer {} in round {}",
                        share_id, party_id, bytes_meta.from, from, to, self.info.round(),
                    );
                    self.msg_in_faulters.set(from, Fault::CorruptedMessage)?;
                }
            },
            RoundType::P2pOnly(r) => match bytes_meta.msg_type {
                Bcast => {
                    warn!(
                        "peer {} (party {}) says: unexpected bcast received from peer {} (party {}) in round {}",
                        share_id, party_id, bytes_meta.from, from, self.info.round(),
                    );
                    self.msg_in_faulters.set(from, Fault::CorruptedMessage)?;
                }
                P2p { to } => {
                    if r.p2ps_in.is_none(bytes_meta.from, to)? {
                        r.p2ps_in.set(bytes_meta.from, to, bytes_meta.payload)?;
                    } else {
                        warn!(
                            "peer {} (party {}) says: duplicate message from peer {} (party {})",
                            share_id, party_id, bytes_meta.from, from,
                        );
                        self.msg_in_faulters.set(from, Fault::CorruptedMessage)?;
                    }
                }
            },
            RoundType::NoMessages(_) => {
                match bytes_meta.msg_type {
                    Bcast => {
                        warn!(
                            "peer {} (party {}) says: unexpected bcast received from peer {} (party {}) in round {}",
                            share_id, party_id, bytes_meta.from, from, self.info.round(),
                        );
                    }
                    P2p { to } => {
                        warn!(
                            "peer {} (party {}) says: unexpected p2p received from peer {} (party {}) to peer {} in round {}",
                            share_id, party_id, bytes_meta.from, from, to, self.info.round(),
                        );
                    }
                };

                self.msg_in_faulters.set(from, Fault::CorruptedMessage)?;
            }
        }

        Ok(())
    }

    pub fn expecting_more_msgs_this_round(&self) -> bool {
        match &self.round_type {
            RoundType::BcastAndP2p(r) => !r.bcasts_in.is_full() || !r.p2ps_in.is_full(),
            RoundType::BcastOnly(r) => !r.bcasts_in.is_full(),
            RoundType::P2pOnly(r) => !r.p2ps_in.is_full(),
            RoundType::NoMessages(_) => false,
        }
    }

    pub fn execute_next_round(mut self) -> TofnResult<Protocol<F, K, P>> {
        let my_share_id = self.info().share_info().share_id();
        let my_party_id = self.info().party_id();
        let curr_round_num = self.info.round();

        if !self.msg_in_faulters.is_empty() {
            warn!(
                "peer {} (party {}) says: faulters detected during msg_in: ending protocol in round {}",
                my_share_id, my_party_id, curr_round_num,
            );

            return Ok(Protocol::Done(Err(self.msg_in_faulters)));
        }

        self.info.advance_round();

        let mut protocol = match self.round_type {
            RoundType::BcastAndP2p(r) => r
                .round
                .execute_raw(self.info.share_info(), r.bcasts_in, r.p2ps_in)?
                .build(self.info),
            RoundType::BcastOnly(r) => r
                .round
                .execute_raw(self.info.share_info(), r.bcasts_in)?
                .build(self.info),
            RoundType::P2pOnly(r) => r
                .round
                .execute_raw(self.info.share_info(), r.p2ps_in)?
                .build(self.info),
            RoundType::NoMessages(r) => r.round.execute(self.info.share_info())?.build(self.info),
        }?;

        if !self.future_messages.is_empty() {
            // Any faulters identified here will be returned during
            // the execution of the next round.
            if let Protocol::NotDone(round) = &mut protocol {
                for (party_id, msg) in self.future_messages.into_iter() {
                    debug!(
                        "peer {} (party {}) says: replaying party {}'s early round {} message",
                        my_share_id,
                        my_party_id,
                        party_id,
                        curr_round_num + 1,
                    );

                    round.msg_in(party_id, &msg)?;
                }
            } else if let Protocol::Done(Ok(_)) = &mut protocol {
                for (party_id, _) in self.future_messages.into_iter() {
                    warn!(
                        "peer {} (party {}) says: received unexpected future message from party {} in round {}",
                        my_share_id, my_party_id, party_id, curr_round_num,
                    );

                    self.msg_in_faulters
                        .set(party_id, Fault::CorruptedMessage)?;
                }
            }
        }

        Ok(protocol)
    }

    pub fn info(&self) -> &ProtocolInfoDeluxe<K, P> {
        &self.info
    }

    // private methods
    fn new(info: ProtocolInfoDeluxe<K, P>, round_type: RoundType<F, K>) -> Self {
        let party_count = info.party_share_counts().party_count();

        Self {
            info,
            round_type,
            msg_in_faulters: FillVecMap::with_size(party_count),
            future_messages: Vec::new(),
        }
    }

    pub(super) fn new_bcast_and_p2p(
        round: Box<dyn bcast_and_p2p::ExecuterRaw<FinalOutput = F, Index = K>>,
        info: ProtocolInfoDeluxe<K, P>,
        bcast_out: BytesVec,
        p2ps_out: HoleVecMap<K, BytesVec>,
    ) -> TofnResult<Self> {
        let share_count = info.share_info().share_count();
        let share_id = info.share_info().share_id();

        // validate args
        if p2ps_out.len() != share_count {
            error!(
                "peer {} (party {}) says: p2ps_out length {} differs from share count {}",
                share_id,
                info.party_id(),
                p2ps_out.len(),
                share_count,
            );
            return Err(TofnFatal);
        }

        let bcast_out = wire_bytes::wrap(bcast_out, share_id, Bcast, info.round())?;
        let p2ps_out = p2ps_out.map2_result(|(to, payload)| {
            wire_bytes::wrap(payload, share_id, P2p { to }, info.round())
        })?;

        Ok(Self::new(
            info,
            RoundType::BcastAndP2p(BcastAndP2pRound {
                round,
                bcast_out,
                p2ps_out,
                bcasts_in: FillVecMap::with_size(share_count),
                p2ps_in: FillP2ps::with_size(share_count)?,
            }),
        ))
    }

    pub(super) fn new_bcast_only(
        round: Box<dyn bcast_only::ExecuterRaw<FinalOutput = F, Index = K>>,
        info: ProtocolInfoDeluxe<K, P>,
        bcast_out: BytesVec,
    ) -> TofnResult<Self> {
        let bcast_out =
            wire_bytes::wrap(bcast_out, info.share_info().share_id(), Bcast, info.round())?;

        let share_count = info.share_info().share_count();

        Ok(Self::new(
            info,
            RoundType::BcastOnly(BcastOnlyRound {
                round,
                bcast_out,
                bcasts_in: FillVecMap::with_size(share_count),
            }),
        ))
    }

    pub(super) fn new_p2p_only(
        round: Box<dyn p2p_only::ExecuterRaw<FinalOutput = F, Index = K>>,
        info: ProtocolInfoDeluxe<K, P>,
        p2ps_out: HoleVecMap<K, BytesVec>,
    ) -> TofnResult<Self> {
        let share_count = info.share_info().share_count();
        let share_id = info.share_info().share_id();

        // validate args
        if p2ps_out.len() != share_count {
            error!(
                "peer {} (party {}) says: p2ps_out length {} differs from share count {}",
                share_id,
                info.party_id(),
                p2ps_out.len(),
                share_count,
            );
            return Err(TofnFatal);
        }

        let p2ps_out = p2ps_out.map2_result(|(to, payload)| {
            wire_bytes::wrap(payload, share_id, P2p { to }, info.round())
        })?;

        Ok(Self::new(
            info,
            RoundType::P2pOnly(P2pOnlyRound {
                round,
                p2ps_out,
                p2ps_in: FillP2ps::with_size(share_count)?,
            }),
        ))
    }

    pub(super) fn new_no_messages(
        round: Box<dyn no_messages::Executer<FinalOutput = F, Index = K>>,
        info: ProtocolInfoDeluxe<K, P>,
    ) -> TofnResult<Self> {
        Ok(Self::new(
            info,
            RoundType::NoMessages(NoMessagesRound { round }),
        ))
    }

    #[cfg(test)]
    pub fn round_as_any(&self) -> &dyn std::any::Any {
        match &self.round_type {
            RoundType::BcastAndP2p(r) => r.round.as_any(),
            RoundType::BcastOnly(r) => r.round.as_any(),
            RoundType::P2pOnly(r) => r.round.as_any(),
            RoundType::NoMessages(r) => r.round.as_any(),
        }
    }
}

#[cfg(feature = "malicious")]
pub mod malicious {
    use tracing::{error, info};

    use crate::sdk::{
        api::TofnFatal,
        round::RoundType,
        wire_bytes::{
            malicious::corrupt_payload,
            MsgType::{self, *},
        },
    };

    use super::{Round, TofnResult};

    impl<F, K, P> Round<F, K, P> {
        pub fn corrupt_msg_payload(&mut self, msg_type: MsgType<K>) -> TofnResult<()> {
            info!(
                "malicious party {} corrupt msg",
                self.info.share_info().share_id()
            );
            match &mut self.round_type {
                RoundType::BcastAndP2p(r) => match msg_type {
                    Bcast => r.bcast_out = corrupt_payload::<K>(&r.bcast_out)?,
                    P2p { to } => {
                        let p2p_out = r.p2ps_out.get_mut(to)?;
                        *p2p_out = corrupt_payload::<K>(p2p_out)?
                    }
                },
                RoundType::BcastOnly(r) => match msg_type {
                    Bcast => r.bcast_out = corrupt_payload::<K>(&r.bcast_out)?,
                    P2p { to: _ } => {
                        error!("no p2ps expected this round, can't corrupt msg bytes",);
                        return Err(TofnFatal);
                    }
                },
                RoundType::P2pOnly(r) => match msg_type {
                    Bcast => {
                        error!("no bcasts expected this round, can't corrupt msg bytes",);
                        return Err(TofnFatal);
                    }
                    P2p { to } => {
                        let p2p_out = r.p2ps_out.get_mut(to)?;
                        *p2p_out = corrupt_payload::<K>(p2p_out)?
                    }
                },
                RoundType::NoMessages(_) => {
                    error!("no messages expected this round, can't corrupt msg bytes",);
                    return Err(TofnFatal);
                }
            }
            Ok(())
        }
    }
}
