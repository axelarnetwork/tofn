use tracing::{error, warn};

use crate::{
    collections::{zip3, FillP2ps, FillVecMap, HoleVecMap, TypedUsize},
    sdk::{
        api::{BytesVec, Fault, ProtocolFaulters, TofnFatal, TofnResult},
        wire_bytes::ExpectedMsgTypes::{self, *},
    },
};

use super::{
    api::Protocol,
    executer::ExecuterRaw,
    protocol_info::ProtocolInfoDeluxe,
    wire_bytes::{self, MsgType::*, XWireBytes},
};

pub struct Round<F, K, P> {
    info: ProtocolInfoDeluxe<K, P>,
    round: Box<dyn ExecuterRaw<FinalOutput = F, Index = K>>,
    bcast_out: Option<BytesVec>,
    p2ps_out: Option<HoleVecMap<K, BytesVec>>,
    bcasts_in: FillVecMap<K, BytesVec>,
    p2ps_in: FillP2ps<K, BytesVec>,
    expected_msg_types: FillVecMap<K, ExpectedMsgTypes>,
    msg_in_faulters: ProtocolFaulters<P>,
}

// api: Round methods for tofn users
impl<F, K, P> Round<F, K, P> {
    pub fn bcast_out(&self) -> Option<&BytesVec> {
        self.bcast_out.as_ref()
    }

    pub fn p2ps_out(&self) -> Option<&HoleVecMap<K, BytesVec>> {
        self.p2ps_out.as_ref()
    }

    /// we assume message autenticity
    /// thus, it's a fatal error if `from` is out of bounds
    pub fn msg_in(&mut self, from: TypedUsize<P>, bytes: &[u8]) -> TofnResult<()> {
        let share_id = self.info().share_info().share_id();
        let party_id = self.info().party_id();

        // deserialize metadata
        // TODO bounds check everything in bytes_meta
        let bytes_meta: XWireBytes<K> = match wire_bytes::decode_message(bytes) {
            Some(w) => w,
            None => {
                warn!(
                    "peer {} (party {}) says: msg_in fail to deserialize metadata for msg from party {}",
                    share_id, party_id, from
                );
                self.msg_in_faulters.set(from, Fault::CorruptedMessage)?; // fatal error if `from` is out of bounds
                return Ok(());
            }
        };

        // verify share_id belongs to this party
        match self
            .info
            .party_share_counts()
            .share_to_party_id(bytes_meta.from)
        {
            Ok(from_party_id) if from_party_id == from => (), // happy path
            _ => {
                warn!(
                    "peer {} (party {}) says: msg_in share id {} does not belong to party {}",
                    share_id, party_id, bytes_meta.from, from
                );
                self.msg_in_faulters.set(from, Fault::CorruptedMessage)?;
                return Ok(());
            }
        }

        // store and check expected message types from this share_id
        let expected_msg_type = match self.expected_msg_types.get(bytes_meta.from)? {
            Some(msg_type) => {
                if *msg_type != bytes_meta.expected_msg_types {
                    warn!(
                        "peer {} (party {}) says: msg_in share id {} gave conflicting expected message types",
                        share_id, party_id, bytes_meta.from
                    );
                    self.msg_in_faulters.set(from, Fault::CorruptedMessage)?;
                    return Ok(());
                }
                *msg_type
            }
            None => {
                self.expected_msg_types
                    .set(bytes_meta.from, bytes_meta.expected_msg_types)?;
                bytes_meta.expected_msg_types
            }
        };

        // store message payload according to round type (bcast and/or p2p)
        match bytes_meta.msg_type {
            // it sure would be nice to break out of match arms: https://stackoverflow.com/q/37814942
            Bcast => {
                if matches!(expected_msg_type, BcastAndP2p | BcastOnly) {
                    if self.bcasts_in.is_none(bytes_meta.from)? {
                        self.bcasts_in.set(bytes_meta.from, bytes_meta.payload)?;
                    } else {
                        warn!(
                            "peer {} (party {}) says: duplicate bcast message from peer {} (party {}) in round {}",
                            share_id, party_id, bytes_meta.from, from, self.info.round(),
                        );
                        self.msg_in_faulters.set(from, Fault::CorruptedMessage)?;
                    }
                } else {
                    warn!(
                        "peer {} (party {}) says: peer {} (party {}) declared {:?} in round {} but sent Bcast",
                        share_id, party_id, bytes_meta.from, from, expected_msg_type, self.info.round(),
                    );
                    self.msg_in_faulters.set(from, Fault::CorruptedMessage)?;
                }
            }
            P2p { to } => {
                if matches!(expected_msg_type, BcastAndP2p | P2pOnly) {
                    if self.p2ps_in.is_none(bytes_meta.from, to)? {
                        self.p2ps_in.set(bytes_meta.from, to, bytes_meta.payload)?;
                    } else {
                        warn!(
                            "peer {} (party {}) says: duplicate p2p to {} message from peer {} (party {}) in round {}",
                            share_id, party_id, to, bytes_meta.from, from, self.info.round(),
                        );
                        self.msg_in_faulters.set(from, Fault::CorruptedMessage)?;
                    }
                } else {
                    warn!(
                        "peer {} (party {}) says: peer {} (party {}) declared {:?} in round {} but sent P2p",
                        share_id, party_id, bytes_meta.from, from, expected_msg_type, self.info.round(),
                    );
                    self.msg_in_faulters.set(from, Fault::CorruptedMessage)?;
                }
            }
        }

        Ok(())
    }

    pub fn expecting_more_msgs_this_round(&self) -> TofnResult<bool> {
        debug_assert_eq!(self.expected_msg_types.size(), self.bcasts_in.size());
        debug_assert_eq!(self.expected_msg_types.size(), self.p2ps_in.size());

        for (_from, expected_msg_type_option, bcast_option, p2ps) in
            zip3(&self.expected_msg_types, &self.bcasts_in, &self.p2ps_in)
        {
            if let Some(expected_msg_type) = expected_msg_type_option {
                if (matches!(expected_msg_type, BcastAndP2p | BcastOnly) && bcast_option.is_none())
                    || (matches!(expected_msg_type, BcastAndP2p | P2pOnly) && !p2ps.is_full())
                {
                    return Ok(true);
                }
            } else {
                return Ok(true); // this party has not yet sent any messages
            }
        }

        Ok(false)
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

        self.round
            .execute_raw(
                self.info.share_info(),
                self.bcasts_in,
                self.p2ps_in,
                self.expected_msg_types,
            )?
            .build(self.info)
    }

    pub fn info(&self) -> &ProtocolInfoDeluxe<K, P> {
        &self.info
    }

    // private methods
    pub(super) fn new(
        round: Box<dyn ExecuterRaw<FinalOutput = F, Index = K>>,
        info: ProtocolInfoDeluxe<K, P>,
        bcast_out: Option<BytesVec>,
        p2ps_out: Option<HoleVecMap<K, BytesVec>>,
    ) -> TofnResult<Self> {
        let total_share_count = info.share_info().share_count();
        let my_share_id = info.share_info().share_id();

        // validate args
        if let Some(ref p2ps) = p2ps_out {
            if p2ps.len() != total_share_count {
                error!(
                    "peer {} (party {}) says: p2ps_out length {} differs from total share count {}",
                    my_share_id,
                    info.party_id(),
                    p2ps.len(),
                    total_share_count,
                );
                return Err(TofnFatal);
            }
        }

        // bundle metadata into outgoing messages
        let expected_msg_types = match (&bcast_out, &p2ps_out) {
            (None, None) => {
                error!(
                    "peer {} (party {}) says: rounds must send at least one outgoing message",
                    my_share_id,
                    info.party_id(),
                );
                return Err(TofnFatal);
            }
            (None, Some(_)) => P2pOnly,
            (Some(_), None) => BcastOnly,
            (Some(_), Some(_)) => BcastAndP2p,
        };
        // can't use Option::map because closure returns Result and uses ? operator
        let bcast_out = if let Some(payload) = bcast_out {
            Some(wire_bytes::encode_message(
                payload,
                my_share_id,
                Bcast,
                expected_msg_types,
            )?)
        } else {
            None
        };
        let p2ps_out = if let Some(p2ps) = p2ps_out {
            Some(p2ps.map2_result(|(to, payload)| {
                wire_bytes::encode_message(payload, my_share_id, P2p { to }, expected_msg_types)
            })?)
        } else {
            None
        };

        let party_count = info.party_share_counts().party_count();
        Ok(Self {
            info,
            round,
            bcast_out,
            p2ps_out,
            bcasts_in: FillVecMap::with_size(total_share_count),
            p2ps_in: FillP2ps::with_size(total_share_count)?,
            expected_msg_types: FillVecMap::with_size(total_share_count),
            msg_in_faulters: FillVecMap::with_size(party_count),
        })
    }

    #[cfg(test)]
    pub fn round_as_any(&self) -> &dyn std::any::Any {
        self.round.as_any()
    }
}

#[cfg(feature = "malicious")]
pub mod malicious {
    use tracing::{error, info};

    use crate::sdk::{
        api::TofnFatal,
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
            match msg_type {
                Bcast => {
                    if let Some(ref mut bcast) = self.bcast_out {
                        *bcast = corrupt_payload::<K>(&bcast)?
                    } else {
                        error!("no outgoing bcast from this party during this round; can't corrupt msg bytes",);
                        return Err(TofnFatal);
                    }
                }
                P2p { to } => {
                    if let Some(ref mut p2ps) = self.p2ps_out {
                        let p2p = p2ps.get_mut(to)?;
                        *p2p = corrupt_payload::<K>(p2p)?
                    } else {
                        error!("no outgoing p2ps from this party during this round; can't corrupt msg bytes",);
                        return Err(TofnFatal);
                    }
                }
            }
            Ok(())
        }
    }
}
