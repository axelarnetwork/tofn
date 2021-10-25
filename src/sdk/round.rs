use tracing::{debug, error, info, warn};

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
    wire_bytes::{self, MsgType::*, WireBytes},
};

/// MAX_MSG_IN_LEN is the maximum byte length of messages exchanged during sign.
/// The sender of a message larger than this maximum will be accused as a faulter.
pub struct Round<F, K, P, const MAX_MSG_IN_LEN: usize> {
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
impl<F, K, P, const MAX_MSG_IN_LEN: usize> Round<F, K, P, MAX_MSG_IN_LEN> {
    pub fn bcast_out(&self) -> Option<&BytesVec> {
        self.bcast_out.as_ref()
    }

    pub fn p2ps_out(&self) -> Option<&HoleVecMap<K, BytesVec>> {
        self.p2ps_out.as_ref()
    }

    /// we assume message autenticity
    /// thus, it's a fatal error if `from` is out of bounds
    pub fn msg_in(&mut self, from: TypedUsize<P>, bytes: &[u8]) -> TofnResult<()> {
        let share_id = self.info().share_info().my_id();
        let party_id = self.info().party_id();

        // guard against large-message attack
        if bytes.len() > MAX_MSG_IN_LEN {
            warn!(
                "peer {} (party {}) says: msg_in bytes length {} exceeds maximum {} from party {}",
                share_id,
                party_id,
                bytes.len(),
                MAX_MSG_IN_LEN,
                from
            );
            self.msg_in_faulters.set(from, Fault::CorruptedMessage)?;
            return Ok(());
        }

        // deserialize metadata
        let bytes_meta: WireBytes<K> = match wire_bytes::decode_message(bytes) {
            Some(w) => w,
            None => {
                warn!(
                    "peer {} (party {}) says: msg_in fail to deserialize metadata for msg from party {}",
                    share_id, party_id, from
                );
                self.msg_in_faulters.set(from, Fault::CorruptedMessage)?;
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
            // Special case: total_share_count == 1 and expected_msg_types == P2pOnly
            // In this case no outgoing messages are ever sent,
            // so peers won't know what msg types to expect.
            // Solution: send a dummy bcast indicating P2pOnly
            TotalShareCount1P2pOnly => {
                if self.info().share_info().total_share_count() != 1 {
                    warn!(
                        "peer {} (party {}) says: received TotalShareCount1P2pOnly message from peer {} (party {}) in round {} but total_share_count is {}",
                        share_id, party_id, bytes_meta.from, from, self.info.round(), self.info().share_info().total_share_count(),
                    );
                    self.msg_in_faulters.set(from, Fault::CorruptedMessage)?;
                }
                if !matches!(expected_msg_type, P2pOnly) {
                    warn!(
                        "peer {} (party {}) says: received TotalShareCount1P2pOnly message from peer {} (party {}) in round {} but expected_msg_type is total_share_count is {:?}",
                        share_id, party_id, bytes_meta.from, from, self.info.round(), expected_msg_type,
                    );
                    self.msg_in_faulters.set(from, Fault::CorruptedMessage)?;
                }
                info!(
                    "peer {} (party {}) says: special case: received TotalShareCount1P2pOnly message from peer {} (party {}) in round {}",
                    share_id, party_id, bytes_meta.from, from, self.info.round(),
                );
            }
        }

        Ok(())
    }

    pub fn expecting_more_msgs_this_round(&self) -> bool {
        debug_assert_eq!(self.expected_msg_types.size(), self.bcasts_in.size());
        debug_assert_eq!(self.expected_msg_types.size(), self.p2ps_in.size());

        for (_from, expected_msg_type_option, bcast_option, p2ps) in
            zip3(&self.expected_msg_types, &self.bcasts_in, &self.p2ps_in)
        {
            if let Some(expected_msg_type) = expected_msg_type_option {
                if (matches!(expected_msg_type, BcastAndP2p | BcastOnly) && bcast_option.is_none())
                    || (matches!(expected_msg_type, BcastAndP2p | P2pOnly) && !p2ps.is_full())
                {
                    return true;
                }
            } else {
                return true; // this party has not yet sent any messages
            }
        }

        false
    }

    /// Execute the next round.
    pub fn execute_next_round(mut self) -> TofnResult<Protocol<F, K, P, MAX_MSG_IN_LEN>> {
        let my_share_id = self.info().share_info().my_id();
        let my_party_id = self.info().party_id();
        let curr_round_num = self.info.round();
        let mut share_faulters = self.info().share_info().new_fillvecmap();

        self.info.advance_round();

        // for each msg_in faulter party P: for each share S belonging to P: unset all of S's messages and mark S as a faulter
        if !self.msg_in_faulters.is_empty() {
            let faulter_party_ids = self.msg_in_faulters.as_subset();

            let pretty_faulter_party_ids: Vec<TypedUsize<P>> = faulter_party_ids.iter().collect();
            debug!(
                "peer {} (party {}) says: tofn SDK detected msg_in faulter parties {:?} in round {}; deleting all messages received from these parties",
                my_share_id, my_party_id, pretty_faulter_party_ids, curr_round_num,
            );

            let faulter_share_ids = self
                .info
                .party_share_counts()
                .share_id_subset(&faulter_party_ids)?;

            for faulter_share_id in faulter_share_ids {
                self.expected_msg_types.unset(faulter_share_id)?;
                self.bcasts_in.unset(faulter_share_id)?;
                self.p2ps_in.unset_all(faulter_share_id)?;
                share_faulters.set(faulter_share_id, Fault::CorruptedMessage)?;
            }
        }

        self.round
            .execute_raw(
                self.info.share_info(),
                self.bcasts_in,
                self.p2ps_in,
                self.expected_msg_types,
                share_faulters,
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
        let total_share_count = info.share_info().total_share_count();
        let my_share_id = info.share_info().my_id();

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
        let bcast_out = match bcast_out {
            Some(payload) => Some(wire_bytes::encode_message(
                payload,
                my_share_id,
                Bcast,
                expected_msg_types,
            )?),
            None => None,
        };
        let p2ps_out = match p2ps_out {
            Some(p2ps) => Some(p2ps.map2_result(|(to, payload)| {
                wire_bytes::encode_message(payload, my_share_id, P2p { to }, expected_msg_types)
            })?),
            None => None,
        };

        let bcast_out = if total_share_count == 1 && matches!(expected_msg_types, P2pOnly) {
            info!(
                "peer {} (party {}) says: special case: sending dummy bcast_out of type TotalShareCount1P2pOnly",
                my_share_id, info.party_id(),
            );
            debug_assert!(bcast_out.is_none()); // otherwise expected_msg_types would not be P2pOnly
            Some(wire_bytes::encode_message(
                BytesVec::new(), // empty payload
                my_share_id,
                TotalShareCount1P2pOnly,
                P2pOnly,
            )?)
        } else {
            bcast_out
        };

        let party_count = info.party_share_counts().party_count();
        let bcasts_in = info.share_info().new_fillvecmap();
        let expected_msg_types = info.share_info().new_fillvecmap();
        Ok(Self {
            info,
            round,
            bcast_out,
            p2ps_out,
            bcasts_in,
            p2ps_in: FillP2ps::with_size(total_share_count),
            expected_msg_types,
            msg_in_faulters: FillVecMap::with_size(party_count),
        })
    }

    #[cfg(test)]
    pub fn round_as_any(&self) -> &dyn std::any::Any {
        self.round.as_any()
    }

    #[cfg(test)]
    pub fn bcast_out_mut(&mut self) -> &mut Option<BytesVec> {
        &mut self.bcast_out
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

    impl<F, K, P, const MAX_MSG_IN_LEN: usize> Round<F, K, P, MAX_MSG_IN_LEN> {
        pub fn corrupt_msg_payload(&mut self, msg_type: MsgType<K>) -> TofnResult<()> {
            info!(
                "malicious party {} corrupt msg",
                self.info.share_info().my_id()
            );
            match msg_type {
                Bcast => {
                    if let Some(ref mut bcast) = self.bcast_out {
                        *bcast = corrupt_payload::<K>(bcast)?
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
                TotalShareCount1P2pOnly => {
                    error!("can't corrupt messages of type TotalShareCount1P2pOnly");
                    return Err(TofnFatal);
                }
            }
            Ok(())
        }
    }
}
