use super::super::wire_bytes::{self, MsgType::*, WireBytes};
use super::*;
use crate::refactor::protocol::api::{Fault, Protocol};
use tracing::warn;

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
        // unwrap metadata
        let bytes_meta: WireBytes<K> = match wire_bytes::unwrap(bytes) {
            Some(w) => w,
            None => {
                warn!("msg_in fault from party {}: fail deserialization", from);
                self.msg_in_faulters.set(from, Fault::CorruptedMessage)?; // fatal error if `from` is out of bounds
                return Ok(());
            }
        };

        // verify share_id belongs to this party
        match self.info.share_to_party_id_nonfatal(bytes_meta.from) {
            Some(party_id) if party_id == from => (), // happy path
            _ => {
                warn!(
                    "msg_in fault: share_id {} does not belong to party {}",
                    bytes_meta.from, from
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
                            "msg_in fault from share_id {}: duplicate message",
                            bytes_meta.from
                        );
                        self.msg_in_faulters.set(from, Fault::CorruptedMessage)?;
                    }
                }
                P2p { to } => {
                    if r.p2ps_in.is_none(bytes_meta.from, to)? {
                        r.p2ps_in.set(bytes_meta.from, to, bytes_meta.payload)?;
                    } else {
                        warn!(
                            "msg_in fault from share_id {}: duplicate message",
                            bytes_meta.from
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
                            "msg_in fault from share_id {}: duplicate message",
                            bytes_meta.from
                        );
                        self.msg_in_faulters.set(from, Fault::CorruptedMessage)?;
                    }
                }
                P2p { to } => {
                    warn!(
                        "msg_in fault from share_id {}: no p2ps expected this round, received p2p to {}",
                        bytes_meta.from, to
                    );
                    self.msg_in_faulters.set(from, Fault::CorruptedMessage)?;
                }
            },
            RoundType::P2pOnly(r) => match bytes_meta.msg_type {
                Bcast => {
                    warn!(
                        "msg_in fault from share_id {}: no bcasts expected this round, received bcast",
                        bytes_meta.from
                    );
                    self.msg_in_faulters.set(from, Fault::CorruptedMessage)?;
                }
                P2p { to } => {
                    if r.p2ps_in.is_none(bytes_meta.from, to)? {
                        r.p2ps_in.set(bytes_meta.from, to, bytes_meta.payload)?;
                    } else {
                        warn!(
                            "msg_in fault from share_id {}: duplicate message",
                            bytes_meta.from
                        );
                        self.msg_in_faulters.set(from, Fault::CorruptedMessage)?;
                    }
                }
            },
            RoundType::NoMessages(_) => {
                warn!(
                    "msg_in fault from share_id {}: no messages expected this round, received bcast",
                    bytes_meta.from
                );
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
    pub fn execute_next_round(self) -> TofnResult<Protocol<F, K, P>> {
        if !self.msg_in_faulters.is_empty() {
            warn!("msg_in faulters detected: end protocol");
            return Ok(Protocol::Done(Err(self.msg_in_faulters)));
        }

        match self.round_type {
            RoundType::BcastAndP2p(r) => r
                .round
                .execute_raw(&self.info.core, r.bcasts_in, r.p2ps_in)?
                .build(self.info),
            RoundType::BcastOnly(r) => r
                .round
                .execute_raw(&self.info.core, r.bcasts_in)?
                .build(self.info),
            RoundType::P2pOnly(r) => r
                .round
                .execute_raw(&self.info.core, r.p2ps_in)?
                .build(self.info),
            RoundType::NoMessages(r) => r.round.execute(&self.info.core)?.build(self.info),
        }
    }
    pub fn party_count(&self) -> usize {
        self.info.core.party_count()
    }
    pub fn index(&self) -> TypedUsize<K> {
        self.info.core.index()
    }
    pub fn share_to_party_id(&self, share_id: TypedUsize<K>) -> TofnResult<TypedUsize<P>> {
        self.info.share_to_party_id(share_id)
    }
    pub fn share_to_party_id_nonfatal(&self, share_id: TypedUsize<K>) -> Option<TypedUsize<P>> {
        self.info.share_to_party_id_nonfatal(share_id)
    }
}

#[cfg(feature = "malicious")]
pub mod malicious {
    use tracing::{error, info};

    use crate::refactor::protocol::{
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
            info!("malicious party {} corrupt msg", self.index());
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
