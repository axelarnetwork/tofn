use crate::refactor::protocol::api::Protocol;

use super::super::wire_bytes::{self, MsgType::*, WireBytes};
use super::*;

impl<F, K, P> Round<F, K, P> {
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
    // TODO add from_party arg, do not return TofnResult
    // instead blame all errors on from_party
    pub fn msg_in(&mut self, bytes: &[u8]) -> TofnResult<()> {
        let bytes_meta: WireBytes<K> =
            wire_bytes::unwrap(bytes).expect("TODO deal with deserialization faults here");
        match &mut self.round_type {
            RoundType::BcastAndP2p(r) => match bytes_meta.msg_type {
                Bcast => r.bcasts_in.set_warn(bytes_meta.from, bytes_meta.payload),
                P2p { to } => r.p2ps_in.set_warn(bytes_meta.from, to, bytes_meta.payload),
            },
            RoundType::BcastOnly(r) => match bytes_meta.msg_type {
                Bcast => r.bcasts_in.set_warn(bytes_meta.from, bytes_meta.payload),
                P2p { to } => {
                    error!(
                        "no p2ps expected this round, received p2p from {} to {}",
                        bytes_meta.from, to
                    );
                    Err(TofnFatal)
                }
            },
            RoundType::NoMessages(_) => {
                error!(
                    "no messages expected this round, received msg from {}",
                    bytes_meta.from
                );
                Err(TofnFatal)
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
    pub fn execute_next_round(self) -> TofnResult<Protocol<F, K, P>> {
        match self.round_type {
            RoundType::BcastAndP2p(r) => r
                .round
                .execute_raw(&self.info.core, r.bcasts_in, r.p2ps_in)?
                .build(self.info),
            RoundType::BcastOnly(r) => r
                .round
                .execute_raw(&self.info.core, r.bcasts_in)?
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

    // pub use crate::refactor::protocol::wire_bytes::MsgType;

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
                RoundType::NoMessages(_) => {
                    error!("no messages expected this round, can't corrupt msg bytes",);
                    return Err(TofnFatal);
                }
            }
            Ok(())
        }
    }
}
