use serde::de::DeserializeOwned;
use tracing::warn;

use crate::{
    collections::{FillP2ps, FillVecMap, XP2ps},
    sdk::{
        api::{BytesVec, Fault, TofnResult},
        protocol_info::ProtocolInfo,
    },
};

use super::{
    protocol_builder::XProtocolBuilder,
    wire_bytes::ExpectedMsgTypes::{self, *},
};

pub trait Executer: Send + Sync {
    type FinalOutput;
    type Index;
    type Bcast: DeserializeOwned;
    type P2p: DeserializeOwned;
    fn execute(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        bcasts_in: FillVecMap<Self::Index, Self::Bcast>,
        p2ps_in: XP2ps<Self::Index, Self::P2p>,
    ) -> TofnResult<XProtocolBuilder<Self::FinalOutput, Self::Index>>;

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        unimplemented!("(Executer) return `self` to enable runtime reflection: https://bennetthardwick.com/dont-use-boxed-trait-objects-for-struct-internals")
    }
}

/// "raw" means we haven't yet checked for missing messages or deserialization failure
pub trait ExecuterRaw: Send + Sync {
    type FinalOutput;
    type Index;
    fn execute_raw(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        bcasts_in: FillVecMap<Self::Index, BytesVec>,
        p2ps_in: FillP2ps<Self::Index, BytesVec>,
        expected_msg_types: FillVecMap<Self::Index, ExpectedMsgTypes>,
    ) -> TofnResult<XProtocolBuilder<Self::FinalOutput, Self::Index>>;

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        unimplemented!("(ExecuterRaw) return `self` to enable runtime reflection: https://bennetthardwick.com/dont-use-boxed-trait-objects-for-struct-internals")
    }
}

impl<T: Executer> ExecuterRaw for T {
    type FinalOutput = T::FinalOutput;
    type Index = T::Index;

    fn execute_raw(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        bcasts_in: FillVecMap<Self::Index, BytesVec>,
        p2ps_in: FillP2ps<Self::Index, BytesVec>,
        expected_msg_types: FillVecMap<Self::Index, ExpectedMsgTypes>,
    ) -> TofnResult<XProtocolBuilder<Self::FinalOutput, Self::Index>> {
        let mut faulters = FillVecMap::with_size(info.share_count());

        // check for missing messages (timeout fault)
        // each party A has told us what to expect form A (bcast and/or p2p)
        debug_assert_eq!(bcasts_in.size(), expected_msg_types.size());
        debug_assert_eq!(p2ps_in.size(), expected_msg_types.size());
        for (from, expected_msg_type) in expected_msg_types.iter() {
            if let Some(expected_msg_type) = expected_msg_type {
                if matches!(expected_msg_type, BcastAndP2p | BcastOnly)
                    && bcasts_in.is_none(from)?
                {
                    warn!(
                        "peer {} says: detected missing bcast from peer {}",
                        info.share_id(),
                        from
                    );
                    faulters.set(from, Fault::MissingMessage)?;
                }

                // if p2ps are expected from party A then _all_ p2ps from A must be present
                if matches!(expected_msg_type, BcastAndP2p | P2pOnly) && !p2ps_in.xis_full(from)? {
                    // TODO log `to` for missing p2p message?
                    warn!(
                        "peer {} says: detected missing p2p from peer {}",
                        info.share_id(),
                        from
                    );
                    faulters.set(from, Fault::MissingMessage)?;
                }
            } else {
                warn!(
                    "peer {} says: expected_msg_type not set for peer {} (this peer did not send any messages)",
                    info.share_id(),
                    from
                );
                faulters.set(from, Fault::MissingMessage)?;
            }
        }
        if !faulters.is_empty() {
            return Ok(XProtocolBuilder::Done(Err(faulters)));
        }

        // attempt to deserialize bcasts, p2ps
        let bcasts_deserialized: FillVecMap<_, Result<_, _>> =
            bcasts_in.map(|bytes| bincode::deserialize(&bytes));
        let p2ps_deserialized: FillP2ps<_, Result<_, _>> =
            p2ps_in.map(|bytes| bincode::deserialize(&bytes));

        // check for deserialization faults
        for (from, bcast) in bcasts_deserialized.iter() {
            if let Some(bcast) = bcast {
                if bcast.is_err() {
                    warn!(
                        "peer {} says: detected corrupted bcast from peer {}",
                        info.share_id(),
                        from
                    );
                    faulters.set(from, Fault::CorruptedMessage)?;
                }
            }
        }
        for (from, to, p2p) in p2ps_deserialized.iter() {
            if let Some(p2p) = p2p {
                if p2p.is_err() {
                    warn!(
                        "peer {} says: detected corrupted p2p from peer {} to peer {}",
                        info.share_id(),
                        from,
                        to
                    );
                    faulters.set(from, Fault::CorruptedMessage)?;
                }
            }
        }
        if !faulters.is_empty() {
            return Ok(XProtocolBuilder::Done(Err(faulters)));
        }

        // all deserialization succeeded---unwrap deserialized bcasts, p2ps
        // TODO instead of unwrap() make a map2_result() for FillVecMap, FillP2ps
        let bcasts_in = bcasts_deserialized.map(Result::unwrap);
        let p2ps_in = p2ps_deserialized.map(Result::unwrap);

        self.execute(info, bcasts_in, p2ps_in.to_xp2ps()?)
    }

    #[cfg(test)]
    #[inline]
    fn as_any(&self) -> &dyn std::any::Any {
        self.as_any()
    }
}
