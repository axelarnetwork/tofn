use serde::de::DeserializeOwned;
use tracing::warn;

use crate::{
    collections::{FillP2ps, FillVecMap, P2ps, TypedUsize},
    sdk::{
        api::{BytesVec, Fault, TofnResult},
        protocol_info::ProtocolInfo,
        wire_bytes::deserialize,
    },
};

use super::{
    protocol_builder::ProtocolBuilder,
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
        p2ps_in: P2ps<Self::Index, Self::P2p>,
    ) -> TofnResult<ProtocolBuilder<Self::FinalOutput, Self::Index>>;

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
    ) -> TofnResult<ProtocolBuilder<Self::FinalOutput, Self::Index>>;

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
    ) -> TofnResult<ProtocolBuilder<Self::FinalOutput, Self::Index>> {
        let mut faulters = info.new_fillvecmap();

        // check for missing messages (timeout fault)
        // each party A has told us what to expect from A (bcast and/or p2p)
        debug_assert_eq!(bcasts_in.size(), expected_msg_types.size());
        debug_assert_eq!(p2ps_in.size(), expected_msg_types.size());
        for (from, expected_msg_type) in expected_msg_types.iter() {
            if let Some(expected_msg_type) = expected_msg_type {
                if matches!(expected_msg_type, BcastAndP2p | BcastOnly)
                    && bcasts_in.is_none(from)?
                {
                    warn!(
                        "peer {} says: detected missing bcast from peer {}",
                        info.my_id(),
                        from
                    );
                    faulters.set(from, Fault::MissingMessage)?;
                }

                // if p2ps are expected from party A then _all_ p2ps from A must be present
                if matches!(expected_msg_type, BcastAndP2p | P2pOnly)
                    && !p2ps_in.is_full_from(from)?
                {
                    // TODO log `to` for missing p2p message?
                    warn!(
                        "peer {} says: detected missing p2p from peer {}",
                        info.my_id(),
                        from
                    );
                    faulters.set(from, Fault::MissingMessage)?;
                }
            } else {
                warn!(
                    "peer {} says: expected_msg_type not set for peer {} (this peer did not send any messages)\nTODO: support expected_msg_type P2pOnly and total_share_count == 1",
                    info.my_id(),
                    from
                );
                faulters.set(from, Fault::MissingMessage)?;
            }
        }
        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        let expected_msg_types = expected_msg_types.to_vecmap()?;

        // attempt to deserialize bcasts, p2ps
        let bcasts_deserialized: FillVecMap<_, Option<_>> =
            bcasts_in.map(|bytes| deserialize(&bytes));
        let p2ps_deserialized: FillP2ps<_, Option<_>> = p2ps_in.map(|bytes| deserialize(&bytes));

        // check for deserialization faults
        for (from, bcast) in bcasts_deserialized.iter() {
            if let Some(None) = bcast {
                warn!(
                    "peer {} says: detected corrupted bcast from peer {}",
                    info.my_id(),
                    from
                );
                faulters.set(from, Fault::CorruptedMessage)?;
            }
        }
        for (from, p2ps) in p2ps_deserialized.iter() {
            for (to, p2p) in p2ps.iter() {
                if let Some(None) = p2p {
                    warn!(
                        "peer {} says: detected corrupted p2p from peer {} to peer {}",
                        info.my_id(),
                        from,
                        to
                    );
                    faulters.set(from, Fault::CorruptedMessage)?;
                }
            }
        }
        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        // all deserialization succeeded---unwrap deserialized bcasts, p2ps
        // TODO instead of unwrap() make a map2_result() for FillVecMap, FillP2ps
        let bcasts_in = bcasts_deserialized.map(Option::unwrap);
        let p2ps_in = p2ps_deserialized.map(Option::unwrap).to_p2ps()?;

        // special case: total_share_count == 1: `p2ps_in` is `[None]` by default
        let expected_msg_type = expected_msg_types.get(TypedUsize::from_usize(0))?;
        let p2ps_in = if info.total_share_count() == 1
            && matches!(expected_msg_type, BcastAndP2p | P2pOnly)
        {
            P2ps::new_size_1_some()
        } else {
            p2ps_in
        };

        self.execute(info, bcasts_in, p2ps_in)
    }

    #[cfg(test)]
    #[inline]
    fn as_any(&self) -> &dyn std::any::Any {
        self.as_any()
    }
}
