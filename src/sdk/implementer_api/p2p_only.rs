use serde::de::DeserializeOwned;
use tracing::warn;

use crate::{
    collections::{FillP2ps, FillVecMap, P2ps},
    sdk::{
        api::{BytesVec, Fault, TofnResult},
        implementer_api::ProtocolBuilder,
        protocol_info::ProtocolInfo,
    },
};

pub trait Executer: Send + Sync {
    type FinalOutput;
    type Index;
    type P2p: DeserializeOwned;
    fn execute(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        p2ps_in: P2ps<Self::Index, Self::P2p>,
    ) -> TofnResult<ProtocolBuilder<Self::FinalOutput, Self::Index>>;

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        unimplemented!("(Executer) return `self` to enable runtime reflection: https://bennetthardwick.com/dont-use-boxed-trait-objects-for-struct-internals")
    }
}

/// "raw" means we haven't yet checked for timeouts or deserialization failure
pub trait ExecuterRaw: Send + Sync {
    type FinalOutput;
    type Index;
    fn execute_raw(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        p2ps_in: FillP2ps<Self::Index, BytesVec>,
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
        p2ps_in: FillP2ps<Self::Index, BytesVec>,
    ) -> TofnResult<ProtocolBuilder<Self::FinalOutput, Self::Index>> {
        let mut faulters = FillVecMap::with_size(info.share_count());

        // check for timeout faults
        for (from, to, p2p) in p2ps_in.iter() {
            if p2p.is_none() {
                warn!(
                    "peer {} says: detected missing p2p from peer {} to peer {}",
                    info.share_id(),
                    from,
                    to
                );
                faulters.set(from, Fault::MissingMessage)?;
            }
        }
        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        // attempt to deserialize p2ps
        let p2ps_deserialized: P2ps<_, Result<_, _>> =
            p2ps_in.map_to_p2ps(|bytes| bincode::deserialize(&bytes))?;

        // check for deserialization faults
        for (from, to, p2p) in p2ps_deserialized.iter() {
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
        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        // unwrap deserialized p2ps
        let p2ps_in = p2ps_deserialized.map(Result::unwrap);

        self.execute(info, p2ps_in)
    }

    #[cfg(test)]
    #[inline]
    fn as_any(&self) -> &dyn std::any::Any {
        self.as_any()
    }
}
