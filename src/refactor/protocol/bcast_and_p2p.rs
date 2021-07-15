use serde::de::DeserializeOwned;
use tracing::warn;

use crate::refactor::{
    collections::{Behave, FillP2ps, FillVecMap, P2ps, VecMap},
    protocol::api::Fault,
};

use super::{
    api::{BytesVec, TofnResult},
    implementer_api::{ProtocolBuilder, RoundInfo},
};
pub trait Executer: Send + Sync {
    type FinalOutput;
    type Index: Behave;
    type PartyIndex: Behave;
    type Bcast: DeserializeOwned;
    type P2p: DeserializeOwned;
    fn execute(
        self: Box<Self>,
        info: &RoundInfo<Self::Index, Self::PartyIndex>,
        bcasts_in: VecMap<Self::Index, Self::Bcast>,
        p2ps_in: P2ps<Self::Index, Self::P2p>,
    ) -> TofnResult<ProtocolBuilder<Self::FinalOutput, Self::Index, Self::PartyIndex>>;

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        unimplemented!("(Executer) return `self` to enable runtime reflection: https://bennetthardwick.com/dont-use-boxed-trait-objects-for-struct-internals")
    }
}

/// "raw" means we haven't yet checked for timeouts or deserialization failure
pub trait ExecuterRaw: Send + Sync {
    type FinalOutput;
    type Index: Behave;
    type PartyIndex: Behave;
    fn execute_raw(
        self: Box<Self>,
        info: &RoundInfo<Self::Index, Self::PartyIndex>,
        bcasts_in: FillVecMap<Self::Index, BytesVec>,
        p2ps_in: FillP2ps<Self::Index, BytesVec>,
    ) -> TofnResult<ProtocolBuilder<Self::FinalOutput, Self::Index, Self::PartyIndex>>;

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        unimplemented!("(ExecuterRaw) return `self` to enable runtime reflection: https://bennetthardwick.com/dont-use-boxed-trait-objects-for-struct-internals")
    }
}

impl<T: Executer> ExecuterRaw for T {
    type FinalOutput = T::FinalOutput;
    type Index = T::Index;
    type PartyIndex = T::PartyIndex;

    fn execute_raw(
        self: Box<Self>,
        info: &RoundInfo<Self::Index, Self::PartyIndex>,
        bcasts_in: FillVecMap<Self::Index, BytesVec>,
        p2ps_in: FillP2ps<Self::Index, BytesVec>,
    ) -> TofnResult<ProtocolBuilder<Self::FinalOutput, Self::Index, Self::PartyIndex>> {
        let mut faulters = FillVecMap::with_size(info.party_count());

        // check for timeout faults
        for (from, bcast) in bcasts_in.iter() {
            if bcast.is_none() {
                warn!("party {} detect missing bcast from {}", info.index(), from);
                faulters.set(from, Fault::MissingMessage)?;
            }
        }
        for (from, to, p2p) in p2ps_in.iter() {
            if p2p.is_none() {
                warn!(
                    "party {} detect missing p2p from {} to {}",
                    info.index(),
                    from,
                    to
                );
                faulters.set(from, Fault::MissingMessage)?;
            }
        }
        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        // attempt to deserialize bcasts, p2ps
        let bcasts_deserialized: VecMap<_, Result<_, _>> =
            bcasts_in.unwrap_all_map(|bytes| bincode::deserialize(&bytes))?;
        let p2ps_deserialized: P2ps<_, Result<_, _>> =
            p2ps_in.unwrap_all_map(|bytes| bincode::deserialize(&bytes))?;

        // check for deserialization faults
        for (from, bcast) in bcasts_deserialized.iter() {
            if bcast.is_err() {
                warn!(
                    "party {} detect corrupted bcast from {}",
                    info.index(),
                    from
                );
                faulters.set(from, Fault::CorruptedMessage)?;
            }
        }
        for (from, to, p2p) in p2ps_deserialized.iter() {
            if p2p.is_err() {
                warn!(
                    "party {} detect corrupted p2p from {} to {}",
                    info.index(),
                    from,
                    to
                );
                faulters.set(from, Fault::CorruptedMessage)?;
            }
        }
        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        // unwrap deserialized bcasts, p2ps
        let bcasts_in = bcasts_deserialized.map(Result::unwrap);
        let p2ps_in = p2ps_deserialized.map(Result::unwrap);

        self.execute(info, bcasts_in, p2ps_in)
    }

    #[cfg(test)]
    #[inline]
    fn as_any(&self) -> &dyn std::any::Any {
        self.as_any()
    }
}
