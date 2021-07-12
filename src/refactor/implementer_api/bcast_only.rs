use serde::de::DeserializeOwned;
use tracing::warn;

use crate::{
    collections::{Behave, FillVecMap, TypedUsize, VecMap},
    refactor::{
        api::{BytesVec, Fault, TofnResult},
        implementer_api::ProtocolBuilder,
    },
};

pub trait Executer: Send + Sync {
    type FinalOutput;
    type Index: Behave;
    type Bcast: DeserializeOwned;
    fn execute(
        self: Box<Self>,
        party_count: usize,
        index: TypedUsize<Self::Index>,
        bcasts_in: VecMap<Self::Index, Self::Bcast>,
    ) -> TofnResult<ProtocolBuilder<Self::FinalOutput, Self::Index>>;

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        unimplemented!("(Executer) return `self` to enable runtime reflection: https://bennetthardwick.com/dont-use-boxed-trait-objects-for-struct-internals")
    }
}

/// "raw" means we haven't yet checked for timeouts or deserialization failure
pub trait ExecuterRaw: Send + Sync {
    type FinalOutput;
    type Index: Behave;
    fn execute_raw(
        self: Box<Self>,
        party_count: usize,
        index: TypedUsize<Self::Index>,
        bcasts_in: FillVecMap<Self::Index, BytesVec>,
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
        party_count: usize,
        index: TypedUsize<Self::Index>,
        bcasts_in: FillVecMap<Self::Index, BytesVec>,
    ) -> TofnResult<ProtocolBuilder<Self::FinalOutput, Self::Index>> {
        let mut faulters = FillVecMap::with_size(party_count);

        // check for timeout faults
        for (from, bcast) in bcasts_in.iter() {
            if bcast.is_none() {
                warn!("party {} detect missing bcast from {}", index, from);
                faulters.set(from, Fault::MissingMessage)?;
            }
        }
        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        // attempt to deserialize bcasts, p2ps
        let bcasts_deserialized: VecMap<_, Result<_, _>> =
            bcasts_in.unwrap_all_map(|bytes| bincode::deserialize(&bytes));

        // check for deserialization faults
        for (from, bcast) in bcasts_deserialized.iter() {
            if bcast.is_err() {
                warn!("party {} detect corrupted bcast from {}", index, from);
                faulters.set(from, Fault::CorruptedMessage)?;
            }
        }
        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        // unwrap deserialized bcasts, p2ps
        let bcasts_in = bcasts_deserialized.map(Result::unwrap);

        self.execute(party_count, index, bcasts_in)
    }

    #[cfg(test)]
    #[inline]
    fn as_any(&self) -> &dyn std::any::Any {
        self.as_any()
    }
}

pub struct BcastOnlyRound<F, K>
where
    K: Behave,
{
    pub round: Box<dyn ExecuterRaw<FinalOutput = F, Index = K>>,
    pub party_count: usize,
    pub index: TypedUsize<K>,
    pub bcast_out: BytesVec,
    pub bcasts_in: FillVecMap<K, BytesVec>,
}
