use serde::de::DeserializeOwned;

use crate::{
    refactor::{
        api::{BytesVec, Fault},
        implementer_api::ProtocolBuilder,
    },
    vecmap::{Behave, FillP2ps, FillVecMap, Index, P2ps, VecMap},
};

pub trait RoundExecuter: Send + Sync {
    type FinalOutput;
    type Index: Behave;
    type Bcast: DeserializeOwned;
    type P2p: DeserializeOwned;
    fn execute(
        self: Box<Self>,
        party_count: usize,
        index: Index<Self::Index>,
        bcasts_in: VecMap<Self::Index, Self::Bcast>, // TODO Option
        p2ps_in: P2ps<Self::Index, Self::P2p>, //VecMap<Self::Index, HoleVecMap<Self::Index, Self::P2p>>, // TODO Option
    ) -> ProtocolBuilder<Self::FinalOutput, Self::Index>;

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        unimplemented!("(Executer) return `self` to enable runtime reflection: https://bennetthardwick.com/dont-use-boxed-trait-objects-for-struct-internals")
    }
}

/// "raw" means we haven't yet checked for timeouts or deserialization failure
pub trait RoundExecuterRaw: Send + Sync {
    type FinalOutput;
    type Index: Behave;
    fn execute_raw(
        self: Box<Self>,
        party_count: usize,
        index: Index<Self::Index>,
        bcasts_in: FillVecMap<Self::Index, BytesVec>, // TODO Option
        p2ps_in: FillP2ps<Self::Index, BytesVec>,     // TODO Option
    ) -> ProtocolBuilder<Self::FinalOutput, Self::Index>;

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        unimplemented!("(ExecuterRaw) return `self` to enable runtime reflection: https://bennetthardwick.com/dont-use-boxed-trait-objects-for-struct-internals")
    }
}

impl<T: RoundExecuter> RoundExecuterRaw for T {
    type FinalOutput = T::FinalOutput;
    type Index = T::Index;

    fn execute_raw(
        self: Box<Self>,
        party_count: usize,
        index: Index<Self::Index>,
        bcasts_in: FillVecMap<Self::Index, BytesVec>,
        p2ps_in: FillP2ps<Self::Index, BytesVec>,
    ) -> ProtocolBuilder<Self::FinalOutput, Self::Index> {
        let mut faulters = FillVecMap::with_size(party_count);

        // check for timeout faults
        for (from, bcast) in bcasts_in.iter() {
            if bcast.is_none() {
                warn!("party {} detect missing bcast from {}", index, from);
                faulters.set(from, Fault::MissingMessage);
            }
        }
        for (from, to, p2p) in p2ps_in.iter() {
            if p2p.is_none() {
                warn!("party {} detect missing p2p from {} to {}", index, from, to);
                faulters.set(from, Fault::MissingMessage);
            }
        }
        if !faulters.is_empty() {
            return ProtocolBuilder::Done(Err(faulters));
        }

        // attempt to deserialize bcasts, p2ps
        let bcasts_deserialized: VecMap<_, Result<_, _>> =
            bcasts_in.unwrap_all_map(|bytes| bincode::deserialize(&bytes));
        let p2ps_deserialized: P2ps<_, Result<_, _>> =
            p2ps_in.unwrap_all_map(|bytes| bincode::deserialize(&bytes));

        // check for deserialization faults
        for (from, bcast) in bcasts_deserialized.iter() {
            if bcast.is_err() {
                warn!("party {} detect corrupted bcast from {}", index, from);
                faulters.set(from, Fault::CorruptedMessage);
            }
        }
        for (from, to, p2p) in p2ps_deserialized.iter() {
            if p2p.is_err() {
                warn!(
                    "party {} detect corrupted p2p from {} to {}",
                    index, from, to
                );
                faulters.set(from, Fault::CorruptedMessage);
            }
        }
        if !faulters.is_empty() {
            return ProtocolBuilder::Done(Err(faulters));
        }

        // unwrap deserialized bcasts, p2ps
        let bcasts_in = bcasts_deserialized.map(Result::unwrap);
        let p2ps_in = p2ps_deserialized.map(Result::unwrap);

        self.execute(party_count, index, bcasts_in, p2ps_in)
    }

    #[cfg(test)]
    #[inline]
    fn as_any(&self) -> &dyn std::any::Any {
        self.as_any()
    }
}

use tracing::{error, info, warn};

pub(crate) fn serialize<T: ?Sized>(value: &T) -> BytesVec
where
    T: serde::Serialize,
{
    let result = bincode::serialize(value).map_err(|err| err.to_string());
    if let Err(ref err_msg) = result {
        error!("serialization failure: {}", err_msg);
    }
    result.unwrap()
}

pub(crate) fn log_fault_info<K>(me: Index<K>, faulter: Index<K>, fault: &str)
where
    K: Behave,
{
    info!("party {} detect [{}] by {}", me, fault, faulter,);
}

pub(crate) fn log_fault_warn<K>(me: Index<K>, faulter: Index<K>, fault: &str)
where
    K: Behave,
{
    warn!("party {} detect [{}] by {}", me, fault, faulter,);
}

pub(crate) fn log_accuse_warn<K>(me: Index<K>, faulter: Index<K>, fault: &str)
where
    K: Behave,
{
    warn!("party {} accuse {} of [{}]", me, faulter, fault);
}
