use serde::de::DeserializeOwned;

use crate::{
    refactor::{BytesVec, TofnResult},
    vecmap::{FillHoleVecMap, FillVecMap, HoleVecMap, Index, Pair, VecMap},
};

pub enum ProtocolBuilder<F, K> {
    NotDone(ProtocolRoundBuilder<F, K>),
    Done(F),
}

/// FinalOutput should impl DeTimeout
/// allow us to create a new FinalOutput that indicates timeout or deserialization error
pub trait DeTimeout {
    fn new_timeout() -> Self;
    fn new_deserialization_failure() -> Self;
}

pub struct ProtocolRoundBuilder<F, K> {
    pub round: Box<dyn RoundExecuterRaw<FinalOutput = F, Index = K>>,
    pub bcast_out: Option<TofnResult<BytesVec>>,
    pub p2ps_out: Option<TofnResult<HoleVecMap<K, BytesVec>>>,
}

pub trait RoundExecuter: Send + Sync {
    type FinalOutput: DeTimeout;
    type Index;
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
        unimplemented!("(RoundExecuterTyped) return `self` to enable runtime reflection: https://bennetthardwick.com/dont-use-boxed-trait-objects-for-struct-internals")
    }
}

/// "raw" means we haven't yet checked for timeouts or deserialization failure
pub trait RoundExecuterRaw: Send + Sync {
    type FinalOutput;
    type Index;
    fn execute_raw(
        self: Box<Self>,
        party_count: usize,
        index: Index<Self::Index>,
        bcasts_in: FillVecMap<Self::Index, BytesVec>, // TODO Option
        p2ps_in: VecMap<Self::Index, FillHoleVecMap<Self::Index, BytesVec>>, // TODO Option
    ) -> ProtocolBuilder<Self::FinalOutput, Self::Index>;

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        unimplemented!("(RoundExecuterRaw) return `self` to enable runtime reflection: https://bennetthardwick.com/dont-use-boxed-trait-objects-for-struct-internals")
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
        p2ps_in: VecMap<Self::Index, FillHoleVecMap<Self::Index, BytesVec>>,
    ) -> ProtocolBuilder<Self::FinalOutput, Self::Index> {
        // TODO this is only a PoC for timeout, deserialization errors
        // DeTimeout needs a fuller API to return detailed fault info

        // check for timeouts
        let bcast_timeout = !bcasts_in.is_full();
        let p2p_timeout = !p2ps_in
            .iter()
            .all(|(_, party_p2ps_in)| party_p2ps_in.is_full());
        if bcast_timeout || p2p_timeout {
            return ProtocolBuilder::Done(Self::FinalOutput::new_timeout());
        }

        // attempt to deserialize bcasts
        let bcasts_deserialize: Result<VecMap<_, _>, _> = bcasts_in
            .into_iter()
            .map(|(_, bytes)| bincode::deserialize(&bytes.as_ref().unwrap()))
            .collect();
        let bcasts_in = match bcasts_deserialize {
            Ok(vec) => vec,
            Err(_) => {
                return ProtocolBuilder::Done(Self::FinalOutput::new_deserialization_failure())
            }
        };

        // attempt to deserialize p2ps
        let p2ps_deserialize: TofnResult<VecMap<_, _>> = p2ps_in
            .into_iter()
            .map(|(_, party_p2ps)| {
                party_p2ps
                    .into_iter()
                    .map(|(i, bytes)| Pair(i, bincode::deserialize(&bytes.as_ref().unwrap())))
                    .collect::<Result<HoleVecMap<_, _>, _>>()
            })
            .collect();
        let p2ps_in = match p2ps_deserialize {
            Ok(vec) => P2ps::from_vecmaps(vec),
            Err(_) => {
                return ProtocolBuilder::Done(Self::FinalOutput::new_deserialization_failure())
            }
        };

        self.execute(party_count, index, bcasts_in, p2ps_in)
    }

    #[cfg(test)]
    #[inline]
    fn as_any(&self) -> &dyn std::any::Any {
        self.as_any()
    }
}

use tracing::error;

use super::P2ps;

pub(crate) fn serialize<T: ?Sized>(value: &T) -> TofnResult<BytesVec>
where
    T: serde::Serialize,
{
    let result = bincode::serialize(value).map_err(|err| err.to_string());
    if let Err(ref err_msg) = result {
        error!("serialization failure: {}", err_msg);
    }
    result
}
