use serde::de::DeserializeOwned;

use crate::{
    refactor::{BytesVec, TofnResult},
    vecmap::{Behave, FillP2ps, FillVecMap, HoleVecMap, Index, P2ps, VecMap},
};

pub enum ProtocolBuilder<F, K>
where
    K: Behave,
{
    NotDone(ProtocolRoundBuilder<F, K>),
    Done(F),
}

/// FinalOutput should impl DeTimeout
/// allow us to create a new FinalOutput that indicates timeout or deserialization error
pub trait DeTimeout {
    fn new_timeout() -> Self;
    fn new_deserialization_failure() -> Self;
}

pub struct ProtocolRoundBuilder<F, K>
where
    K: Behave,
{
    pub round: Box<dyn RoundExecuterRaw<FinalOutput = F, Index = K>>,
    pub bcast_out: Option<TofnResult<BytesVec>>,
    pub p2ps_out: Option<TofnResult<HoleVecMap<K, BytesVec>>>,
}

pub trait RoundExecuter: Send + Sync {
    type FinalOutput: DeTimeout;
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
        unimplemented!("(RoundExecuter) return `self` to enable runtime reflection: https://bennetthardwick.com/dont-use-boxed-trait-objects-for-struct-internals")
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
        p2ps_in: FillP2ps<Self::Index, BytesVec>,
    ) -> ProtocolBuilder<Self::FinalOutput, Self::Index> {
        // TODO this is only a PoC for timeout, deserialization errors
        // DeTimeout needs a fuller API to return detailed fault info

        // check for timeouts
        if !bcasts_in.is_full() || !p2ps_in.is_full() {
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
        let p2ps_deserialize: P2ps<_, Result<T::P2p, _>> =
            p2ps_in.unwrap_all_map(|bytes| bincode::deserialize(&bytes));
        if !p2ps_deserialize.iter().all(|(_, _, r)| r.is_ok()) {
            return ProtocolBuilder::Done(Self::FinalOutput::new_deserialization_failure());
        }
        let p2ps_in = p2ps_deserialize.map(|r| r.unwrap());

        self.execute(party_count, index, bcasts_in, p2ps_in)
    }

    #[cfg(test)]
    #[inline]
    fn as_any(&self) -> &dyn std::any::Any {
        self.as_any()
    }
}

use tracing::error;

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

/*
fn test_execute_raw<F, K, B, P>(
    // self: Box<Self>,
    party_count: usize,
    index: Index<K>,
    bcasts_in: FillVecMap<K, BytesVec>,
    p2ps_in: VecMap<K, FillHoleVecMap<K, BytesVec>>,
)
//-> ProtocolBuilder<F, K>
where
    K: Behave,
    B: DeserializeOwned,
    P: DeserializeOwned,
{
    let mut faulters = FillVecMap::with_size(party_count);

    // check for timeout faults
    for (from, bcast) in bcasts_in.iter() {
        if bcast.is_none() {
            warn!("party {} detect missing bcast from {}", index, from);
            faulters.set(from, Fault::MissingMessage);
        }
    }
    for (from, p2ps) in p2ps_in.iter() {
        for (to, p2p) in p2ps.iter() {
            if p2p.is_none() {
                warn!("party {} detect missing p2p from {} to {}", index, from, to);
                faulters.set(from, Fault::MissingMessage);
            }
        }
    }
    if !faulters.is_empty() {
        // return ProtocolBuilder::Done(Err(faulters));
        panic!("TODO timeout faults");
    }

    // attempt to deserialize bcasts, p2ps
    let bcasts_deserialized: VecMap<_, Result<_, _>> = bcasts_in
        .into_iter()
        .map(|(_, bytes)| bincode::deserialize(&bytes.as_ref().unwrap()))
        .collect();
    let p2ps_deserialized: VecMap<_, HoleVecMap<K, Result<P, _>>> = p2ps_in
        .into_iter()
        .map(|(from, p2ps)| {
            p2ps.into_iter()
                .map(|(to, bytes)| Pair(to, bincode::deserialize(&bytes.as_ref().unwrap())))
                .collect::<TofnResult<_>>()
                .expect("TODO propagate TofnError")
        })
        .collect();

    // check for deserialization faults
    for (from, bcast) in bcasts_deserialized.iter() {
        if bcast.is_err() {
            warn!("party {} detect corrupted bcast from {}", index, from);
            faulters.set(from, Fault::CorruptedMessage);
        }
    }
    for (from, p2ps) in p2ps_deserialized.iter() {
        for (to, p2p) in p2ps.iter() {
            if p2p.is_err() {
                warn!(
                    "party {} detect corrupted p2p from {} to {}",
                    index, from, to
                );
                faulters.set(from, Fault::CorruptedMessage);
            }
        }
    }
    if !faulters.is_empty() {
        // return ProtocolBuilder::Done(Err(faulters));
        panic!("TODO deserialization faults");
    }

    // unwrap deserialized bcasts, p2ps
    let bcasts_in: VecMap<K, B> = bcasts_deserialized
        .into_iter()
        .map(|(from, bcast)| bcast.unwrap())
        .collect();
    let p2ps_in = P2ps::from_vecmaps(
        p2ps_deserialized
            .into_iter()
            .map(|(from, p2ps)| {
                p2ps.into_iter()
                    .map(|(to, p2p)| Pair(to, p2p.unwrap()))
                    .collect::<TofnResult<HoleVecMap<K, P>>>()
                    .expect("TODO propagate TofnError")
            })
            .collect(),
    );

    // self.execute(party_count, index, bcasts_in, p2ps_in)
}
*/
