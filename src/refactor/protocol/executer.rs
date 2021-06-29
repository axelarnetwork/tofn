use serde::de::DeserializeOwned;

use crate::{
    fillvec::FillVec,
    refactor::BytesVec,
    vecmap::{fillvecmap::FillVecMap, VecMap},
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
    pub round: Box<dyn RoundExecuter<FinalOutput = F, Index = K>>,
    pub bcast_out: Option<Vec<u8>>,
    pub p2ps_out: Option<FillVec<Vec<u8>>>, // TODO FillVec with hole?
}

pub trait RoundExecuterTyped: Send + Sync {
    type FinalOutputTyped: DeTimeout;
    type Index;
    type Bcast: DeserializeOwned;
    type P2p: DeserializeOwned;
    fn execute_typed(
        self: Box<Self>,
        party_count: usize,
        index: usize,
        bcasts_in: VecMap<Self::Index, Self::Bcast>,
        p2ps_in: Vec<FillVec<Self::P2p>>,
    ) -> ProtocolBuilder<Self::FinalOutputTyped, Self::Index>;

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        unimplemented!("(RoundExecuterTyped) return `self` to enable runtime reflection: https://bennetthardwick.com/dont-use-boxed-trait-objects-for-struct-internals")
    }
}

pub trait RoundExecuter: Send + Sync {
    type FinalOutput;
    type Index;
    fn execute(
        self: Box<Self>,
        party_count: usize,
        index: usize,
        bcasts_in: FillVecMap<Self::Index, BytesVec>, // TODO Option
        p2ps_in: Vec<FillVec<Vec<u8>>>,               // TODO Option
    ) -> ProtocolBuilder<Self::FinalOutput, Self::Index>;

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        unimplemented!("(RoundExecuter) return `self` to enable runtime reflection: https://bennetthardwick.com/dont-use-boxed-trait-objects-for-struct-internals")
    }
}

impl<T: RoundExecuterTyped> RoundExecuter for T {
    type FinalOutput = T::FinalOutputTyped;
    type Index = T::Index;

    fn execute(
        self: Box<Self>,
        party_count: usize,
        index: usize,
        bcasts_in: FillVecMap<Self::Index, BytesVec>,
        p2ps_in: Vec<FillVec<Vec<u8>>>,
    ) -> ProtocolBuilder<Self::FinalOutput, Self::Index> {
        // TODO this is only a PoC for timeout, deserialization errors
        // DeTimeout needs a fuller API to return detailed fault info

        // check for timeouts
        let bcast_timeout = !bcasts_in.is_full();
        let p2p_timeout = p2ps_in.iter().enumerate().any(|(i, party)| {
            party
                .vec_ref()
                .iter()
                .enumerate()
                .any(|(j, b)| j != i && b.is_none())
        });
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
        // TODO this sucks with FillVec
        let mut p2ps_in_deserialized: Vec<FillVec<T::P2p>> = Vec::with_capacity(p2ps_in.len());
        for (i, party_p2ps) in p2ps_in.iter().enumerate() {
            let mut party_p2ps_deserialized: Vec<Option<T::P2p>> =
                Vec::with_capacity(party_p2ps.len());
            for (j, bytes) in party_p2ps.vec_ref().iter().enumerate() {
                if j == i {
                    party_p2ps_deserialized.push(None);
                } else {
                    let res = bincode::deserialize(&bytes.as_ref().unwrap());
                    match res {
                        Ok(p2p) => party_p2ps_deserialized.push(Some(p2p)),
                        Err(_) => {
                            return ProtocolBuilder::Done(
                                Self::FinalOutput::new_deserialization_failure(),
                            )
                        }
                    }
                }
            }
            assert_eq!(party_p2ps_deserialized.len(), party_p2ps.len());
            p2ps_in_deserialized.push(FillVec::from_vec(party_p2ps_deserialized));
        }
        assert_eq!(p2ps_in_deserialized.len(), p2ps_in.len());

        self.execute_typed(party_count, index, bcasts_in, p2ps_in_deserialized)
    }

    #[cfg(test)]
    #[inline]
    fn as_any(&self) -> &dyn std::any::Any {
        self.as_any()
    }
}

use tracing::error;

pub(crate) fn serialize_as_option<T: ?Sized>(value: &T) -> Option<Vec<u8>>
where
    T: serde::Serialize,
{
    let bytes = bincode::serialize(value).ok();
    if bytes.is_none() {
        error!("serialization failure");
    }
    bytes
}
