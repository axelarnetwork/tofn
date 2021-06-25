use std::vec;

use tracing::{error, warn};

use crate::fillvec::FillVec;
use serde::de::DeserializeOwned;

pub type Protocol<F> = GenericProtocol<ProtocolRound<F>, F>;
pub type ProtocolBuilder<F> = GenericProtocol<ProtocolRoundBuilder<F>, F>;

/// Why trait bound `G: HasTypeParameter<TypeParameter = F>`?
/// We want to write `G<F>` as in:
/// ```compile_fail
/// pub enum ProtocolGeneric<G, F> {
///     NotDone(G<F>), // ERROR
///     Done(F),
/// }
/// ```
/// but this is not supported by Rust

pub enum GenericProtocol<G, F>
where
    G: HasTypeParameter<TypeParameter = F>,
{
    NotDone(G),
    Done(F),
}

/// work-around for higher kinded types (HKT):
/// * https://stackoverflow.com/a/41509242
/// * https://github.com/rust-lang/rfcs/blob/master/text/1598-generic_associated_types.md
/// * https://github.com/rust-lang/rust/issues/44265
pub trait HasTypeParameter {
    type TypeParameter;
}

impl<F> HasTypeParameter for ProtocolRound<F> {
    type TypeParameter = F;
}
impl<F> HasTypeParameter for ProtocolRoundBuilder<F> {
    type TypeParameter = F;
}
impl<T: RoundExecuter> HasTypeParameter for T {
    type TypeParameter = T::FinalOutput;
}

pub trait RoundExecuter: Send + Sync {
    type FinalOutput;
    fn execute(
        self: Box<Self>,
        party_count: usize,
        index: usize,
        bcasts_in: FillVec<Vec<u8>>,
        p2ps_in: Vec<FillVec<Vec<u8>>>,
    ) -> Protocol<Self::FinalOutput>;

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        unimplemented!("(RoundExecuter) return `self` to enable runtime reflection: https://bennetthardwick.com/dont-use-boxed-trait-objects-for-struct-internals")
    }
}

/// FinalOutput should impl DeTimeout
/// allow us to create a new FinalOutput that indicates timeout or deserialization error
pub trait DeTimeout {
    fn new_timeout() -> Self;
    fn new_deserialization_failure() -> Self;
}

pub trait RoundExecuterTyped: Send + Sync {
    type FinalOutputTyped: DeTimeout;
    type Bcast: DeserializeOwned;
    type P2p: DeserializeOwned;
    fn execute_typed(
        self: Box<Self>,
        party_count: usize,
        index: usize,
        bcasts_in: Vec<Self::Bcast>,
        p2ps_in: Vec<FillVec<Self::P2p>>, // TODO use HoleVec instead
    ) -> Protocol<Self::FinalOutputTyped>;

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        unimplemented!("(RoundExecuterTyped) return `self` to enable runtime reflection: https://bennetthardwick.com/dont-use-boxed-trait-objects-for-struct-internals")
    }
}

impl<T: RoundExecuterTyped> RoundExecuter for T {
    type FinalOutput = T::FinalOutputTyped;

    fn execute(
        self: Box<Self>,
        party_count: usize,
        index: usize,
        bcasts_in: FillVec<Vec<u8>>,
        p2ps_in: Vec<FillVec<Vec<u8>>>,
    ) -> Protocol<Self::FinalOutput> {
        // TODO this is only a PoC for timeout, deserialization errors
        // DeTimeout needs a fuller API to return detailed fault info

        // check for timeouts
        let bcast_timeout = bcasts_in.vec_ref().iter().any(Option::is_none);
        let p2p_timeout = p2ps_in.iter().enumerate().any(|(i, party)| {
            party
                .vec_ref()
                .iter()
                .enumerate()
                .any(|(j, b)| j != i && b.is_none())
        });
        if bcast_timeout || p2p_timeout {
            return Protocol::Done(Self::FinalOutput::new_timeout());
        }

        // attempt to deserialize bcasts
        let bcasts_deserialize: Result<Vec<_>, _> = bcasts_in
            .into_vec()
            .into_iter()
            .map(|bytes| bincode::deserialize(&bytes.as_ref().unwrap()))
            .collect();
        let bcasts_in = match bcasts_deserialize {
            Ok(vec) => vec,
            Err(_) => return Protocol::Done(Self::FinalOutput::new_deserialization_failure()),
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
                            return Protocol::Done(Self::FinalOutput::new_deserialization_failure())
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
    fn as_any(&self) -> &dyn std::any::Any {
        self.as_any()
    }
}

pub struct ProtocolRoundBuilder<F> {
    pub round: Box<dyn RoundExecuter<FinalOutput = F>>,
    pub bcast_out: Option<Vec<u8>>,
    pub p2ps_out: FillVec<Vec<u8>>, // TODO FillVec with hole?
}

pub struct ProtocolRound<F> {
    round: Box<dyn RoundExecuter<FinalOutput = F>>,
    party_count: usize,
    index: usize,
    bcast_out: Option<Vec<u8>>,
    p2ps_out: FillVec<Vec<u8>>, // TODO FillVec with hole?
    bcasts_in: FillVec<Vec<u8>>,
    p2ps_in: Vec<FillVec<Vec<u8>>>, // TODO FillVec with hole?
}

impl<F> ProtocolRound<F> {
    pub fn new(
        round: Box<dyn RoundExecuter<FinalOutput = F>>,
        party_count: usize,
        index: usize,
        bcast_out: Option<Vec<u8>>,
        p2ps_out: Option<FillVec<Vec<u8>>>,
    ) -> Self {
        // validate args
        // TODO return error instead of panic?
        assert!(index < party_count);
        if let Some(ref p2ps) = p2ps_out {
            assert_eq!(p2ps.len(), party_count);
        }

        let bcasts_in_len = match bcast_out {
            Some(_) => party_count,
            None => 0,
        };
        let p2ps_in_len = match p2ps_out {
            Some(_) => party_count,
            None => 0,
        };
        let p2ps_out_bytes = match p2ps_out {
            Some(p2ps) => p2ps,
            None => FillVec::with_len(0),
        };
        Self {
            round,
            party_count,
            index,
            bcast_out,
            p2ps_out: p2ps_out_bytes,
            bcasts_in: FillVec::with_len(bcasts_in_len),
            p2ps_in: vec![FillVec::with_len(p2ps_in_len); p2ps_in_len],
        }
    }
    pub fn bcast_out(&self) -> Option<&Vec<u8>> {
        self.bcast_out.as_ref()
    }
    pub fn p2ps_out(&self) -> &FillVec<Vec<u8>> {
        &self.p2ps_out
    }
    pub fn bcast_in(&mut self, from: usize, bytes: &[u8]) {
        if !self.expecting_bcasts_in() {
            warn!("`bcast_in` called but no bcasts expected; discarding `bytes`");
            return;
        }
        // TODO range check should occur at a lower level
        if from >= self.bcasts_in.len() {
            warn!(
                "`from` index {} out of range {}, discarding `msg`",
                from,
                self.bcasts_in.len()
            );
            return;
        }
        self.bcasts_in.overwrite_warn(from, bytes.to_vec());
    }
    pub fn p2p_in(&mut self, from: usize, to: usize, bytes: &[u8]) {
        if !self.expecting_p2ps_in() {
            warn!("`p2p_in` called but no p2ps expected; discaring `bytes`");
            return;
        }
        // TODO range check should occur at a lower level
        if from >= self.p2ps_in.len() {
            warn!(
                "`from` index {} out of range {}, discarding `msg`",
                from,
                self.p2ps_in.len()
            );
            return;
        }
        if to >= self.p2ps_in[from].len() {
            warn!(
                "`to` index {} out of range {}, discarding `msg`",
                to,
                self.p2ps_in[from].len()
            );
            return;
        }
        self.p2ps_in[from].overwrite_warn(to, bytes.to_vec());
    }
    pub fn expecting_more_msgs_this_round(&self) -> bool {
        let bcasts_full = self.bcasts_in.is_full();
        let p2ps_full = self
            .p2ps_in
            .iter()
            .enumerate()
            .all(|(i, p)| p.is_full_except(i));
        !bcasts_full && self.expecting_bcasts_in() || !p2ps_full && self.expecting_p2ps_in()
    }
    pub fn execute_next_round(self) -> Protocol<F> {
        self.round
            .execute(self.party_count, self.index, self.bcasts_in, self.p2ps_in)
    }
    pub fn party_count(&self) -> usize {
        self.party_count
    }
    pub fn index(&self) -> usize {
        self.index
    }

    fn expecting_bcasts_in(&self) -> bool {
        self.bcasts_in.len() != 0
    }
    fn expecting_p2ps_in(&self) -> bool {
        !self.p2ps_in.len() != 0
    }

    #[cfg(test)]
    pub fn round(&self) -> &Box<dyn RoundExecuter<FinalOutput = F>> {
        &self.round
    }
}

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
