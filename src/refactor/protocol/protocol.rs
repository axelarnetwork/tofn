use std::vec;

use tracing::{error, warn};

use crate::fillvec::FillVec;
use serde::de::DeserializeOwned;

pub enum Protocol<F> {
    NotDone(ProtocolRound<F>),
    Done(F),
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
        unimplemented!("return `self` to enable runtime reflection: https://bennetthardwick.com/dont-use-boxed-trait-objects-for-struct-internals")
    }
}

pub trait RoundExecuterTyped: Send + Sync {
    type FinalOutput;
    type Bcast: DeserializeOwned;
    type P2p: DeserializeOwned;
    fn execute_typed(
        self: Box<Self>,
        party_count: usize,
        index: usize,
        bcasts_in: Vec<Self::Bcast>,
        p2ps_in: Vec<FillVec<Self::P2p>>, // TODO use HoleVec instead
    ) -> Protocol<Self::FinalOutput>;
}

impl<T: RoundExecuterTyped> RoundExecuter for T {
    type FinalOutput = T::FinalOutput;

    fn execute(
        self: Box<Self>,
        party_count: usize,
        index: usize,
        bcasts_in: FillVec<Vec<u8>>,
        p2ps_in: Vec<FillVec<Vec<u8>>>,
    ) -> Protocol<Self::FinalOutput> {
        // TODO handle None and deserialization failure
        let bcasts_in: Vec<T::Bcast> = bcasts_in
            .into_vec()
            .into_iter()
            .map(|bytes| bincode::deserialize(&bytes.as_ref().unwrap()).unwrap())
            .collect();
        let p2ps_in: Vec<FillVec<T::P2p>> = p2ps_in
            .into_iter()
            .map(|party_p2ps| {
                FillVec::from_vec(
                    party_p2ps
                        .into_vec()
                        .into_iter()
                        .map(|bytes| bytes.map(|bytes| bincode::deserialize(&bytes).unwrap()))
                        .collect(),
                )
            })
            .collect();
        self.execute_typed(party_count, index, bcasts_in, p2ps_in)
    }
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
