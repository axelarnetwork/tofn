use tracing::error;

use crate::fillvec::FillVec;
// use serde::{de::DeserializeOwned, Serialize};

pub enum RoundOutput<F> {
    NotDone(RoundWaiter<F>),
    Done(F),
}

pub trait RoundExecuter {
    type FinalOutput;
    fn execute(self: Box<Self>, all_in_msgs: FillVec<Vec<u8>>) -> RoundOutput<Self::FinalOutput>;

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        unimplemented!("return `self` to enable runtime reflection: https://bennetthardwick.com/dont-use-boxed-trait-objects-for-struct-internals")
    }
}

pub struct RoundWaiter<F> {
    round: Box<dyn RoundExecuter<FinalOutput = F>>,
    bcast_out: Option<Vec<u8>>,
    p2ps_out: Option<Vec<Option<Vec<u8>>>>,
    bcasts_in: FillVec<Vec<u8>>,
    p2ps_in: Vec<FillVec<Vec<u8>>>,
}

impl<F> RoundWaiter<F> {
    // TODO ugly API: bcast_out, p2ps_out
    pub fn bcast_out(&self) -> Option<&[u8]> {
        self.bcast_out.as_ref().map(Vec::as_slice)
    }
    pub fn p2ps_out(&self) -> Option<&[Option<Vec<u8>>]> {
        self.p2ps_out.as_ref().map(Vec::as_slice)
    }
    pub fn bcast_in(&mut self, from: usize, msg: &[u8]) {
        // TODO check `from` in bounds, warn of overwrite
        self.bcasts_in.overwrite(from, msg.to_vec());
    }
    pub fn p2p_in(&mut self, from: usize, to: usize, msg: &[u8]) {
        // TODO check `from`, `to` in bounds, warn of overwrite
        self.p2ps_in[from].overwrite(to, msg.to_vec());
    }
    pub fn expecting_more_msgs_this_round(&self) -> bool {
        !self
            .p2ps_in
            .iter()
            .enumerate()
            .all(|(i, p2ps)| p2ps.is_full_except(i))
            && !self.bcasts_in.is_full()
    }
    pub fn execute_next_round(self) -> RoundOutput<F> {
        self.round.execute(self.bcasts_in)
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

pub mod keygen;
