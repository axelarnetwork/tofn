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

pub struct SerializedMsgs {
    bcast: Option<Vec<u8>>,
    p2ps: Option<FillVec<Vec<u8>>>, // TODO HoleVec instead of FillVec?
}

pub struct RoundWaiter<F> {
    round: Box<dyn RoundExecuter<FinalOutput = F>>,
    msgs_out: SerializedMsgs,
    bcasts_in: FillVec<Vec<u8>>,
    p2ps_in: Vec<FillVec<Vec<u8>>>,
}

impl<F> RoundWaiter<F> {
    pub fn msgs_out(&self) -> &SerializedMsgs {
        &self.msgs_out
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
