use tracing::error;

use crate::fillvec::FillVec;
// use serde::{de::DeserializeOwned, Serialize};

pub enum RoundOutput<F> {
    NotDone(RoundWaiter<F>),
    Done(F),
}

pub trait RoundExecuter {
    type FinalOutput;
    fn execute(self: Box<Self>, msgs_in: Vec<SerializedMsgs>) -> RoundOutput<Self::FinalOutput>;

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        unimplemented!("return `self` to enable runtime reflection: https://bennetthardwick.com/dont-use-boxed-trait-objects-for-struct-internals")
    }
}

#[derive(Clone, Default)]
pub struct SerializedMsgs {
    pub bcast: Option<Vec<u8>>,
    // TODO HoleVec instead of FillVec?
    // TODO why Option<FillVec<_>>?
    pub p2ps: Option<FillVec<Vec<u8>>>,
}

pub struct RoundWaiter<F> {
    pub(crate) round: Box<dyn RoundExecuter<FinalOutput = F>>,
    pub(crate) msgs_out: SerializedMsgs,
    pub(crate) msgs_in: Vec<SerializedMsgs>,
}

impl<F> RoundWaiter<F> {
    pub fn msgs_out(&self) -> &SerializedMsgs {
        &self.msgs_out
    }
    pub fn bcast_in(&mut self, from: usize, msg: &[u8]) {
        // TODO check `from` in bounds, warn of overwrite
        self.msgs_in[from].bcast = Some(msg.to_vec());
    }
    pub fn p2p_in(&mut self, from: usize, to: usize, msg: &[u8]) {
        // TODO check `from`, `to` in bounds, warn of overwrite
        self.msgs_in[from]
            .p2ps
            .as_mut()
            .unwrap()
            .overwrite(to, msg.to_vec());
    }
    pub fn expecting_more_msgs_this_round(&self) -> bool {
        // TODO
        false
        // !self
        //     .msgs_in
        //     .iter()
        //     .enumerate()
        //     .all(|(i, party_msgs_in)| party_msgs_in.p2ps.is_full_except(i))
        //     && !self.msgs_in.bcasts_in.is_full()
    }
    pub fn execute_next_round(self) -> RoundOutput<F> {
        self.round.execute(self.msgs_in)
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
