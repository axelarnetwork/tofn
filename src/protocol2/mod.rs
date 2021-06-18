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
    out_msg: Option<Vec<u8>>,
    all_in_msgs: FillVec<Vec<u8>>,
}

impl<F> RoundWaiter<F> {
    pub fn msg_out(&self) -> Option<&[u8]> {
        self.out_msg.as_ref().map(Vec::as_slice)
    }
    pub fn msg_in(&mut self, from: usize, msg: &[u8]) {
        // TODO check `from` in bounds, warn of overwrite
        self.all_in_msgs.overwrite(from, msg.to_vec());
    }
    pub fn expecting_more_msgs_this_round(&self) -> bool {
        !self.all_in_msgs.is_full()
    }
    pub fn execute_next_round(self) -> RoundOutput<F> {
        self.round.execute(self.all_in_msgs)
    }
}

pub mod keygen;
