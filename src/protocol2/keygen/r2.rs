use crate::{
    fillvec::FillVec,
    protocol2::{RoundExecuter, RoundOutput},
};

use super::{r1, KeygenOutput};

pub(super) struct R2 {
    pub(super) state: r1::State,
    pub(super) msg: r1::Bcast,
}

impl RoundExecuter for R2 {
    type FinalOutput = KeygenOutput;

    fn execute(self: Box<Self>, all_in_msgs: FillVec<Vec<u8>>) -> RoundOutput<Self::FinalOutput> {
        todo!()
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
