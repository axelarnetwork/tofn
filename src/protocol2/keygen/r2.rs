use crate::{
    fillvec::FillVec,
    protocol2::{RoundExecuter, RoundOutput},
};

use super::{r1, KeygenOutput};

pub(super) struct R2 {
    state: r1::State,
    msg: r1::Bcast,
}

impl R2 {
    pub(super) fn new(state: r1::State, msg: r1::Bcast) -> Self {
        Self { state, msg }
    }
}

impl RoundExecuter for R2 {
    type FinalOutput = KeygenOutput;

    fn execute(self: Box<Self>, all_in_msgs: FillVec<Vec<u8>>) -> RoundOutput<Self::FinalOutput> {
        todo!()
    }
}
