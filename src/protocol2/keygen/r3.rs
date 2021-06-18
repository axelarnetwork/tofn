use crate::{
    fillvec::FillVec,
    protocol2::{RoundExecuter, RoundOutput},
};

use super::{r1, r2, KeygenOutput};

pub(super) struct R3 {
    pub(super) share_count: usize,
    pub(super) threshold: usize,
    pub(super) index: usize,
    pub(super) r1state: r1::State,
    pub(super) r1bcast: r1::Bcast,
    pub(super) r2state: r2::State,
    pub(super) r2bcast: r2::Bcast,
}

impl RoundExecuter for R3 {
    type FinalOutput = KeygenOutput;

    fn execute(self: Box<Self>, all_in_msgs: FillVec<Vec<u8>>) -> RoundOutput<Self::FinalOutput> {
        todo!()
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
