use crate::{
    fillvec::FillVec,
    protocol2::{RoundExecuter, RoundOutput},
};

use super::KeygenOutput;

pub(super) struct R3 {
    // pub(super) share_count: usize,
// pub(super) threshold: usize,
// pub(super) index: usize,
// pub(super) dk: paillier_k256::DecryptionKey,
// pub(super) u_i_vss: vss_k256::Vss,
// pub(super) y_i_reveal: hash::Randomness,
// pub(super) msg: r1::Bcast,
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
