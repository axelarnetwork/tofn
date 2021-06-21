use tracing::warn;

use crate::{
    hash,
    k256_serde::to_bytes,
    protocol::gg20::{keygen::crimes::Crime, vss_k256},
    protocol2::{RoundExecuter, RoundOutput, SerializedMsgs},
};

use super::{r1, r2, KeygenOutput};

#[allow(non_snake_case)]
pub(super) struct R4 {
    pub(super) share_count: usize,
    pub(super) threshold: usize,
    pub(super) index: usize,
    pub(super) y: k256::ProjectivePoint,
    pub(super) x_i: k256::Scalar,
    pub(super) all_X_i: Vec<k256::ProjectivePoint>,
}

impl RoundExecuter for R4 {
    type FinalOutput = KeygenOutput;

    fn execute(self: Box<Self>, msgs_in: Vec<SerializedMsgs>) -> RoundOutput<Self::FinalOutput> {
        todo!()
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
