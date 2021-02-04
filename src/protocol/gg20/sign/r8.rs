use super::{Sign, Status};
use curv::{
    elliptic::curves::traits::{ECPoint, ECScalar},
    FE, GE,
};
use serde::{Deserialize, Serialize};

// round 8

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bcast {}
#[derive(Debug)] // do not derive Clone, Serialize, Deserialize
pub(super) struct State {}

impl Sign {
    pub(super) fn r8(&self) -> (State, Bcast) {
        assert!(matches!(self.status, Status::R7));
        let r7state = self.r7state.as_ref().unwrap();
        todo!();
    }
}
