use super::{Sign, Status};
use curv::BigInt;
use serde::{Deserialize, Serialize};

// round 4

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bcast {
    reveal: BigInt,
}
#[derive(Debug)] // do not derive Clone, Serialize, Deserialize
pub struct State {}

impl Sign {
    pub(super) fn r4(&self) -> (State, Bcast) {
        assert!(matches!(self.status, Status::R3));
        (
            State {},
            Bcast {
                reveal: self.r1state.as_ref().unwrap().my_reveal.clone(),
            },
        )
    }
}
