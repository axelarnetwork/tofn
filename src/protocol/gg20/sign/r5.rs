use super::{Sign, Status};
use serde::{Deserialize, Serialize};

// round 5

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bcast {}
#[derive(Debug)] // do not derive Clone, Serialize, Deserialize
pub struct State {}

impl Sign {
    pub(super) fn r5(&self) -> (State, Bcast) {
        assert!(matches!(self.status, Status::R4));
        (State {}, Bcast {})
    }
}
