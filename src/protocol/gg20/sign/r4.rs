use super::{Sign, Status};
use curv::{elliptic::curves::traits::ECScalar, BigInt, FE};
use serde::{Deserialize, Serialize};

// round 4

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bcast {
    reveal: BigInt,
}
#[derive(Debug)] // do not derive Clone, Serialize, Deserialize
pub struct State {
    nonce_x_blind_inv: FE,
}

impl Sign {
    pub(super) fn r4(&self) -> (State, Bcast) {
        assert!(matches!(self.status, Status::R3));
        let r3state = self.r3state.as_ref().unwrap();

        // compute delta = sum over delta_i
        let mut nonce_x_blind = r3state.my_nonce_x_blind_summand;
        for (i, in_r3bcast) in self.in_r3bcasts.vec_ref().iter().enumerate() {
            if i == self.my_participant_index {
                continue;
            }
            nonce_x_blind = nonce_x_blind + in_r3bcast.as_ref().unwrap().nonce_x_blind_summand;
        }
        let nonce_x_blind_inv = nonce_x_blind.invert();

        (
            State { nonce_x_blind_inv },
            Bcast {
                reveal: self.r1state.as_ref().unwrap().my_reveal.clone(),
            },
        )
    }
}
