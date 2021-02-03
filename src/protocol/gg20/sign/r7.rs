use super::{Sign, Status};
use curv::{
    elliptic::curves::traits::{ECPoint, ECScalar},
    FE, GE,
};
use serde::{Deserialize, Serialize};

// round 7

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bcast {}
#[derive(Debug)] // do not derive Clone, Serialize, Deserialize
pub(super) struct State {}

impl Sign {
    pub(super) fn r7(&self) -> (State, Bcast) {
        assert!(matches!(self.status, Status::R6));
        let r6state = self.r6state.as_ref().unwrap();

        // verify that sum of S_i (aka ecdsa_public_key_check) equals ecdsa_public_key as per phase 6 of 2020/540
        let mut ecdsa_public_key = r6state.my_ecdsa_public_key_check;
        for (i, in_r6bcast) in self.in_r6bcasts.vec_ref().iter().enumerate() {
            if i == self.my_participant_index {
                continue;
            }
            let in_r6bcast = in_r6bcast.as_ref().unwrap();
            ecdsa_public_key = ecdsa_public_key + in_r6bcast.ecdsa_public_key_check;
        }
        assert_eq!(
            ecdsa_public_key.get_element(),
            self.my_secret_key_share.ecdsa_public_key
        ); // TODO panic

        (State {}, Bcast {})
    }
}
