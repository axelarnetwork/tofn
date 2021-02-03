use super::{Sign, Status};
use curv::{
    elliptic::curves::traits::{ECPoint, ECScalar},
    FE, GE,
};
use serde::{Deserialize, Serialize};

// round 6

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bcast {
    ecdsa_public_key_check: GE,
}
#[derive(Debug)] // do not derive Clone, Serialize, Deserialize
pub(super) struct State {
    my_ecdsa_public_key_check: GE,
}

impl Sign {
    pub(super) fn r6(&self) -> (State, Bcast) {
        assert!(matches!(self.status, Status::R5));
        let r3state = self.r3state.as_ref().unwrap();
        let r5state = self.r5state.as_ref().unwrap();

        // verify that sum of R_i (aka ecdsa_randomizer_x_nonce_summand) equals the generator point as per phase 5 of 2020/540
        let mut ecdsa_randomizer_x_nonce = r5state.my_ecdsa_randomizer_x_nonce_summand;
        for (i, in_r5bcast) in self.in_r5bcasts.vec_ref().iter().enumerate() {
            if i == self.my_participant_index {
                continue;
            }
            let in_r5bcast = in_r5bcast.as_ref().unwrap();
            ecdsa_randomizer_x_nonce =
                ecdsa_randomizer_x_nonce + in_r5bcast.ecdsa_randomizer_x_nonce_summand;
        }
        assert_eq!(ecdsa_randomizer_x_nonce, GE::generator()); // TODO panic

        // TODO verify zk proofs from phase 5 of 2020/540

        // compute S_i (aka ecdsa_public_key_check) as per phase 6 of 2020/540
        let my_ecdsa_public_key_check =
            r5state.ecdsa_randomizer * r3state.my_nonce_x_keyshare_summand;

        // TODO zk proofs as per phase 6 of 2020/540
        (
            State {
                my_ecdsa_public_key_check,
            },
            Bcast {
                ecdsa_public_key_check: my_ecdsa_public_key_check,
            },
        )
    }
}
