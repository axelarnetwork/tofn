use super::{Sign, Status};
use curv::{
    elliptic::curves::traits::{ECPoint, ECScalar},
    FE, GE,
};
use serde::{Deserialize, Serialize};

// round 7

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bcast {
    ecdsa_sig_summand: FE,
}
#[derive(Debug)] // do not derive Clone, Serialize, Deserialize
pub(super) struct State {
    my_ecdsa_sig_summand: FE,
}

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

        // compute our sig share s_i (aka my_ecdsa_sig_summand) as per phase 7 of 2020/540
        let r1state = self.r1state.as_ref().unwrap();
        let r3state = self.r3state.as_ref().unwrap();
        let r5state = self.r5state.as_ref().unwrap();
        let r: FE = ECScalar::from(
            &r5state
                .ecdsa_randomizer
                .x_coor()
                .unwrap()
                .mod_floor(&FE::q()),
        );
        let my_ecdsa_sig_summand = self.msg_to_sign * r1state.my_ecdsa_nonce_summand
            + r * r3state.my_nonce_x_keyshare_summand;

        (
            State {
                my_ecdsa_sig_summand,
            },
            Bcast {
                ecdsa_sig_summand: my_ecdsa_sig_summand,
            },
        )
    }
}
