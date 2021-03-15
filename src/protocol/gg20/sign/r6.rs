use super::{Sign, Status};
use crate::zkp::range;
use curv::{elliptic::curves::traits::ECPoint, GE};
use serde::{Deserialize, Serialize};

// round 6

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bcast {
    pub ecdsa_public_key_check: GE,
}
#[derive(Debug)] // do not derive Clone, Serialize, Deserialize
pub(super) struct State {
    pub(super) my_ecdsa_public_key_check: GE,
}

impl Sign {
    pub(super) fn r6(&self) -> (State, Bcast) {
        assert!(matches!(self.status, Status::R5));
        let r3state = self.r3state.as_ref().unwrap();
        let r5state = self.r5state.as_ref().unwrap();

        // checks:
        // * sum of ecdsa_randomizer_x_nonce_summand (R_i) = G as per phase 5 of 2020/540
        // * verify zk proofs
        let mut ecdsa_randomizer_x_nonce = r5state.my_ecdsa_randomizer_x_nonce_summand;
        for (i, participant_index) in self.participant_indices.iter().enumerate() {
            if i == self.my_participant_index {
                continue;
            }
            let in_r5bcast = self.in_r5bcasts.vec_ref()[i].as_ref().unwrap();
            ecdsa_randomizer_x_nonce =
                ecdsa_randomizer_x_nonce + in_r5bcast.ecdsa_randomizer_x_nonce_summand;

            let in_r5p2p = self.in_r5p2ps.vec_ref()[i].as_ref().unwrap();
            self.my_secret_key_share
                .my_zkp
                .verify_range_proof_wc(
                    &range::StatementWc {
                        stmt: range::Statement {
                            ciphertext: &self.in_r1bcasts.vec_ref()[i]
                                .as_ref()
                                .unwrap()
                                .encrypted_ecdsa_nonce_summand
                                .c,
                            ek: &self.my_secret_key_share.all_eks[*participant_index],
                        },
                        msg_g: &in_r5bcast.ecdsa_randomizer_x_nonce_summand,
                        g: &r5state.ecdsa_randomizer,
                    },
                    &in_r5p2p.ecdsa_randomizer_x_nonce_summand_proof,
                )
                .unwrap_or_else(|e| {
                    panic!(
                        "party {} says: range proof wc failed to verify for party {} because [{}]",
                        self.my_secret_key_share.my_index, participant_index, e
                    )
                });
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
