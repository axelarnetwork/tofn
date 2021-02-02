use super::{Sign, Status};
use crate::fillvec::FillVec;
use curv::{
    elliptic::curves::traits::{ECPoint, ECScalar},
    FE, GE,
};
use multi_party_ecdsa::utilities::mta;
use serde::{Deserialize, Serialize};

// round 3

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bcast {
    pub nonce_x_blind_summand: FE, // delta_i
    pub T: GE,
}
#[derive(Debug)] // do not derive Clone, Serialize, Deserialize
pub struct State {
    pub(super) my_nonce_x_blind_summand: FE,
}

impl Sign {
    pub(super) fn r3(&self) -> (State, Bcast) {
        assert!(matches!(self.status, Status::R2));

        let my_dk = &self.my_secret_key_share.my_dk;
        let r1state = self.r1state.as_ref().unwrap();

        // complete the MtA protocols:
        // 1. my_ecdsa_nonce_summand * my_secret_blind_summand
        // 2. my_ecdsa_nonce_summand * my_secret_key_summand
        let mut my_mta_blind_summands_lhs = FillVec::with_capacity(self.participant_indices.len());
        let mut my_mta_keyshare_summands_lhs =
            FillVec::with_capacity(self.participant_indices.len());
        for (i, participant_index) in self.participant_indices.iter().enumerate() {
            if *participant_index == self.my_secret_key_share.my_index {
                continue;
            }
            let mta = self.in_r2p2ps.vec_ref()[i].as_ref().unwrap();

            let (my_mta_blind_summand_lhs, _) = mta
                .mta_response_blind
                .verify_proofs_get_alpha(my_dk, &r1state.my_ecdsa_nonce_summand)
                .unwrap(); // TODO panic

            let (my_mta_keyshare_summand_lhs, _) = mta
                .mta_response_keyshare
                .verify_proofs_get_alpha(my_dk, &r1state.my_ecdsa_nonce_summand)
                .unwrap(); // TODO panic

            // TODO zengo does this extra check, but it requires more messages to be sent
            // if input.g_w_i_s[ind] != input.m_b_w_s[i].b_proof.pk {
            //     println!("MtAwc did not work i = {} ind ={}", i, ind);
            //     return Err(Error::InvalidCom);
            // }

            my_mta_blind_summands_lhs
                .insert(i, my_mta_blind_summand_lhs)
                .unwrap();
            my_mta_keyshare_summands_lhs
                .insert(i, my_mta_keyshare_summand_lhs)
                .unwrap();
        }

        // compute delta_i, sigma_i as per phase 2 of 2020/540
        // remember:
        // my_ecdsa_nonce_summand -> k_i
        // my_secret_blind_summand -> gamma_i
        // my_secret_key_summand -> w_i
        // my_nonce_x_blind_summand -> ki_gamma_i -> delta_i
        // my_nonce_x_keyshare_summand -> ki_w_i -> sigma_i
        let r2state = self.r2state.as_ref().unwrap();
        let my_mta_blind_summands_lhs = my_mta_blind_summands_lhs.into_vec();
        let my_mta_keyshare_summands_lhs = my_mta_keyshare_summands_lhs.into_vec();

        let mut my_nonce_x_blind_summand = r1state
            .my_ecdsa_nonce_summand
            .mul(&r1state.my_secret_blind_summand.get_element());
        let mut my_nonce_x_keyshare_summand = r1state
            .my_ecdsa_nonce_summand
            .mul(&r1state.my_secret_key_summand.get_element());

        for i in 0..self.participant_indices.len() {
            if self.participant_indices[i] == self.my_secret_key_share.my_index {
                continue;
            }
            my_nonce_x_blind_summand = my_nonce_x_blind_summand
                + my_mta_blind_summands_lhs[i]
                    .unwrap()
                    .add(&r2state.my_mta_blind_summands_rhs[i].unwrap().get_element());
            my_nonce_x_keyshare_summand = my_nonce_x_keyshare_summand
                + my_mta_keyshare_summands_lhs[i].unwrap().add(
                    &r2state.my_mta_keyshare_summands_rhs[i]
                        .unwrap()
                        .get_element(),
                );
        }

        // compute the point T_i = g*sigma_i + h*l_i and zk proof as per phase 3 of 2020/540
        // rememeber:
        // my_public_nonce_x_keyshare_summand -> g_sigma_i
        let my_public_nonce_x_keyshare_summand = GE::generator() * my_nonce_x_keyshare_summand;
        let l: FE = ECScalar::new_random();
        let h_l = GE::base_point2() * l;
        let T = my_public_nonce_x_keyshare_summand + h_l;

        // TODO compute zk proof and send it

        (
            State {
                my_nonce_x_blind_summand,
            },
            Bcast {
                nonce_x_blind_summand: my_nonce_x_blind_summand,
                T,
            },
        )
    }
}
