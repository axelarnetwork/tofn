use k256::elliptic_curve::Field;
use serde::{Deserialize, Serialize};

use super::{Sign, Status};
use crate::{
    fillvec::FillVec, hash, k256_serde::to_bytes, paillier_k256, protocol::gg20::vss_k256,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct Bcast {
    pub Gamma_i_commit_k256: hash::Output,
    pub k_i_ciphertext_k256: paillier_k256::Ciphertext,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct P2p {
    pub range_proof_k256: paillier_k256::zk::range::Proof,
}
#[derive(Debug)] // do not derive Clone, Serialize, Deserialize
#[allow(non_snake_case)]
pub(super) struct State {
    pub(super) w_i_k256: k256::Scalar,
    pub(super) gamma_i_k256: k256::Scalar,
    pub(super) Gamma_i_k256: k256::ProjectivePoint,
    pub(super) Gamma_i_reveal_k256: hash::Randomness,
    pub(super) k_i_k256: k256::Scalar,
    pub(super) k_i_randomness_k256: paillier_k256::Randomness,
}

impl Sign {
    #[allow(non_snake_case)]
    pub(super) fn r1(&self) -> (State, Bcast, FillVec<P2p>) {
        assert!(matches!(self.status, Status::New));

        let w_i_k256 = self.my_secret_key_share.share.my_x_i_k256.unwrap()
            * &vss_k256::lagrange_coefficient(self.my_participant_index, &self.participant_indices);
        let k_i_k256 = k256::Scalar::random(rand::thread_rng());
        let gamma_i_k256 = k256::Scalar::random(rand::thread_rng());
        let Gamma_i_k256 = k256::ProjectivePoint::generator() * gamma_i_k256;
        let (Gamma_i_commit_k256, Gamma_i_reveal_k256) = hash::commit(to_bytes(&Gamma_i_k256));

        // initiate MtA protocols for
        // 1. k_i (me) * gamma_j (other)
        // 2. k_i (me) * w_j (other)
        // both MtAs use k_i, so my message k_i_ciphertext can be used in both MtA protocols
        // range proof must be custom for each other party
        // but k_i_ciphertext can be broadcast to all parties

        let (k_i_ciphertext_k256, k_i_randomness_k256) =
            self.my_ek_k256().encrypt(&(&k_i_k256).into());

        let mut out_p2ps = FillVec::with_len(self.participant_indices.len());
        for (i, participant_index) in self.participant_indices.iter().enumerate() {
            if *participant_index == self.my_secret_key_share.share.my_index {
                continue;
            }
            let other_zkp_k256 = &self.my_secret_key_share.group.all_shares[*participant_index].zkp;
            let range_proof_k256 = other_zkp_k256.range_proof(
                &paillier_k256::zk::range::Statement {
                    ciphertext: &k_i_ciphertext_k256,
                    ek: self.my_ek_k256(),
                },
                &paillier_k256::zk::range::Witness {
                    msg: &k_i_k256,
                    randomness: &k_i_randomness_k256,
                },
            );
            out_p2ps.insert(i, P2p { range_proof_k256 }).unwrap();
        }

        (
            State {
                w_i_k256,
                gamma_i_k256,
                Gamma_i_k256,
                Gamma_i_reveal_k256,
                k_i_k256,
                k_i_randomness_k256,
            },
            Bcast {
                Gamma_i_commit_k256,
                k_i_ciphertext_k256,
            },
            out_p2ps,
        )
    }
}
