use k256::elliptic_curve::Field;
use serde::{Deserialize, Serialize};

use crate::{
    fillvec::FillVec,
    hash,
    k256_serde::to_bytes,
    paillier_k256,
    protocol::gg20::{vss, vss_k256},
    zkp::paillier::range,
};
use curv::{
    // arithmetic::traits::Samplable,
    cryptographic_primitives::commitments::{hash_commitment::HashCommitment, traits::Commitment},
    elliptic::curves::traits::{ECPoint, ECScalar},
    BigInt,
    FE,
    GE,
};
use multi_party_ecdsa::utilities::mta;
// use paillier::{EncryptWithChosenRandomness, Paillier, Randomness, RawPlaintext};

use super::{Sign, Status};

// round 1
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct Bcast {
    // curv
    pub Gamma_i_commit: BigInt,
    pub k_i_ciphertext: mta::MessageA,

    // k256
    pub Gamma_i_commit_k256: hash::Output,
    pub k_i_ciphertext_k256: paillier_k256::Ciphertext,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct P2p {
    pub range_proof: range::Proof,                         // curv
    pub range_proof_k256: paillier_k256::zk::range::Proof, // k256
}
#[derive(Debug)] // do not derive Clone, Serialize, Deserialize
#[allow(non_snake_case)]
pub(super) struct State {
    // curv
    pub(super) w_i: FE,
    pub(super) gamma_i: FE,
    pub(super) Gamma_i: GE,
    pub(super) Gamma_i_reveal: BigInt,
    pub(super) k_i: FE,
    pub(super) encrypted_k_i: BigInt, // redundant
    pub(super) k_i_randomness: BigInt,

    // k256
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

        // curv
        let w_i // w_i
            = self.my_secret_key_share.my_ecdsa_secret_key_share
            * vss::lagrangian_coefficient( // l_i
                self.my_secret_key_share.share_count,
                self.my_secret_key_share.my_index,
                &self.participant_indices,
            );
        let gamma_i = FE::new_random();
        let Gamma_i = GE::generator() * gamma_i;
        let k_i = FE::new_random(); // k_i
        let (commit, Gamma_i_reveal) =
            HashCommitment::create_commitment(&Gamma_i.bytes_compressed_to_big_int());

        // k256
        let w_i_k256 = self.my_secret_key_share.my_x_i_k256.unwrap()
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

        // curv
        let my_ek = &self.my_secret_key_share.my_ek;
        let (encrypted_k_i_zengo, k_i_randomness) = mta::MessageA::a(&k_i, my_ek);
        let encrypted_k_i = encrypted_k_i_zengo.c.clone();

        // k256
        let (k_i_ciphertext_k256, k_i_randomness_k256) =
            self.my_ek_k256().encrypt(&(&k_i_k256).into());

        // TODO these variable names are getting ridiculous
        let mut out_p2ps = FillVec::with_len(self.participant_indices.len());
        for (i, participant_index) in self.participant_indices.iter().enumerate() {
            if *participant_index == self.my_secret_key_share.my_index {
                continue;
            }

            // curv
            let other_zkp = &self.my_secret_key_share.all_zkps[*participant_index];
            let range_proof = other_zkp.range_proof(
                &range::Statement {
                    ciphertext: &encrypted_k_i,
                    ek: my_ek,
                },
                &range::Witness {
                    msg: &k_i,
                    randomness: &k_i_randomness,
                },
            );

            // k256
            let other_zkp_k256 = &self.my_secret_key_share.all_zkps_k256[*participant_index];
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
            out_p2ps
                .insert(
                    i,
                    P2p {
                        range_proof,
                        range_proof_k256,
                    },
                )
                .unwrap();
        }

        (
            State {
                w_i,
                gamma_i,
                Gamma_i,
                Gamma_i_reveal,
                k_i,
                encrypted_k_i,
                k_i_randomness,

                w_i_k256,
                gamma_i_k256,
                Gamma_i_k256,
                Gamma_i_reveal_k256,
                k_i_k256,
                k_i_randomness_k256,
            },
            Bcast {
                Gamma_i_commit: commit,
                k_i_ciphertext: encrypted_k_i_zengo,

                Gamma_i_commit_k256,
                k_i_ciphertext_k256,
            },
            out_p2ps,
        )
    }
}
