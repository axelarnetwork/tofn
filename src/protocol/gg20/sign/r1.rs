use crate::zkp::range;
use serde::{Deserialize, Serialize};

use crate::{fillvec::FillVec, protocol::gg20::vss};
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
pub struct Bcast {
    pub commit: BigInt,
    pub encrypted_ecdsa_nonce_summand: mta::MessageA,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct P2p {
    pub range_proof: range::Proof,
}
#[derive(Debug)] // do not derive Clone, Serialize, Deserialize
pub struct State {
    pub(super) my_secret_key_summand: FE,
    pub(super) my_secret_blind_summand: FE,
    pub(super) my_public_blind_summand: GE,
    pub(super) my_reveal: BigInt,
    pub(super) my_ecdsa_nonce_summand: FE,
    // TODO pair these next two fields in a range::Witness
    // problem: range::Witness has a lifetime parameter---eliminate it
    pub(super) my_encrypted_ecdsa_nonce_summand: BigInt,
    pub(super) my_encrypted_ecdsa_nonce_summand_randomness: BigInt,
}

impl Sign {
    // immutable &self: do not modify existing self state, only add more
    pub(super) fn r1(&self) -> (State, Bcast, FillVec<P2p>) {
        assert!(matches!(self.status, Status::New));
        let my_secret_key_summand // w_i
            = self.my_secret_key_share.my_ecdsa_secret_key_share
            * vss::lagrangian_coefficient( // l_i
                self.my_secret_key_share.share_count,
                self.my_secret_key_share.my_index,
                &self.participant_indices,
            );
        let my_secret_blind_summand = FE::new_random(); // gamma_i
        let my_public_blind_summand = GE::generator() * my_secret_blind_summand; // g_gamma_i
        let my_ecdsa_nonce_summand = FE::new_random(); // k_i
        let (commit, my_reveal) = HashCommitment::create_commitment(
            &my_public_blind_summand.bytes_compressed_to_big_int(),
        );

        // initiate MtA protocols for
        // 1. my_ecdsa_nonce_summand (me) * my_secret_blind_summand (other)
        // 2. my_ecdsa_nonce_summand (me) * my_secret_key_summand (other)
        // both MtAs use my_ecdsa_nonce_summand, so I use the same message for both
        // re-use encrypted_ecdsa_nonce_summand for all other parties
        let my_ek = &self.my_secret_key_share.my_ek;
        let (encrypted_ecdsa_nonce_summand, my_encrypted_ecdsa_nonce_summand_randomness) =
            mta::MessageA::a(&my_ecdsa_nonce_summand, my_ek);
        let my_encrypted_ecdsa_nonce_summand = encrypted_ecdsa_nonce_summand.c.clone();

        // TODO these variable names are getting ridiculous
        let mut out_p2ps = FillVec::with_len(self.participant_indices.len());
        for (i, participant_index) in self.participant_indices.iter().enumerate() {
            if *participant_index == self.my_secret_key_share.my_index {
                continue;
            }
            let other_zkp = &self.my_secret_key_share.all_zkps[*participant_index];
            let range_proof = other_zkp.range_proof(
                &range::Statement {
                    ciphertext: &my_encrypted_ecdsa_nonce_summand,
                    ek: my_ek,
                },
                &range::Witness {
                    msg: &my_ecdsa_nonce_summand,
                    randomness: &my_encrypted_ecdsa_nonce_summand_randomness,
                },
            );
            out_p2ps.insert(i, P2p { range_proof }).unwrap();
        }

        (
            State {
                my_secret_key_summand,
                my_secret_blind_summand,
                my_public_blind_summand,
                my_reveal,
                my_ecdsa_nonce_summand,
                my_encrypted_ecdsa_nonce_summand,
                my_encrypted_ecdsa_nonce_summand_randomness,
            },
            Bcast {
                commit,
                encrypted_ecdsa_nonce_summand,
                // TODO broadcast GE::generator() * self.my_secret_key_share.my_ecdsa_secret_key_share ? https://github.com/ZenGo-X/multi-party-ecdsa/blob/master/examples/gg20_sign_client.rs#L138
            },
            out_p2ps,
        )
    }
}
