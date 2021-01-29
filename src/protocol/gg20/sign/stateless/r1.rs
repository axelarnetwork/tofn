use super::{R1Bcast, R1State};
use crate::protocol::gg20::{keygen::SecretKeyShare, sign, vss};
use curv::{
    cryptographic_primitives::commitments::{hash_commitment::HashCommitment, traits::Commitment},
    elliptic::curves::traits::{ECPoint, ECScalar},
    FE, GE,
};

pub fn start(key: &SecretKeyShare, participant_indices: &[usize]) -> (R1State, R1Bcast) {
    // TODO check participant_indices for duplicates

    // create
    let lagrangian_coefficient =
        vss::lagrangian_coefficient(key.share_count, key.my_index, participant_indices);
    let my_secret_key_summand = lagrangian_coefficient * key.my_ecdsa_secret_key_share; // w_i
    let my_secret_blind_summand = FE::new_random(); // gamma_i
    let my_public_blind_summand = GE::generator() * my_secret_blind_summand; // g_gamma_i
    let my_ecdsa_nonce_summand = FE::new_random(); // k_i

    // phase1_broadcast
    let (my_commit, my_reveal) =
        HashCommitment::create_commitment(&my_public_blind_summand.bytes_compressed_to_big_int());

    (
        R1State {
            my_secret_key_summand,
            my_ecdsa_nonce_summand,
            my_reveal,
        },
        R1Bcast { my_commit },
    )
}
