use curv::{
    cryptographic_primitives::commitments::{hash_commitment::HashCommitment, traits::Commitment},
    elliptic::curves::traits::{ECPoint, ECScalar},
    FE, GE,
};
use paillier::{KeyGeneration, Paillier};
use zk_paillier::zkproofs::NICorrectKeyProof;

use super::{R1Bcast, R1State};
use crate::protocol::gg20::{keygen::validate_params, zkp::Zkp};

pub fn start(share_count: usize, threshold: usize, my_index: usize) -> (R1State, R1Bcast) {
    // TODO don't panic here
    validate_params(share_count, threshold, my_index).unwrap();
    let my_ecdsa_secret_summand = FE::new_random();
    let my_ecdsa_public_summand = GE::generator() * my_ecdsa_secret_summand;

    // TODO use safe primes in production
    // let (ek, dk) = Paillier::keypair_safe_primes().keys();
    let (my_ek, my_dk) = Paillier::keypair().keys();

    let correct_key_proof = NICorrectKeyProof::proof(&my_dk);
    let zkp = Zkp::new_unsafe();
    let (my_commit, my_reveal) =
        HashCommitment::create_commitment(&my_ecdsa_public_summand.bytes_compressed_to_big_int());
    let my_bcast = R1Bcast {
        commit: my_commit.clone(),
        ek: my_ek.clone(),
        zkp,
        correct_key_proof,
    };
    (
        R1State {
            share_count,
            threshold,
            my_index,
            my_ecdsa_secret_summand,
            my_dk,
            my_ek,
            my_commit,
            my_reveal,
            my_ecdsa_public_summand,
        },
        my_bcast,
    )
}
