use super::{super::super::zkp::Zkp, R1Bcast, R1State};
use curv::{
    cryptographic_primitives::commitments::{hash_commitment::HashCommitment, traits::Commitment},
    elliptic::curves::traits::{ECPoint, ECScalar},
    FE, GE,
};
use paillier::{KeyGeneration, Paillier};
use zk_paillier::zkproofs::NICorrectKeyProof;

pub fn start() -> (R1State, R1Bcast) {
    let my_ecdsa_secret_summand = FE::new_random();
    let my_ecdsa_public_summand = GE::generator() * my_ecdsa_secret_summand;

    // TODO use safe primes in production
    // let (ek, dk) = Paillier::keypair_safe_primes().keys();
    let (ek, my_dk) = Paillier::keypair().keys();

    let correct_key_proof = NICorrectKeyProof::proof(&my_dk);
    let zkp = Zkp::new_unsafe();
    let (commit, my_reveal) =
        HashCommitment::create_commitment(&my_ecdsa_public_summand.bytes_compressed_to_big_int());
    let my_bcast = R1Bcast {
        commit,
        ek,
        zkp,
        correct_key_proof,
    };
    (
        R1State {
            my_ecdsa_secret_summand,
            my_dk,
            my_reveal,
            my_ecdsa_public_summand,
            my_output: my_bcast.clone(),
        },
        my_bcast,
    )
}
