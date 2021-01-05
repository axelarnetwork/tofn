use curv::{
    FE, GE,
    elliptic::curves::traits::{ECScalar, ECPoint},
    cryptographic_primitives::commitments::{
        hash_commitment::HashCommitment,
        traits::Commitment
    },
};
use paillier::{Paillier, KeyGeneration};
use zk_paillier::zkproofs::NICorrectKeyProof;
use super::{R1State, R1Bcast, super::super::zkp::Zkp};

pub fn start() -> (R1State, R1Bcast) {
    let my_ecdsa_secret_summand = FE::new_random();
    let my_ecdsa_public_summand = GE::generator() * my_ecdsa_secret_summand;

    // TODO use safe primes in production
    // let (ek, dk) = Paillier::keypair_safe_primes().keys();
    let (ek, my_dk) = Paillier::keypair().keys();

    let correct_key_proof = NICorrectKeyProof::proof(&my_dk);
    let zkp = Zkp::new_unsafe();
    let (commit, my_reveal) = HashCommitment::create_commitment(
        &my_ecdsa_public_summand.bytes_compressed_to_big_int()
    );
    let my_bcast = R1Bcast{
        commit,
        ek,
        zkp,
        correct_key_proof
    };
    (
        R1State{
            my_ecdsa_secret_summand,
            my_dk,
            my_reveal,
            my_ecdsa_public_summand,
            my_output: my_bcast.clone(),
        },
        my_bcast
    )
}