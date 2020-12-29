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
    let u = FE::new_random();
    let y = GE::generator() * u;

    // TODO use safe primes in production
    // let (ek, dk) = Paillier::keypair_safe_primes().keys();
    let (ek, dk) = Paillier::keypair().keys();

    let correct_key_proof = NICorrectKeyProof::proof(&dk);
    let zkp = Zkp::new_unsafe();
    let (commit, reveal) = HashCommitment::create_commitment(
        &y.bytes_compressed_to_big_int()
    );
    let msg_out = R1Bcast{ commit, ek, zkp, correct_key_proof };
    (
        R1State{ u, dk, reveal, y, msg_out: msg_out.clone() },
        msg_out,
    )
}