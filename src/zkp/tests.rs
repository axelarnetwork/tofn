use curv::{
    // arithmetic::traits::{Modulo, Samplable},
    // cryptographic_primitives::hashing::{hash_sha256::HSha256, traits::Hash},
    elliptic::curves::traits::ECScalar,
    BigInt,
    FE,
};
use paillier::{EncryptWithChosenRandomness, KeyGeneration, Paillier, Randomness, RawPlaintext};

use super::{RangeProof, RangeStatement, RangeWitness, Zkp};

#[test]
fn basic_correctness() {
    let (ek, _dk) = Paillier::keypair().keys(); // not using safe primes
    let msg = FE::new_random();
    let randomness = Randomness::sample(&ek);
    let ciphertext = Paillier::encrypt_with_chosen_randomness(
        &ek,
        RawPlaintext::from(msg.to_big_int()),
        &randomness,
    )
    .0
    .clone()
    .into_owned();

    let stmt = RangeStatement { ciphertext, ek };
    let wit = RangeWitness {
        msg,
        randomness: randomness.0,
    };
    let zkp = Zkp::new_unsafe();

    // test: valid proof
    let proof = zkp.range_proof(&stmt, &wit);
    zkp.verify_range_proof(&stmt, &proof).unwrap();

    // test: bad proof
    let bad_proof = RangeProof {
        u: proof.u + BigInt::from(1),
        ..proof
    };
    zkp.verify_range_proof(&stmt, &bad_proof).unwrap_err();

    // test: bad witness
    let one: FE = ECScalar::from(&BigInt::from(1));
    let bad_wit = RangeWitness {
        msg: wit.msg + one,
        ..wit
    };
    let bad_proof = zkp.range_proof(&stmt, &bad_wit);
    zkp.verify_range_proof(&stmt, &bad_proof).unwrap_err();
}
