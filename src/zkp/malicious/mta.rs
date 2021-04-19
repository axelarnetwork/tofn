use crate::zkp::mta::{Proof, ProofWc};
use curv::elliptic::curves::traits::ECPoint;
use curv::{BigInt, GE};

impl Proof {
    pub(crate) fn add_to_v(&mut self, increment: BigInt) {
        self.v += increment;
    }
}

impl ProofWc {
    pub(crate) fn add_to_u(
        &mut self,
        increment: curv::elliptic::curves::secp256_k1::Secp256k1Point,
    ) {
        self.u = self.u + increment;
    }
}

pub fn corrupt_proof(proof: &Proof) -> Proof {
    let mut proof = proof.clone();
    proof.add_to_v(BigInt::from(1));
    proof
}

pub fn corrupt_proof_wc(proof: &ProofWc) -> ProofWc {
    let mut proof = proof.clone();
    proof.add_to_u(GE::generator());
    proof
}

mod tests {

    #[test]
    fn basic_correctness() {
        use super::*;
        use crate::zkp::{
            mta::{Statement, StatementWc, Witness},
            Zkp,
        };
        use curv::{
            arithmetic::traits::Samplable,
            elliptic::curves::traits::{ECPoint, ECScalar},
            BigInt, FE, GE,
        };
        use paillier::{
            Add, EncryptWithChosenRandomness, KeyGeneration, Mul, Paillier, Randomness,
            RawCiphertext, RawPlaintext,
        };

        // create a (statement, witness) pair
        let (ek, _dk) = &Paillier::keypair().keys(); // not using safe primes
        let msg = &BigInt::sample_below(&ek.n);
        let x = &FE::new_random();
        let x_g = &(GE::generator() * x);
        let randomness = &Randomness::sample(&ek);
        let ciphertext1 = &BigInt::sample_below(&ek.nn);
        let ciphertext2 = &Paillier::add(
            ek,
            Paillier::mul(
                ek,
                RawCiphertext::from(ciphertext1),
                RawPlaintext::from(x.to_big_int()),
            ),
            Paillier::encrypt_with_chosen_randomness(ek, RawPlaintext::from(msg), randomness),
        )
        .0;

        let stmt_wc = &StatementWc {
            stmt: Statement {
                ciphertext1,
                ciphertext2,
                ek,
            },
            x_g,
        };
        let stmt = &stmt_wc.stmt;
        let wit = &Witness {
            msg,
            randomness: &randomness.0,
            x,
        };
        let zkp = Zkp::new_unsafe();

        let proof = zkp.mta_proof(stmt, wit);
        let proof_wc = zkp.mta_proof_wc(stmt_wc, wit);

        // test: bad proof
        let bad_proof = corrupt_proof(&proof);
        zkp.verify_mta_proof(stmt, &bad_proof).unwrap_err();

        // test: bad proof wc (with check)
        let bad_proof_wc = corrupt_proof_wc(&proof_wc);
        zkp.verify_mta_proof_wc(stmt_wc, &bad_proof_wc).unwrap_err();

        // test: bad witness
        let bad_wit = &Witness {
            msg: &(wit.msg + BigInt::from(1)),
            ..*wit
        };
        let bad_wit_proof = zkp.mta_proof(stmt, bad_wit);
        zkp.verify_mta_proof(&stmt, &bad_wit_proof).unwrap_err();

        // test: bad witness wc (with check)
        let bad_wit_proof_wc = zkp.mta_proof_wc(stmt_wc, bad_wit);
        zkp.verify_mta_proof_wc(stmt_wc, &bad_wit_proof_wc)
            .unwrap_err();
    }
}
