use curv::{
    cryptographic_primitives::hashing::{hash_sha256::HSha256, traits::Hash},
    elliptic::curves::traits::{ECPoint, ECScalar},
    BigInt, FE, GE,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug)]
pub struct Statement<'a> {
    pub base1: &'a GE,
    pub base2: &'a GE,
    pub target1: &'a GE,
    pub target2: &'a GE,
}
#[derive(Clone, Debug)]
pub struct Witness<'a> {
    pub scalar: &'a FE,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    alpha1: GE,
    alpha2: GE,
    t: FE,
}

// statement (base1, base2, target1, target2), witness (scalar)
//   such that target1 == scalar * base1 and target2 == scalar * base2
// notation based on section 4.3 of GG20 https://eprint.iacr.org/2020/540.pdf
// except: (g, R, Sigma, S, alpha, beta) ->  (base1, base2, target1, target2, alpha1, alpha2)
pub fn prove(stmt: &Statement, wit: &Witness) -> Proof {
    let a = FE::new_random();
    let alpha1 = stmt.base1 * &a;
    let alpha2 = stmt.base2 * &a;
    let c: FE = ECScalar::from(&HSha256::create_hash(&[
        &stmt.base1.bytes_compressed_to_big_int(),
        &stmt.base2.bytes_compressed_to_big_int(),
        &stmt.target1.bytes_compressed_to_big_int(),
        &stmt.target2.bytes_compressed_to_big_int(),
        &alpha1.bytes_compressed_to_big_int(),
        &alpha2.bytes_compressed_to_big_int(),
    ]));
    Proof {
        alpha1,
        alpha2,
        t: a + c * wit.scalar,
    }
}

pub fn verify(stmt: &Statement, proof: &Proof) -> Result<(), &'static str> {
    let c: FE = ECScalar::from(&HSha256::create_hash(&[
        &stmt.base1.bytes_compressed_to_big_int(),
        &stmt.base2.bytes_compressed_to_big_int(),
        &stmt.target1.bytes_compressed_to_big_int(),
        &stmt.target2.bytes_compressed_to_big_int(),
        &proof.alpha1.bytes_compressed_to_big_int(),
        &proof.alpha2.bytes_compressed_to_big_int(),
    ]));
    let lhs1 = stmt.base1 * &proof.t;
    let lhs2 = stmt.base2 * &proof.t;
    let rhs1 = proof.alpha1 + stmt.target1 * &c;
    let rhs2 = proof.alpha2 + stmt.target2 * &c;
    match (lhs1 == rhs1, lhs2 == rhs2) {
        (true, true) => Ok(()),
        (false, false) => Err("fail both targets"),
        (false, true) => Err("fail target1"),
        (true, false) => Err("fail target2"),
    }
}

#[cfg(any(test, feature = "malicious"))] // malicious module used in tests
pub(crate) mod malicious {
    use super::*;

    pub fn corrupt_proof(proof: &Proof) -> Proof {
        let proof = proof.clone();
        let one: FE = ECScalar::from(&BigInt::from(1));
        Proof {
            t: proof.t + one,
            ..proof
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{malicious::corrupt_proof, prove, verify, Statement, Witness};
    use curv::{elliptic::curves::traits::ECScalar, BigInt, FE, GE};
    use tracing_test::traced_test; // enable logs in tests

    #[test]
    #[traced_test]
    fn basic_correctness() {
        let (base1, base2) = (&GE::random_point(), &GE::random_point());
        let scalar = &FE::new_random();
        let target1 = &(base1 * scalar);
        let target2 = &(base2 * scalar);
        let stmt = Statement {
            base1,
            base2,
            target1,
            target2,
        };
        let wit = Witness { scalar };

        // test: valid proof
        let proof = prove(&stmt, &wit);
        verify(&stmt, &proof).unwrap();

        // test: bad proof
        let bad_proof = corrupt_proof(&proof);
        verify(&stmt, &bad_proof).unwrap_err();

        // test: bad witness
        let one: FE = ECScalar::from(&BigInt::from(1));
        let bad_wit = Witness {
            scalar: &(*wit.scalar + one),
            ..wit
        };
        let bad_proof = prove(&stmt, &bad_wit);
        verify(&stmt, &bad_proof).unwrap_err();
    }
}
