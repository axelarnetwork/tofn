use crate::gg20::{constants, crypto_tools::k256_serde};
use ecdsa::{elliptic_curve::Field, hazmat::FromDigest};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug)]
pub struct Statement<'a> {
    pub base1: &'a k256::ProjectivePoint,
    pub base2: &'a k256::ProjectivePoint,
    pub target1: &'a k256::ProjectivePoint,
    pub target2: &'a k256::ProjectivePoint,
}
#[derive(Clone, Debug)]
pub struct Witness<'a> {
    pub scalar: &'a k256::Scalar,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    alpha1: k256_serde::ProjectivePoint,
    alpha2: k256_serde::ProjectivePoint,
    t: k256_serde::Scalar,
}

// statement (base1, base2, target1, target2), witness (scalar)
//   such that target1 == scalar * base1 and target2 == scalar * base2
// notation based on section 4.3 of GG20 https://eprint.iacr.org/2020/540.pdf
// except: (g, R, Sigma, S, alpha, beta) ->  (base1, base2, target1, target2, alpha1, alpha2)
pub fn prove(stmt: &Statement, wit: &Witness) -> Proof {
    let a = k256::Scalar::random(rand::thread_rng());
    let alpha1 = k256_serde::ProjectivePoint::from(stmt.base1 * &a);
    let alpha2 = k256_serde::ProjectivePoint::from(stmt.base2 * &a);
    let c = k256::Scalar::from_digest(
        Sha256::new()
            .chain(constants::CHAUM_PEDERSEN_PROOF_TAG.to_le_bytes())
            .chain(k256_serde::to_bytes(&stmt.base1))
            .chain(k256_serde::to_bytes(&stmt.base2))
            .chain(k256_serde::to_bytes(&stmt.target1))
            .chain(k256_serde::to_bytes(&stmt.target2))
            .chain(alpha1.bytes())
            .chain(alpha2.bytes()),
    );
    Proof {
        alpha1,
        alpha2,
        t: (a + c * wit.scalar).into(),
    }
}

pub fn verify(stmt: &Statement, proof: &Proof) -> Result<(), &'static str> {
    let c = k256::Scalar::from_digest(
        Sha256::new()
            .chain(constants::CHAUM_PEDERSEN_PROOF_TAG.to_le_bytes())
            .chain(k256_serde::to_bytes(&stmt.base1))
            .chain(k256_serde::to_bytes(&stmt.base2))
            .chain(k256_serde::to_bytes(&stmt.target1))
            .chain(k256_serde::to_bytes(&stmt.target2))
            .chain(proof.alpha1.bytes())
            .chain(proof.alpha2.bytes()),
    );
    let lhs1 = stmt.base1 * proof.t.unwrap();
    let lhs2 = stmt.base2 * proof.t.unwrap();
    let rhs1 = *proof.alpha1.unwrap() + stmt.target1 * &c;
    let rhs2 = *proof.alpha2.unwrap() + stmt.target2 * &c;
    match (lhs1 == rhs1, lhs2 == rhs2) {
        (true, true) => Ok(()),
        (false, false) => Err("fail both targets"),
        (false, true) => Err("fail target1"),
        (true, false) => Err("fail target2"),
    }
}

// warning suppression: uncomment the next line to malicious feature
// #[cfg(any(test, feature = "malicious"))] // malicious module used in tests
#[cfg(test)]
pub(crate) mod malicious {
    use super::*;

    pub fn corrupt_proof(proof: &Proof) -> Proof {
        Proof {
            t: (proof.t.unwrap() + k256::Scalar::one()).into(),
            ..proof.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ecdsa::elliptic_curve::Group;

    #[test]
    fn basic_correctness() {
        let base1 = &k256::ProjectivePoint::random(rand::thread_rng());
        let base2 = &k256::ProjectivePoint::random(rand::thread_rng());
        let scalar = &k256::Scalar::random(rand::thread_rng());
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
        let bad_proof = malicious::corrupt_proof(&proof);
        verify(&stmt, &bad_proof).unwrap_err();

        // test: bad witness
        let bad_wit = Witness {
            scalar: &(*wit.scalar + k256::Scalar::one()),
        };
        let bad_proof = prove(&stmt, &bad_wit);
        verify(&stmt, &bad_proof).unwrap_err();
    }
}
