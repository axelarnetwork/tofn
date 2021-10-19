use crate::{
    collections::TypedUsize,
    crypto_tools::{
        constants,
        k256_serde::{self, SecretScalar},
    },
    gg20::sign::SignShareId,
};
use ecdsa::hazmat::FromDigest;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::warn;

#[derive(Clone, Debug)]
pub struct Statement<'a> {
    pub prover_id: TypedUsize<SignShareId>,
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

fn compute_challenge(
    stmt: &Statement,
    alpha1: &k256_serde::ProjectivePoint,
    alpha2: &k256_serde::ProjectivePoint,
) -> k256::Scalar {
    k256::Scalar::from_digest(
        Sha256::new()
            .chain(constants::CHAUM_PEDERSEN_PROOF_TAG.to_be_bytes())
            .chain(stmt.prover_id.to_bytes())
            .chain(k256_serde::point_to_bytes(stmt.base1))
            .chain(k256_serde::point_to_bytes(stmt.base2))
            .chain(k256_serde::point_to_bytes(stmt.target1))
            .chain(k256_serde::point_to_bytes(stmt.target2))
            .chain(alpha1.to_bytes())
            .chain(alpha2.to_bytes()),
    )
}

// statement (base1, base2, target1, target2), witness (scalar)
//   such that target1 == scalar * base1 and target2 == scalar * base2
// notation based on section 4.3 of GG20 https://eprint.iacr.org/2020/540.pdf
// except: (g, R, Sigma, S, alpha, beta) ->  (base1, base2, target1, target2, alpha1, alpha2)
pub fn prove(stmt: &Statement, wit: &Witness) -> Proof {
    let a = SecretScalar::random_with_thread_rng();

    // alpha = g^a
    let alpha1 = k256_serde::ProjectivePoint::from(stmt.base1 * a.as_ref());

    // beta = R^a
    let alpha2 = k256_serde::ProjectivePoint::from(stmt.base2 * a.as_ref());

    let c = compute_challenge(stmt, &alpha1, &alpha2);

    // t = a + c sigma mod q
    let t = a.as_ref() + c * wit.scalar;

    Proof {
        alpha1,
        alpha2,
        t: t.into(),
    }
}

pub fn verify(stmt: &Statement, proof: &Proof) -> bool {
    // Ensure that t is in Z_q and base1, base2, target1, target2, alpha1, alpha2 are in G
    // This is handled by k256_serde on deserialize

    let c = compute_challenge(stmt, &proof.alpha1, &proof.alpha2);

    // g^t ?= alpha Sigma^c
    let lhs1 = stmt.base1 * proof.t.as_ref();
    let rhs1 = *proof.alpha1.as_ref() + stmt.target1 * &c;

    // R^t ?= beta S^c
    let lhs2 = stmt.base2 * proof.t.as_ref();
    let rhs2 = *proof.alpha2.as_ref() + stmt.target2 * &c;

    let err = match (lhs1 == rhs1, lhs2 == rhs2) {
        (true, true) => return true,
        (false, false) => "both targets",
        (false, true) => "target1",
        (true, false) => "target2",
    };

    warn!("chaum pedersen proof: verify failed for {}", err);

    false
}

// warning suppression: uncomment the next line to malicious feature
// #[cfg(any(test, feature = "malicious"))] // malicious module used in tests
#[cfg(test)]
pub(crate) mod malicious {
    use super::*;

    pub fn corrupt_proof(proof: &Proof) -> Proof {
        Proof {
            t: (proof.t.as_ref() + k256::Scalar::one()).into(),
            ..proof.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ecdsa::elliptic_curve::{Field, Group};

    #[test]
    fn basic_correctness() {
        let base1 = &k256::ProjectivePoint::random(rand::thread_rng());
        let base2 = &k256::ProjectivePoint::random(rand::thread_rng());
        let scalar = &k256::Scalar::random(rand::thread_rng());
        let target1 = &(base1 * scalar);
        let target2 = &(base2 * scalar);
        let prover_id = TypedUsize::from_usize(1);
        let stmt = Statement {
            prover_id,
            base1,
            base2,
            target1,
            target2,
        };
        let wit = Witness { scalar };

        let bad_id = TypedUsize::from_usize(100);
        let bad_stmt = Statement {
            prover_id: bad_id,
            base1,
            base2,
            target1,
            target2,
        };

        // test: valid proof
        let proof = prove(&stmt, &wit);
        assert!(verify(&stmt, &proof));

        // test: bad id
        assert!(!verify(&bad_stmt, &proof));

        // test: bad proof
        let bad_proof = malicious::corrupt_proof(&proof);
        assert!(!verify(&stmt, &bad_proof));
        assert!(!verify(&bad_stmt, &bad_proof));

        // test: bad witness
        let bad_wit = Witness {
            scalar: &(*wit.scalar + k256::Scalar::one()),
        };
        let bad_proof = prove(&stmt, &bad_wit);
        assert!(!verify(&stmt, &bad_proof));
    }
}
