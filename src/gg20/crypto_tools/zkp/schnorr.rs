use crate::{
    collections::TypedUsize,
    gg20::{constants, crypto_tools::k256_serde, keygen::KeygenShareId},
};
use ecdsa::{elliptic_curve::Field, hazmat::FromDigest};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::warn;

#[derive(Clone, Debug)]
pub struct Statement<'a> {
    pub prover_id: TypedUsize<KeygenShareId>,
    pub base: &'a k256::ProjectivePoint,
    pub target: &'a k256::ProjectivePoint,
}

#[derive(Clone, Debug)]
pub struct Witness<'a> {
    pub scalar: &'a k256::Scalar,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    c: k256_serde::Scalar,
    t: k256_serde::Scalar,
}

// statement (base, target), witness (scalar)
//   such that target == scalar * base
pub fn prove(stmt: &Statement, wit: &Witness) -> Proof {
    let a = k256::Scalar::random(rand::thread_rng());
    let alpha = stmt.base * &a;
    let c = k256::Scalar::from_digest(
        Sha256::new()
            .chain(constants::SCHNORR_PROOF_TAG.to_le_bytes())
            .chain(stmt.prover_id.to_bytes())
            .chain(k256_serde::to_bytes(stmt.base))
            .chain(k256_serde::to_bytes(stmt.target))
            .chain(k256_serde::to_bytes(&alpha)),
    );
    Proof {
        c: c.into(),
        t: (a - c * wit.scalar).into(),
    }
}

pub fn verify(stmt: &Statement, proof: &Proof) -> bool {
    let alpha = stmt.base * proof.t.as_ref() + stmt.target * proof.c.as_ref();
    let c_check = k256::Scalar::from_digest(
        Sha256::new()
            .chain(constants::SCHNORR_PROOF_TAG.to_le_bytes())
            .chain(stmt.prover_id.to_bytes())
            .chain(k256_serde::to_bytes(stmt.base))
            .chain(k256_serde::to_bytes(stmt.target))
            .chain(k256_serde::to_bytes(&alpha)),
    );
    if &c_check == proof.c.as_ref() {
        true
    } else {
        warn!("schnorr verify failed");
        false
    }
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
    use ecdsa::elliptic_curve::Group;

    #[test]
    fn basic_correctness() {
        let base = &k256::ProjectivePoint::random(rand::thread_rng());
        let scalar = &k256::Scalar::random(rand::thread_rng());
        let target = &(base * scalar);
        let prover_id = TypedUsize::from_usize(5);
        let bad_id = TypedUsize::from_usize(1);
        let stmt = Statement {
            prover_id,
            base,
            target,
        };
        let wit = Witness { scalar };
        let bad_stmt = Statement {
            prover_id: bad_id,
            base,
            target,
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
