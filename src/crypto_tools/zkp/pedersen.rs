use crate::{
    collections::TypedUsize,
    crypto_tools::{
        constants,
        k256_serde::{self, SecretScalar},
    },
    gg20::sign::SignShareId,
    sdk::api::{TofnFatal, TofnResult},
};
use ecdsa::{
    elliptic_curve::{sec1::FromEncodedPoint, Field},
    hazmat::FromDigest,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{error, warn};

#[derive(Clone, Debug)]
pub struct Statement<'a> {
    pub prover_id: TypedUsize<SignShareId>,
    pub commit: &'a k256::ProjectivePoint,
}

#[derive(Clone, Debug)]
pub struct Witness<'a> {
    pub msg: &'a k256::Scalar,
    pub randomness: &'a k256::Scalar,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    alpha: k256_serde::ProjectivePoint,
    t: k256_serde::Scalar,
    u: k256_serde::Scalar,
}

#[derive(Clone, Debug)]
pub struct StatementWc<'a> {
    pub stmt: Statement<'a>,
    pub msg_g: &'a k256::ProjectivePoint,
    pub g: &'a k256::ProjectivePoint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofWc {
    proof: Proof,
    beta: k256_serde::ProjectivePoint,
}

// (x,y) coordinates of a point of unknown discrete log on the sekp256k1 curve
// see test `secp256k1_alternate_generator` below
const SECP256K1_ALTERNATE_GENERATOR_X: [u8; 32] = [
    0x09, 0xc9, 0xf8, 0xe1, 0xc7, 0xe2, 0x5c, 0xb8, 0x71, 0x39, 0x1b, 0xeb, 0xe1, 0xf5, 0x80, 0x7a,
    0xc5, 0xcc, 0xca, 0x85, 0xc5, 0xa1, 0xdd, 0x57, 0x33, 0x85, 0x18, 0xc4, 0x90, 0x48, 0x1d, 0xae,
];
const SECP256K1_ALTERNATE_GENERATOR_Y: [u8; 32] = [
    0x4c, 0x5a, 0x4d, 0xf7, 0xc3, 0xad, 0x74, 0xf1, 0x8e, 0x7d, 0x87, 0xff, 0x5d, 0x16, 0xa4, 0x3c,
    0x16, 0x87, 0x20, 0xa9, 0xba, 0x35, 0x4d, 0x2c, 0x28, 0x26, 0xd0, 0x52, 0x79, 0xea, 0x49, 0x84,
];

pub fn alternate_generator() -> k256::ProjectivePoint {
    k256::AffinePoint::from_encoded_point(&k256::EncodedPoint::from_affine_coordinates(
        k256::FieldBytes::from_slice(&SECP256K1_ALTERNATE_GENERATOR_X[..]),
        k256::FieldBytes::from_slice(&SECP256K1_ALTERNATE_GENERATOR_Y[..]),
        false,
    ))
    .unwrap()
    .into()
}

// commit returns (commitment, randomness)
pub fn commit(msg: &k256::Scalar) -> (k256::ProjectivePoint, k256::Scalar) {
    let randomness = k256::Scalar::random(rand::thread_rng());
    (commit_with_randomness(msg, &randomness), randomness)
}

/// Compute commitment g^m h^r
pub fn commit_with_randomness(
    msg: &k256::Scalar,
    randomness: &k256::Scalar,
) -> k256::ProjectivePoint {
    (k256::ProjectivePoint::generator() * msg) + (alternate_generator() * randomness)
}

// statement (commitment), witness (msg, randomness)
//   such that commitment = commit(msg, randomness)
// notation follows section 3.3 (phase 6, but with alpha/beta switched)
// of GG20 https://eprint.iacr.org/2020/540.pdf
pub fn prove(stmt: &Statement, wit: &Witness) -> Proof {
    prove_inner(stmt, None, wit).0
}

pub fn verify(stmt: &Statement, proof: &Proof) -> bool {
    verify_inner(stmt, proof, None)
}

// statement (msg_g, g, commitment), witness (msg, randomness)
//   such that commitment = commit(msg, randomness)
//   and msg_g = msg * g (this is the additional "check")
// notation follows section 3.3 of GG20 https://eprint.iacr.org/2020/540.pdf
pub fn prove_wc(stmt: &StatementWc, wit: &Witness) -> TofnResult<ProofWc> {
    let (proof, beta) = prove_inner(&stmt.stmt, Some((stmt.msg_g, stmt.g)), wit);

    let beta = beta
        .ok_or_else(|| {
            error!("pedersen proof: 'wc' missing beta");
            TofnFatal
        })?
        .into();

    Ok(ProofWc { proof, beta })
}

pub fn verify_wc(stmt: &StatementWc, proof: &ProofWc) -> bool {
    verify_inner(
        &stmt.stmt,
        &proof.proof,
        Some((stmt.msg_g, stmt.g, proof.beta.as_ref())),
    )
}

fn compute_challenge(
    stmt: &Statement,
    msg_g_g: Option<(&k256::ProjectivePoint, &k256::ProjectivePoint)>,
    alpha: &k256::ProjectivePoint,
    beta: Option<&k256::ProjectivePoint>,
) -> k256::Scalar {
    k256::Scalar::from_digest(
        Sha256::new()
            .chain(constants::PEDERSEN_PROOF_TAG.to_be_bytes())
            .chain(stmt.prover_id.to_bytes())
            .chain(k256_serde::point_to_bytes(stmt.commit))
            .chain(&msg_g_g.map_or([0; 33], |(msg_g, _)| k256_serde::point_to_bytes(msg_g)))
            .chain(&msg_g_g.map_or([0; 33], |(_, g)| k256_serde::point_to_bytes(g)))
            .chain(k256_serde::point_to_bytes(alpha))
            .chain(&beta.map_or([0; 33], |beta| k256_serde::point_to_bytes(beta))),
    )
}

#[allow(clippy::many_single_char_names)]
fn prove_inner(
    stmt: &Statement,
    msg_g_g: Option<(&k256::ProjectivePoint, &k256::ProjectivePoint)>, // (msg_g, g)
    wit: &Witness,
) -> (Proof, Option<k256::ProjectivePoint>) {
    let a = SecretScalar::random_with_thread_rng();
    let b = SecretScalar::random_with_thread_rng();

    // alpha = g^a h^b
    let alpha = commit_with_randomness(a.as_ref(), b.as_ref());

    // beta = R^a
    let beta = msg_g_g.map(|(_, g)| g * a.as_ref());

    let c = compute_challenge(stmt, msg_g_g, &alpha, beta.as_ref());

    // t = a + c sigma mod q
    let t = a.as_ref() + c * wit.msg;

    // u = b + c l mod q
    let u = b.as_ref() + c * wit.randomness;

    (
        Proof {
            alpha: alpha.into(),
            t: t.into(),
            u: u.into(),
        },
        beta,
    )
}

fn verify_inner(
    stmt: &Statement,
    proof: &Proof,
    msg_g_g_beta: Option<(
        &k256::ProjectivePoint,
        &k256::ProjectivePoint,
        &k256::ProjectivePoint,
    )>, // (msg_g, g, beta)
) -> bool {
    // Ensure that t and u are in Z_q and commit, alpha (and msg_g, g, beta) are in G
    // This is handled by k256_serde on deserialize
    let c = compute_challenge(
        stmt,
        msg_g_g_beta.map(|(msg_g, g, _)| (msg_g, g)),
        proof.alpha.as_ref(),
        msg_g_g_beta.map(|(_, _, beta)| beta),
    );

    // R^t ?= alpha S^c
    if let Some((msg_g, g, beta)) = msg_g_g_beta {
        let lhs = g * proof.t.as_ref();
        let rhs = msg_g * &c + beta;
        if lhs != rhs {
            warn!("pedersen proof: 'wc' check failed");
            return false;
        }
    }

    // g^t h^u ?= beta T^c
    let lhs = commit_with_randomness(proof.t.as_ref(), proof.u.as_ref());
    let rhs = stmt.commit * &c + proof.alpha.as_ref();
    if lhs != rhs {
        warn!("pedersen proof: verify failed");
        return false;
    }

    true
}

#[cfg(any(test, feature = "malicious"))]
pub mod malicious {
    use super::*;

    pub fn corrupt_proof(proof: &Proof) -> Proof {
        Proof {
            u: k256_serde::Scalar::from(proof.u.as_ref() + k256::Scalar::one()),
            ..proof.clone()
        }
    }

    pub fn corrupt_proof_wc(proof: &ProofWc) -> ProofWc {
        ProofWc {
            beta: k256_serde::ProjectivePoint::from(
                k256::ProjectivePoint::generator() + proof.beta.as_ref(),
            ),
            ..proof.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use ecdsa::elliptic_curve::group::prime::PrimeCurveAffine;

    use super::{
        malicious::{corrupt_proof, corrupt_proof_wc},
        *,
    };

    #[test]
    fn basic_correctness() {
        let msg = &k256::Scalar::random(rand::thread_rng());
        let g = &k256::ProjectivePoint::generator();
        let msg_g = &(g * msg);
        let (commit, randomness) = &commit(msg);

        let prover_id = TypedUsize::from_usize(8921436);
        let stmt_wc = &StatementWc {
            stmt: Statement { prover_id, commit },
            msg_g,
            g,
        };
        let stmt = &stmt_wc.stmt;
        let wit = &Witness { msg, randomness };

        let bad_id = TypedUsize::from_usize(0);
        let bad_stmt_wc = &StatementWc {
            stmt: Statement {
                prover_id: bad_id,
                commit,
            },
            msg_g,
            g,
        };
        let bad_stmt = &bad_stmt_wc.stmt;

        // test: valid proof
        let proof = prove(stmt, wit);
        assert!(verify(stmt, &proof));

        // test: valid proof wc (with check)
        let proof_wc = prove_wc(stmt_wc, wit).unwrap();
        assert!(verify_wc(stmt_wc, &proof_wc));

        // test: valid proof and bad id
        assert!(!verify(bad_stmt, &proof));

        // test: valid proof wc and bad id
        assert!(!verify_wc(bad_stmt_wc, &proof_wc));

        // test: bad proof
        let bad_proof = corrupt_proof(&proof);
        assert!(!verify(stmt, &bad_proof));
        assert!(!verify(bad_stmt, &bad_proof));

        // test: bad proof wc (with check)
        let bad_proof_wc = corrupt_proof_wc(&proof_wc);
        assert!(!verify_wc(stmt_wc, &bad_proof_wc));
        assert!(!verify_wc(bad_stmt_wc, &bad_proof_wc));

        // test: bad witness
        let bad_wit = &Witness {
            msg: &(*wit.msg + k256::Scalar::one()),
            ..*wit
        };
        let bad_proof = prove(stmt, bad_wit);
        assert!(!verify(stmt, &bad_proof));

        // test: bad witness wc (with check)
        let bad_wit_proof_wc = prove_wc(stmt_wc, bad_wit).unwrap();
        assert!(!verify_wc(stmt_wc, &bad_wit_proof_wc));
    }

    #[test]
    /// This test proves that the return value of `alternate_generator()`
    /// has unknown discrete log with respect to the secp256k1 curve generator
    fn secp256k1_alternate_generator() {
        // prepare a pseudorandom SEC1 encoding of a k256 curve point
        let hash = Sha256::new()
            .chain(constants::PEDERSEN_SECP256K1_ALTERNATE_GENERATOR_TAG.to_be_bytes())
            .chain(k256::EncodedPoint::from(k256::AffinePoint::generator()).as_bytes())
            .chain(&[0x01])
            .finalize();
        let mut bytes = vec![0x02]; // use even y-coordinate using SEC1 encoding
        bytes.extend_from_slice(hash.as_slice());

        let curve_point = k256::ProjectivePoint::from_encoded_point(
            &k256::EncodedPoint::from_bytes(bytes).unwrap(),
        )
        .unwrap();

        assert_eq!(curve_point, alternate_generator());
    }
}
