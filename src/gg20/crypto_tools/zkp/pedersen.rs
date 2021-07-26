use crate::gg20::{constants, crypto_tools::k256_serde};
use ecdsa::{
    elliptic_curve::{sec1::FromEncodedPoint, Field},
    hazmat::FromDigest,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug)]
pub struct Statement<'a> {
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
// reference: https://github.com/ZenGo-X/curv/blob/b3b9c39b3113395604c50a248dfd3b9bbaa034fa/src/elliptic/curves/secp256_k1.rs#L44-L55
const SECP256K1_ALTERNATE_GENERATOR_X: [u8; 32] = [
    0x08, 0xd1, 0x32, 0x21, 0xe3, 0xa7, 0x32, 0x6a, 0x34, 0xdd, 0x45, 0x21, 0x4b, 0xa8, 0x01, 0x16,
    0xdd, 0x14, 0x2e, 0x4b, 0x5f, 0xf3, 0xce, 0x66, 0xa8, 0xdc, 0x7b, 0xfa, 0x03, 0x78, 0xb7, 0x95,
];
const SECP256K1_ALTERNATE_GENERATOR_Y: [u8; 32] = [
    0x5d, 0x41, 0xac, 0x14, 0x77, 0x61, 0x4b, 0x5c, 0x08, 0x48, 0xd5, 0x0d, 0xbd, 0x56, 0x5e, 0xa2,
    0x80, 0x7b, 0xcb, 0xa1, 0xdf, 0x0d, 0xf0, 0x7a, 0x82, 0x17, 0xe9, 0xf7, 0xf7, 0xc2, 0xbe, 0x88,
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
pub fn commit_with_randomness(
    msg: &k256::Scalar,
    randomness: &k256::Scalar,
) -> k256::ProjectivePoint {
    (k256::ProjectivePoint::generator() * msg) + (alternate_generator() * randomness)
}

// statement (commitment), witness (msg, randomness)
//   such that commitment = commit(msg, randomness)
// notation follows section 3.3 of GG20 https://eprint.iacr.org/2020/540.pdf
pub fn prove(stmt: &Statement, wit: &Witness) -> Proof {
    prove_inner(stmt, None, wit).0
}

pub fn verify(stmt: &Statement, proof: &Proof) -> Result<(), &'static str> {
    verify_inner(stmt, proof, None)
}

// statement (msg_g, g, commitment), witness (msg, randomness)
//   such that commitment = commit(msg, randomness)
//   and msg_g = msg * g (this is the additional "check")
// notation follows section 3.3 of GG20 https://eprint.iacr.org/2020/540.pdf
pub fn prove_wc(stmt: &StatementWc, wit: &Witness) -> ProofWc {
    let (proof, beta) = prove_inner(&stmt.stmt, Some((stmt.msg_g, stmt.g)), wit);
    ProofWc {
        proof,
        beta: k256_serde::ProjectivePoint::from(beta.unwrap()),
    }
}

pub fn verify_wc(stmt: &StatementWc, proof: &ProofWc) -> Result<(), &'static str> {
    verify_inner(
        &stmt.stmt,
        &proof.proof,
        Some((stmt.msg_g, stmt.g, proof.beta.unwrap())),
    )
}

fn prove_inner(
    stmt: &Statement,
    msg_g_g: Option<(&k256::ProjectivePoint, &k256::ProjectivePoint)>, // (msg_g, g)
    wit: &Witness,
) -> (Proof, Option<k256::ProjectivePoint>) {
    let a = k256::Scalar::random(rand::thread_rng());
    let b = k256::Scalar::random(rand::thread_rng());
    let alpha = commit_with_randomness(&a, &b);
    let beta = msg_g_g.map(|(_, g)| g * &a);
    let c = k256::Scalar::from_digest(
        Sha256::new()
            .chain(constants::PEDERSEN_PROOF_TAG.to_le_bytes())
            .chain(k256_serde::to_bytes(&stmt.commit))
            .chain(&msg_g_g.map_or(Vec::new(), |(msg_g, _)| k256_serde::to_bytes(msg_g)))
            .chain(&msg_g_g.map_or(Vec::new(), |(_, g)| k256_serde::to_bytes(g)))
            .chain(k256_serde::to_bytes(&alpha))
            .chain(&beta.map_or(Vec::new(), |beta| k256_serde::to_bytes(&beta))),
    );
    (
        Proof {
            alpha: k256_serde::ProjectivePoint::from(alpha),
            t: k256_serde::Scalar::from(a + c * wit.msg),
            u: k256_serde::Scalar::from(b + c * wit.randomness),
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
    )>, // (msg_g, g, beta))
) -> Result<(), &'static str> {
    let c = k256::Scalar::from_digest(
        Sha256::new()
            .chain(constants::PEDERSEN_PROOF_TAG.to_le_bytes())
            .chain(k256_serde::to_bytes(&stmt.commit))
            .chain(&msg_g_g_beta.map_or(Vec::new(), |(msg_g, _, _)| k256_serde::to_bytes(msg_g)))
            .chain(&msg_g_g_beta.map_or(Vec::new(), |(_, g, _)| k256_serde::to_bytes(g)))
            .chain(k256_serde::to_bytes(&proof.alpha.unwrap()))
            .chain(&msg_g_g_beta.map_or(Vec::new(), |(_, _, beta)| k256_serde::to_bytes(beta))),
    );
    if let Some((msg_g, g, beta)) = msg_g_g_beta {
        let lhs = g * proof.t.unwrap();
        let rhs = msg_g * &c + beta;
        if lhs != rhs {
            return Err("'wc' check fail");
        }
    }
    let lhs = commit_with_randomness(proof.t.unwrap(), proof.u.unwrap());
    let rhs = stmt.commit * &c + proof.alpha.unwrap();
    if lhs != rhs {
        return Err("verify fail");
    }
    Ok(())
}

#[cfg(any(test, feature = "malicious"))]
pub mod malicious {
    use super::*;

    pub fn corrupt_proof(proof: &Proof) -> Proof {
        Proof {
            u: k256_serde::Scalar::from(proof.u.unwrap() + k256::Scalar::one()),
            ..proof.clone()
        }
    }

    pub fn corrupt_proof_wc(proof: &ProofWc) -> ProofWc {
        ProofWc {
            beta: k256_serde::ProjectivePoint::from(
                k256::ProjectivePoint::generator() + proof.beta.unwrap(),
            ),
            ..proof.clone()
        }
    }
}

#[cfg(test)]
mod tests {
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

        let stmt_wc = &StatementWc {
            stmt: Statement { commit },
            msg_g,
            g,
        };
        let stmt = &stmt_wc.stmt;
        let wit = &Witness { msg, randomness };

        // test: valid proof
        let proof = prove(stmt, wit);
        verify(&stmt, &proof).unwrap();

        // test: valid proof wc (with check)
        let proof_wc = prove_wc(stmt_wc, wit);
        verify_wc(stmt_wc, &proof_wc).unwrap();

        // test: bad proof
        let bad_proof = corrupt_proof(&proof);
        verify(&stmt, &bad_proof).unwrap_err();

        // test: bad proof wc (with check)
        let bad_proof_wc = corrupt_proof_wc(&proof_wc);
        verify_wc(stmt_wc, &bad_proof_wc).unwrap_err();

        // test: bad witness
        let bad_wit = &Witness {
            msg: &(*wit.msg + k256::Scalar::one()),
            ..*wit
        };
        let bad_proof = prove(stmt, bad_wit);
        verify(stmt, &bad_proof).unwrap_err();

        // test: bad witness wc (with check)
        let bad_wit_proof_wc = prove_wc(stmt_wc, bad_wit);
        verify_wc(stmt_wc, &bad_wit_proof_wc).unwrap_err();
    }
}
