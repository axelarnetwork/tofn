use std::convert::TryInto;

use ecdsa::{
    elliptic_curve::{sec1::ToEncodedPoint, Field},
    hazmat::SignPrimitive,
};
use message_digest::MessageDigest;
use serde::{Deserialize, Serialize};
use tracing::error;

use crate::{
    crypto_tools::{k256_serde, message_digest, rng},
    sdk::api::{BytesVec, TofnFatal, TofnResult},
};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct KeyPair {
    signing_key: k256_serde::SecretScalar,
    verifying_key: k256_serde::ProjectivePoint,
}

impl KeyPair {
    /// SEC1-encoded compressed curve point
    pub fn encoded_verifying_key(&self) -> TofnResult<[u8; 32]> {
        // TODO make this work with k256_serde::ProjectivePoint::to_bytes
        self.verifying_key
            .as_ref()
            .to_affine()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .map_err(|_| {
                error!("failure to convert ecdsa verifying key to 33-byte array");
                TofnFatal
            })
    }
}

pub fn keygen(
    secret_recovery_key: &rng::SecretRecoveryKey,
    session_nonce: &[u8],
) -> TofnResult<KeyPair> {
    let rng = rng::rng_seed_ecdsa_signing_key(KEYGEN_TAG, secret_recovery_key, session_nonce)?;

    let signing_key = k256_serde::SecretScalar::random(rng);
    let verifying_key = k256_serde::ProjectivePoint::from(&signing_key);

    Ok(KeyPair {
        signing_key,
        verifying_key,
    })
}

/// Returns a ASN.1 DER-encoded ECDSA signature.
/// These signatures have variable byte length so we must return a [BytesVec] instead of a [u8] array.
pub fn sign(
    signing_key: &k256_serde::SecretScalar,
    message_digest: &MessageDigest,
) -> TofnResult<BytesVec> {
    let signing_key = signing_key.as_ref();
    let message_digest = k256::Scalar::from(message_digest);

    let rng = rng::rng_seed_ecdsa_ephemeral_scalar(SIGN_TAG, signing_key, &message_digest)?;
    let ephemeral_scalar = k256::Scalar::random(rng);

    let signature = k256_serde::Signature::from(
        signing_key
            .try_sign_prehashed(&ephemeral_scalar, &message_digest)
            .map_err(|_| {
                error!("failure to sign");
                TofnFatal
            })?,
    );

    Ok(signature.to_bytes())
}

/// Domain separation for seeding the RNG
const KEYGEN_TAG: u8 = 0x00;
const SIGN_TAG: u8 = 0x01;

#[cfg(test)]
mod tests {
    use ecdsa::{
        elliptic_curve::Field,
        hazmat::{SignPrimitive, VerifyPrimitive},
    };

    use crate::crypto_tools::k256_serde;

    #[test]
    fn sign_verify() {
        let signing_key = k256_serde::SecretScalar::random(rand::thread_rng());
        let hashed_msg = k256::Scalar::random(rand::thread_rng());
        let ephemeral_scalar = k256::Scalar::random(rand::thread_rng());
        let signature = signing_key
            .as_ref()
            .try_sign_prehashed(&ephemeral_scalar, &hashed_msg)
            .unwrap();
        let verifying_key = k256_serde::ProjectivePoint::from(&signing_key);
        verifying_key
            .as_ref()
            .to_affine()
            .verify_prehashed(&hashed_msg, &signature)
            .unwrap();
    }
}
