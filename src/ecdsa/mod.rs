use std::convert::TryInto;

use ecdsa::{
    elliptic_curve::{sec1::ToEncodedPoint, Field},
    hazmat::{SignPrimitive, VerifyPrimitive},
};
use message_digest::MessageDigest;
use tracing::error;

use crate::{
    constants::ECDSA_TAG,
    crypto_tools::{k256_serde, message_digest, rng},
    sdk::api::{BytesVec, TofnFatal, TofnResult},
};

#[derive(Debug)]
pub struct KeyPair {
    signing_key: k256_serde::SecretScalar,
    encoded_verifying_key: [u8; 33], // SEC1-encoded compressed curve point
}

impl KeyPair {
    /// SEC1-encoded compressed curve point.
    /// tofnd needs to return this to axelar-core.
    pub fn encoded_verifying_key(&self) -> &[u8; 33] {
        &self.encoded_verifying_key
    }

    /// tofnd needs to store this in the kv store.
    pub fn signing_key(&self) -> &k256_serde::SecretScalar {
        &self.signing_key
    }
}

pub fn keygen(
    secret_recovery_key: &rng::SecretRecoveryKey,
    session_nonce: &[u8],
) -> TofnResult<KeyPair> {
    let rng =
        rng::rng_seed_ecdsa_signing_key(ECDSA_TAG, KEYGEN_TAG, secret_recovery_key, session_nonce)?;

    let signing_key = k256_serde::SecretScalar::random(rng);

    // TODO make this work with k256_serde::ProjectivePoint::to_bytes
    let encoded_verifying_key = k256_serde::ProjectivePoint::from(&signing_key)
        .as_ref()
        .to_affine()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .map_err(|_| {
            error!("failure to convert ecdsa verifying key to 33-byte array");
            TofnFatal
        })?;

    Ok(KeyPair {
        signing_key,
        encoded_verifying_key,
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

    let rng =
        rng::rng_seed_ecdsa_ephemeral_scalar(ECDSA_TAG, SIGN_TAG, signing_key, &message_digest)?;
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

pub fn verify(
    encoded_verifying_key: &[u8; 33],
    message_digest: &MessageDigest,
    encoded_signature: &[u8],
) -> TofnResult<bool> {
    // TODO decode failure should not be `TofnFatal`?
    let verifying_key =
        k256_serde::ProjectivePoint::from_bytes(encoded_verifying_key).ok_or(TofnFatal)?;
    let signature = k256::ecdsa::Signature::from_der(encoded_signature).map_err(|_| TofnFatal)?;
    let hashed_msg = k256::Scalar::from(message_digest);

    Ok(verifying_key
        .as_ref()
        .to_affine()
        .verify_prehashed(&hashed_msg, &signature)
        .is_ok())
}

/// Domain separation for seeding the RNG
const KEYGEN_TAG: u8 = 0x00;
const SIGN_TAG: u8 = 0x01;

#[cfg(test)]
mod tests {
    use super::{keygen, sign, verify};
    use crate::{crypto_tools::rng::dummy_secret_recovery_key, multisig::sign::MessageDigest};
    use std::convert::TryFrom;

    #[test]
    fn keygen_sign_decode_verify() {
        let message_digest = MessageDigest::try_from(&[42; 32][..]).unwrap();

        let key_pair = keygen(&dummy_secret_recovery_key(42), b"tofn nonce").unwrap();
        let encoded_signature = sign(key_pair.signing_key(), &message_digest).unwrap();
        let success = verify(
            key_pair.encoded_verifying_key(),
            &message_digest,
            &encoded_signature,
        )
        .unwrap();

        assert!(success);
    }
}
