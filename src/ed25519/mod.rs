use crate::{
    constants::ED25519_TAG,
    crypto_tools::{message_digest::MessageDigest, rng},
    sdk::api::{BytesVec, TofnFatal, TofnResult},
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey, PUBLIC_KEY_LENGTH};

#[derive(Debug)]
pub struct KeyPair(SigningKey);

impl KeyPair {
    pub fn encoded_verifying_key(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        *self.0.verifying_key().as_bytes()
    }
}

pub fn keygen(
    secret_recovery_key: &rng::SecretRecoveryKey,
    session_nonce: &[u8],
) -> TofnResult<KeyPair> {
    let mut rng = rng::rng_seed_ecdsa_signing_key(
        ED25519_TAG,
        KEYGEN_TAG,
        secret_recovery_key,
        session_nonce,
    )?;

    let signing_key = SigningKey::generate(&mut rng);

    Ok(KeyPair(signing_key))
}

/// Returns the 64 bytes signature containing the (R, s) components.
pub fn sign(signing_key: &KeyPair, message_digest: &MessageDigest) -> TofnResult<BytesVec> {
    let sig = signing_key.0.sign(message_digest.as_ref());
    Ok(sig.to_vec())
}

pub fn verify(
    encoded_verifying_key: &[u8; PUBLIC_KEY_LENGTH],
    message_digest: &MessageDigest,
    encoded_signature: &[u8],
) -> TofnResult<bool> {
    // TODO decode failure should not be `TofnFatal`?
    let verifying_key = VerifyingKey::from_bytes(encoded_verifying_key).map_err(|_| TofnFatal)?;
    let signature = Signature::from_slice(encoded_signature).map_err(|_| TofnFatal)?;

    Ok(verifying_key
        .verify_strict(message_digest.as_ref(), &signature)
        .is_ok())
}

/// Domain separation for seeding the RNG
const KEYGEN_TAG: u8 = 0x00;

#[cfg(test)]
mod tests {
    use super::{keygen, sign, verify};
    use crate::{crypto_tools::rng::dummy_secret_recovery_key, multisig::sign::MessageDigest};
    use std::convert::TryFrom;

    #[test]
    fn keygen_sign_decode_verify() {
        let message_digest = MessageDigest::try_from(&[42; 32][..]).unwrap();

        let key_pair = keygen(&dummy_secret_recovery_key(42), b"tofn nonce").unwrap();
        let mut encoded_signature = sign(&key_pair, &message_digest).unwrap();

        // Correct signature should verify
        let success = verify(
            &key_pair.encoded_verifying_key(),
            &message_digest,
            &encoded_signature,
        )
        .unwrap();

        assert!(success);

        // Tamper with the signature, it should no longer verify.
        encoded_signature[0] += 1;

        let success = verify(
            &key_pair.encoded_verifying_key(),
            &message_digest,
            &encoded_signature,
        )
        .unwrap();

        assert!(!success);

    }
}
