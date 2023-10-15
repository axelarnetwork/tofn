use crate::{
    constants::ED25519_TAG,
    crypto_tools::{message_digest::MessageDigest, rng},
    sdk::api::{BytesVec, TofnFatal, TofnResult},
};
use der::{asn1::BitStringRef, Sequence};
use ed25519::pkcs8::{
    spki::{
        der::{Decode, Encode},
        AlgorithmIdentifierRef,
    },
    ALGORITHM_ID,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey, PUBLIC_KEY_LENGTH};
use std::convert::TryInto;

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
    let mut rng =
        rng::rng_seed_signing_key(ED25519_TAG, KEYGEN_TAG, secret_recovery_key, session_nonce)?;

    let signing_key = SigningKey::generate(&mut rng);

    Ok(KeyPair(signing_key))
}

/// Returns a ASN.1 DER-encoded Ed25519 signature.
pub fn sign(signing_key: &KeyPair, message_digest: &MessageDigest) -> TofnResult<BytesVec> {
    let sig = signing_key.0.sign(message_digest.as_ref());

    Asn1Signature {
        signature_algorithm: ALGORITHM_ID,
        signature: (&sig.to_bytes()[..]).try_into().map_err(|_| TofnFatal)?,
    }
    .to_der()
    .map_err(|_| TofnFatal)
}

pub fn verify(
    encoded_verifying_key: &[u8; PUBLIC_KEY_LENGTH],
    message_digest: &MessageDigest,
    encoded_signature: &[u8],
) -> TofnResult<bool> {
    // TODO decode failure should not be `TofnFatal`?
    let verifying_key = VerifyingKey::from_bytes(encoded_verifying_key).map_err(|_| TofnFatal)?;

    let asn_signature = Asn1Signature::from_der(encoded_signature).map_err(|_| TofnFatal)?;
    if asn_signature.signature_algorithm != ALGORITHM_ID {
        return Err(TofnFatal);
    }

    // Using raw_bytes() here is safe since we do not have any unused bits.
    let signature =
        Signature::from_slice(asn_signature.signature.raw_bytes()).map_err(|_| TofnFatal)?;

    Ok(verifying_key
        .verify_strict(message_digest.as_ref(), &signature)
        .is_ok())
}

/// Domain separation for seeding the RNG
const KEYGEN_TAG: u8 = 0x00;

/// Signature structure as defined in [RFC 6960 Section 4.1.1].
///
/// ```text
/// Signature ::= SEQUENCE {
///    signatureAlgorithm      AlgorithmIdentifier,
///    signature               BIT STRING,
///    certs                  [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
/// ```
///
/// [RFC 6960 Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.1.1
/// This was taken from https://github.com/RustCrypto/formats/blob/master/x509-ocsp/src/lib.rs
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct Asn1Signature<'a> {
    pub signature_algorithm: AlgorithmIdentifierRef<'a>,
    pub signature: BitStringRef<'a>,
}

#[cfg(test)]
mod tests {
    use super::{keygen, sign, verify};
    use crate::crypto_tools::{message_digest::MessageDigest, rng::dummy_secret_recovery_key};
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
        *encoded_signature.last_mut().unwrap() += 1;

        let success = verify(
            &key_pair.encoded_verifying_key(),
            &message_digest,
            &encoded_signature,
        )
        .unwrap();

        assert!(!success);
    }
}
