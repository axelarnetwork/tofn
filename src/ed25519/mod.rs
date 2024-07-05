use crate::{
    constants::ED25519_TAG,
    crypto_tools::{message_digest::MessageDigest, rng},
    sdk::{
        api::{BytesVec, TofnFatal, TofnResult},
        key::SecretRecoveryKey,
    },
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
    secret_recovery_key: &SecretRecoveryKey,
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
    use crate::sdk::key::{dummy_secret_recovery_key, SecretRecoveryKey};

    #[test]
    fn keygen_sign_decode_verify() {
        let message_digest = [42; 32].into();

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

    /// Check keygen/signing outputs against known vectors to catch regressions (such as on updating deps).
    /// Known vectors were generated from tofn v0.2.0 release when ed25519 was added.
    #[test]
    fn keygen_sign_known_vectors() {
        struct TestCase {
            secret_recovery_key: SecretRecoveryKey,
            session_nonce: Vec<u8>,
            message_digest: [u8; 32],
            expected_signing_key: Vec<u8>,
            expected_verifying_key: Vec<u8>,
            expected_signature: Vec<u8>,
        }

        let test_cases = vec![
            TestCase {
                secret_recovery_key: SecretRecoveryKey([0; 64]),
                session_nonce: vec![0; 4],
                message_digest: [42; 32],
                expected_signing_key: vec![47, 167, 96, 110, 72, 189, 202, 24, 85, 172, 92, 89, 34, 214, 183, 208, 123, 207, 108, 6, 203, 152, 106, 30, 152, 22, 213, 246, 196, 228, 15, 203],
                expected_verifying_key: vec![252, 19, 166, 220, 100, 224, 119, 124, 12, 62, 248, 29, 85, 210, 67, 70, 106, 30, 134, 23, 122, 102, 202, 128, 167, 87, 162, 1, 162, 174, 45, 87],
                expected_signature: vec![48, 74, 48, 5, 6, 3, 43, 101, 112, 3, 65, 0, 251, 109, 114, 195, 237, 52, 143, 102, 5, 58, 186, 163, 235, 93, 247, 31, 92, 253, 185, 204, 85, 228, 29, 255, 109, 62, 188, 254, 212, 70, 27, 227, 40, 206, 112, 248, 107, 34, 173, 148, 68, 243, 180, 4, 43, 81, 199, 202, 8, 204, 227, 191, 144, 66, 127, 160, 148, 159, 242, 190, 39, 118, 166, 2],
            },
            TestCase {
                secret_recovery_key: SecretRecoveryKey([0xff; 64]),
                session_nonce: vec![0xff; 32],
                message_digest: [0xff; 32],
                expected_signing_key: vec![55, 236, 122, 218, 96, 136, 145, 36, 23, 44, 197, 200, 91, 19, 123, 136, 19, 0, 16, 129, 189, 183, 22, 75, 120, 46, 123, 71, 132, 27, 161, 232],
                expected_verifying_key: vec![35, 64, 196, 184, 99, 43, 153, 241, 236, 145, 132, 185, 168, 32, 145, 236, 146, 250, 111, 22, 9, 14, 95, 163, 52, 100, 192, 16, 201, 62, 98, 58],
                expected_signature: vec![48, 74, 48, 5, 6, 3, 43, 101, 112, 3, 65, 0, 40, 140, 38, 241, 254, 10, 159, 193, 167, 209, 223, 22, 32, 55, 44, 214, 141, 85, 199, 79, 191, 72, 254, 170, 175, 226, 71, 40, 88, 75, 238, 129, 211, 153, 211, 50, 207, 216, 137, 146, 146, 17, 92, 42, 55, 122, 27, 221, 198, 236, 229, 77, 78, 222, 210, 85, 177, 80, 6, 139, 169, 223, 154, 10],
            },
        ];

        for test_case in test_cases {
            let keypair = keygen(&test_case.secret_recovery_key, &test_case.session_nonce).unwrap();

            assert_eq!(
                &(keypair.0.to_bytes())[..],
                &test_case.expected_signing_key
            );
            assert_eq!(
                keypair.encoded_verifying_key().to_vec(),
                test_case.expected_verifying_key
            );

            let signature = sign(&keypair, &test_case.message_digest.into()).unwrap();
            assert_eq!(signature, test_case.expected_signature);

            let success = verify(
                &keypair.encoded_verifying_key(),
                &test_case.message_digest.into(),
                &signature,
            )
            .unwrap();
            assert!(success);
        }
    }
}
