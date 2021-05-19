//! a convenience wrapper for rust-paillier
use paillier::{EncryptWithChosenRandomness, Paillier};
use serde::{Deserialize, Serialize};

pub(crate) fn encrypt(ek: &EncryptionKey, msg: &Plaintext) -> (Ciphertext, Randomness) {
    let r = Randomness(paillier::Randomness::sample(&ek.0).0);
    (encrypt_with_randomness(ek, msg, &r), r)
}

pub(crate) fn encrypt_with_randomness(
    ek: &EncryptionKey,
    msg: &Plaintext,
    r: &Randomness,
) -> Ciphertext {
    Ciphertext(
        Paillier::encrypt_with_chosen_randomness(
            &ek.0,
            paillier::RawPlaintext::from(&msg.0),
            &paillier::Randomness::from(&r.0),
        )
        .0
        .into_owned(),
    )
}

pub(crate) struct EncryptionKey(paillier::EncryptionKey);

// TODO delete this after the k256 migration
impl From<&paillier::EncryptionKey> for EncryptionKey {
    fn from(ek: &paillier::EncryptionKey) -> Self {
        EncryptionKey(ek.clone())
    }
}

pub(crate) struct Plaintext(paillier::BigInt);

impl From<&k256::Scalar> for Plaintext {
    fn from(s: &k256::Scalar) -> Self {
        Plaintext(paillier::BigInt::from(s.to_bytes().as_slice()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Ciphertext(paillier::BigInt);
pub(crate) struct Randomness(paillier::BigInt);
