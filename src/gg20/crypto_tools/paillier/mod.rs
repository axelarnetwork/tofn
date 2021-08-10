//! A centralized wrapper for rust-paillier:
//! * tidy some API ergonomics in rust-paillier
//! * facilitate easy swap-out of rust-paillier crate for something else

use paillier::{
    Add, BigInt, Decrypt, EncryptWithChosenRandomness, KeyGeneration, Mul, Open, Paillier,
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

pub mod zk;

/// unsafe because key pair does not use safe primes
pub fn keygen_unsafe(rng: &mut (impl CryptoRng + RngCore)) -> (EncryptionKey, DecryptionKey) {
    let (ek, dk) = Paillier::keypair(rng).keys();
    (EncryptionKey(ek), DecryptionKey(dk))
}
pub fn keygen(rng: &mut (impl CryptoRng + RngCore)) -> (EncryptionKey, DecryptionKey) {
    let (ek, dk) = Paillier::keypair_safe_primes(rng).keys();
    (EncryptionKey(ek), DecryptionKey(dk))
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EncryptionKey(paillier::EncryptionKey);

impl EncryptionKey {
    pub fn sample_randomness(&self) -> Randomness {
        Randomness(paillier::Randomness::sample(&self.0).0)
    }
    pub fn random_plaintext(&self) -> Plaintext {
        Plaintext(paillier::Randomness::sample(&self.0).0)
    }
    // TODO how to make `encrypt` generic over `T` where `&T` impls `Into<Plaintext>`?
    // example: https://docs.rs/ecdsa/0.11.1/ecdsa/struct.Signature.html#method.from_scalars
    pub fn encrypt(&self, p: &Plaintext) -> (Ciphertext, Randomness) {
        let r = self.sample_randomness();
        (self.encrypt_with_randomness(p, &r), r)
    }
    pub fn encrypt_with_randomness(&self, p: &Plaintext, r: &Randomness) -> Ciphertext {
        Ciphertext(
            Paillier::encrypt_with_chosen_randomness(
                &self.0,
                paillier::RawPlaintext::from(&p.0),
                &paillier::Randomness::from(&r.0),
            )
            .0
            .into_owned(),
        )
    }
    /// Homomorphically add `c1` to `c2`
    pub fn add(&self, c1: &Ciphertext, c2: &Ciphertext) -> Ciphertext {
        Ciphertext(
            Paillier::add(
                &self.0,
                paillier::RawCiphertext::from(&c1.0),
                paillier::RawCiphertext::from(&c2.0),
            )
            .0
            .into_owned(),
        )
    }

    /// Homomorphically multiply `c` by `p`
    pub fn mul(&self, c: &Ciphertext, p: &Plaintext) -> Ciphertext {
        Ciphertext(
            Paillier::mul(
                &self.0,
                paillier::RawCiphertext::from(&c.0),
                paillier::RawPlaintext::from(&p.0),
            )
            .0
            .into_owned(),
        )
    }
}

// TODO: This might be optimized away since BigInt itself doesn't implement Zeroize
impl Zeroize for EncryptionKey {
    fn zeroize(&mut self) {
        self.0.n = BigInt::zero();
        self.0.nn = BigInt::zero();
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecryptionKey(paillier::DecryptionKey);

impl DecryptionKey {
    pub fn decrypt(&self, c: &Ciphertext) -> Plaintext {
        Plaintext(
            Paillier::decrypt(&self.0, paillier::RawCiphertext::from(&c.0))
                .0
                .into_owned(),
        )
    }
    pub fn decrypt_with_randomness(&self, c: &Ciphertext) -> (Plaintext, Randomness) {
        let (pt, r) = Paillier::open(&self.0, paillier::RawCiphertext::from(&c.0));
        (Plaintext(pt.0.into_owned()), Randomness(r.0))
    }
}

// TODO: This might be optimized away since BigInt itself doesn't implement Zeroize
impl Zeroize for DecryptionKey {
    fn zeroize(&mut self) {
        self.0.p = BigInt::zero();
        self.0.q = BigInt::zero();
    }
}

impl Drop for DecryptionKey {
    fn drop(&mut self) {
        self.zeroize()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Plaintext(paillier::BigInt);

impl Plaintext {
    pub fn to_scalar(&self) -> k256::Scalar {
        to_scalar(&self.0)
    }
    pub fn from_scalar(s: &k256::Scalar) -> Self {
        Self(to_bigint(s))
    }
}

/// prefer `Plaintext` associated functions over `From` impls
/// because my IDE can follow the links
impl From<&Plaintext> for k256::Scalar {
    fn from(p: &Plaintext) -> Self {
        p.to_scalar()
    }
}
impl From<&k256::Scalar> for Plaintext {
    fn from(s: &k256::Scalar) -> Self {
        Plaintext::from_scalar(s)
    }
}

// TODO: This might be optimized away since BigInt itself doesn't implement Zeroize
impl Zeroize for Plaintext {
    fn zeroize(&mut self) {
        self.0 = BigInt::zero();
    }
}

impl Drop for Plaintext {
    fn drop(&mut self) {
        self.zeroize()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Ciphertext(paillier::BigInt);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Randomness(paillier::BigInt);

// TODO: This might be optimized away since BigInt itself doesn't implement Zeroize
impl Zeroize for Randomness {
    fn zeroize(&mut self) {
        self.0 = BigInt::zero();
    }
}

impl Drop for Randomness {
    fn drop(&mut self) {
        self.zeroize()
    }
}

fn to_bigint(s: &k256::Scalar) -> BigInt {
    BigInt::from(s.to_bytes().as_slice())
}

fn to_scalar(bigint: &BigInt) -> k256::Scalar {
    let s = mod_secp256k1(bigint);
    let s_vec = to_vec(&s);
    let s_pad = pad32(s_vec);
    let s_bytes = *k256::FieldBytes::from_slice(&s_pad);
    k256::Scalar::from_bytes_reduced(&s_bytes)
}

fn to_vec(bigint: &BigInt) -> Vec<u8> {
    Vec::<u8>::from(bigint)
}

/// pad `v` with leading zero bytes until it has length 32
/// panics if `v.len()` exceeds 32
fn pad32(v: Vec<u8>) -> Vec<u8> {
    debug_assert!(v.len() <= 32);

    if v.len() == 32 {
        return v;
    }
    let mut v_pad = vec![0; 32];
    v_pad[(32 - v.len())..].copy_from_slice(&v);
    v_pad
}

// The order of the secp256k1 curve
const SECP256K1_CURVE_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// secp256k1 curve order as a `BigInt`
fn secp256k1_modulus() -> BigInt {
    BigInt::from(SECP256K1_CURVE_ORDER.as_ref())
}

/// reduce `n` modulo the order of the secp256k1 curve
fn mod_secp256k1(n: &BigInt) -> BigInt {
    n.modulus(&secp256k1_modulus())
}

#[cfg(feature = "malicious")]
pub mod malicious {
    use super::*;
    impl Plaintext {
        pub fn corrupt(&mut self) {
            self.0 += BigInt::one();
        }
    }
    impl Ciphertext {
        pub fn corrupt(&mut self) {
            self.0 += BigInt::one();
        }
        pub fn corrupt_owned(mut self) -> Self {
            self.corrupt();
            self
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::elliptic_curve::Field;

    #[test]
    fn basic_round_trip() {
        let s = k256::Scalar::random(rand::thread_rng());
        let pt = Plaintext::from_scalar(&s);
        let (ek, dk) = keygen_unsafe(&mut rand::thread_rng());
        let (ct, r) = ek.encrypt(&pt);
        let (pt2, r2) = dk.decrypt_with_randomness(&ct);
        assert_eq!(pt, pt2);
        assert_eq!(r, r2);
        let s2 = pt2.to_scalar();
        assert_eq!(s, s2);
    }

    // TODO test for round trip after homomorphic ops
}
