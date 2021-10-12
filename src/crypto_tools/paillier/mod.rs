//! A centralized wrapper for the paillier dependency:
//! It exists for historical reasons:
//! * provide an ergonomic API
//! * facilitate easy swap-out of Paillier back-end

use libpaillier::unknown_order::BigNumber;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::sdk::api::{TofnFatal, TofnResult};

use self::utils::{member_of_mod, member_of_mul_group};

pub mod utils;
pub mod zk;

/// unsafe because key pair does not use safe primes
pub fn keygen_unsafe(
    rng: &mut (impl CryptoRng + RngCore),
) -> TofnResult<(EncryptionKey, DecryptionKey)> {
    let p = BigNumber::prime_with_rng(rng, 1024);
    let q = BigNumber::prime_with_rng(rng, 1024);

    let dk = libpaillier::DecryptionKey::with_safe_primes_unchecked(&p, &q).ok_or(TofnFatal)?;
    let ek = (&dk).into();

    Ok((EncryptionKey(ek), DecryptionKey(dk)))
}

/// Generate a Paillier keypair (using safe primes)
pub fn keygen(rng: &mut (impl CryptoRng + RngCore)) -> TofnResult<(EncryptionKey, DecryptionKey)> {
    let dk = libpaillier::DecryptionKey::with_rng(rng).ok_or(TofnFatal)?;
    let ek = (&dk).into();

    Ok((EncryptionKey(ek), DecryptionKey(dk)))
}

/// Wrapper for a `BigNumber` that is zeroized on drop
#[derive(Debug, Zeroize)]
#[zeroize(drop)]
pub struct SecretNumber(BigNumber);

/// Wrapper for Paillier encryption key
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Zeroize)]
pub struct EncryptionKey(libpaillier::EncryptionKey);

impl EncryptionKey {
    pub fn sample_randomness(&self) -> Randomness {
        Randomness(BigNumber::random(self.0.n()))
    }

    pub fn random_plaintext(&self) -> Plaintext {
        Plaintext(BigNumber::random(self.0.n()))
    }

    /// Validate that the `plaintext` is a valid input to the Paillier encryption key.
    pub fn validate_plaintext(&self, p: &Plaintext) -> bool {
        member_of_mod(&p.0, self.0.n())
    }

    /// Validate that the `ciphertext` is a valid output of the Paillier encryption key.
    pub fn validate_ciphertext(&self, c: &Ciphertext) -> bool {
        member_of_mul_group(&c.0, self.0.nn())
    }

    /// Validate that the `randomness` is a valid input to the Paillier encryption key.
    pub fn validate_randomness(&self, r: &Randomness) -> bool {
        member_of_mul_group(&r.0, self.0.n())
    }

    // TODO how to make `encrypt` generic over `T` where `&T` impls `Into<Plaintext>`?
    // example: https://docs.rs/ecdsa/0.11.1/ecdsa/struct.Signature.html#method.from_scalars
    /// Encrypt a plaintext `p` with the Paillier encryption key.
    pub fn encrypt(&self, p: &Plaintext) -> (Ciphertext, Randomness) {
        // Paillier encryption requires r to be co-prime to N
        // Sampling a random integer mod N has negligible probability of not being co-prime
        let r = self.sample_randomness();

        (self.encrypt_with_randomness(p, &r), r)
    }

    pub fn encrypt_with_randomness(&self, p: &Plaintext, r: &Randomness) -> Ciphertext {
        Ciphertext(self.0.encrypt_with_randomness(&p.0, &r.0))
    }

    /// Homomorphically add `c1` to `c2`
    pub fn add(&self, c1: &Ciphertext, c2: &Ciphertext) -> Ciphertext {
        Ciphertext(self.0.add_unchecked(&c1.0, &c2.0))
    }

    /// Homomorphically multiply `c` by `p`
    pub fn mul(&self, c: &Ciphertext, p: &Plaintext) -> Ciphertext {
        Ciphertext(self.0.mul_unchecked(&c.0, &p.0))
    }
}

/// Wrapper for Paillier decryption key
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Zeroize)]
#[zeroize(drop)]
pub struct DecryptionKey(libpaillier::DecryptionKey);

impl DecryptionKey {
    pub fn decrypt(&self, c: &Ciphertext) -> Plaintext {
        Plaintext(self.0.decrypt_unchecked(&c.0))
    }

    pub fn decrypt_with_randomness(&self, c: &Ciphertext) -> (Plaintext, Randomness) {
        let (m, r) = self.0.decrypt_with_randomness(&c.0);
        (Plaintext(m), Randomness(r))
    }
}

/// Wrapper for Paillier plaintext
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct Plaintext(BigNumber);

impl Plaintext {
    /// Generate a random plaintext in the range [0, n)
    pub fn generate(n: &BigNumber) -> Self {
        Self(BigNumber::random(n))
    }

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

/// Wrapper for Paillier ciphertext
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Ciphertext(libpaillier::Ciphertext);

/// Wrapper for randomness used in Paillier encryption
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct Randomness(BigNumber);

impl Randomness {
    /// Generate a random number in the range `[0, n)`
    pub fn generate(n: &BigNumber) -> Self {
        Self(BigNumber::random(n))
    }

    /// Generate a random number in the range `[0, n)` with the provided `rng`
    pub fn generate_with_rng(rng: &mut (impl CryptoRng + RngCore), n: &BigNumber) -> Self {
        Self(BigNumber::random_with_rng(rng, n))
    }
}

fn to_bigint(s: &k256::Scalar) -> BigNumber {
    BigNumber::from_slice(s.to_bytes().as_slice())
}

fn to_scalar(bigint: &BigNumber) -> k256::Scalar {
    let s = mod_secp256k1(bigint);
    let s_vec = to_vec(&s);
    let s_pad = pad32(s_vec);
    let s_bytes = *k256::FieldBytes::from_slice(&s_pad);
    k256::Scalar::from_bytes_reduced(&s_bytes)
}

fn to_vec(bigint: &BigNumber) -> Vec<u8> {
    bigint.to_bytes()
}

/// pad `v` with leading zero bytes until it has length 32
/// panics if `v.len()` exceeds 32
fn pad32(v: Vec<u8>) -> Vec<u8> {
    debug_assert!(v.len() <= 32);

    if v.len() == 32 {
        return v;
    }

    if v.len() > 32 {
        return v[..32].to_vec();
    }

    let mut v_pad = vec![0; 32];
    v_pad[(32 - v.len())..].copy_from_slice(&v);
    v_pad
}

/// The order of the secp256k1 curve
const SECP256K1_CURVE_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// secp256k1 curve order as a `BigNumber`
fn secp256k1_modulus() -> BigNumber {
    BigNumber::from_slice(SECP256K1_CURVE_ORDER.as_ref())
}

/// reduce `n` modulo the order of the secp256k1 curve
fn mod_secp256k1(n: &BigNumber) -> BigNumber {
    n % &secp256k1_modulus()
}

#[cfg(feature = "malicious")]
pub mod malicious {
    use super::*;

    impl Plaintext {
        pub fn corrupt(&mut self) {
            self.0 += BigNumber::one();
        }

        pub fn corrupt_with(&mut self, offset: &k256::Scalar) {
            self.0 -= to_bigint(offset);
        }
    }

    impl Ciphertext {
        pub fn corrupt(&mut self) {
            self.0 += BigNumber::one();
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
        let (ek, dk) = keygen_unsafe(&mut rand::thread_rng()).unwrap();
        let (ct, r) = ek.encrypt(&pt);
        let (pt2, r2) = dk.decrypt_with_randomness(&ct);
        let s2 = pt2.to_scalar();

        assert_eq!(pt, pt2);
        assert_eq!(r, r2);
        assert_eq!(s, s2);
    }

    #[test]
    fn secp256k1_order() {
        // Test that secp256k1 modulus is the order of the generator
        let g = k256::ProjectivePoint::generator();

        assert_eq!(
            g * to_scalar(&secp256k1_modulus()),
            k256::ProjectivePoint::identity()
        );
    }

    // TODO test for round trip after homomorphic ops
}
