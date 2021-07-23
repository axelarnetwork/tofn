//! Minimize direct use of paillier, zk_paillier crates
use super::{keygen_unsafe, BigInt, DecryptionKey, EncryptionKey};
use paillier::zk::{CompositeDLogProof, DLogStatement, NICorrectKeyProof};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;
// use zk_paillier::zkproofs::{CompositeDLogProof, DLogStatement};

pub(crate) mod mta;
pub(crate) mod range;

pub type EncryptionKeyProof = NICorrectKeyProof;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ZkSetup {
    composite_dlog_statement: DLogStatement,
    q_n_tilde: BigInt,
    q3_n_tilde: BigInt,
}

pub type ZkSetupProof = CompositeDLogProof;

// TODO: This might be optimized away since BigInt itself doesn't implement Zeroize
impl Zeroize for ZkSetup {
    fn zeroize(&mut self) {
        self.composite_dlog_statement.N = BigInt::zero();
        self.composite_dlog_statement.g = BigInt::zero();
        self.composite_dlog_statement.ni = BigInt::zero();
        self.q_n_tilde = BigInt::zero();
        self.q3_n_tilde = BigInt::zero();
    }
}

impl ZkSetup {
    pub fn new_unsafe(rng: &mut (impl CryptoRng + RngCore)) -> (ZkSetup, ZkSetupProof) {
        Self::from_keypair(keygen_unsafe(rng))
    }

    fn from_keypair(
        (ek_tilde, dk_tilde): (EncryptionKey, DecryptionKey),
    ) -> (ZkSetup, ZkSetupProof) {
        let one = BigInt::one();
        let s = BigInt::from(2).pow(256_u32);

        // TODO zeroize these secrets after use
        let phi = (&dk_tilde.0.p - &one) * (&dk_tilde.0.q - &one);
        let xhi = random(&s);

        let h1 = random(&phi);
        let h2 = h1.powm(&(-&xhi), &ek_tilde.0.n);

        let dlog_statement = DLogStatement {
            N: ek_tilde.0.n, // n_tilde
            g: h1,           // h1
            ni: h2,          // h2
        };
        let dlog_proof = CompositeDLogProof::prove(&dlog_statement, &xhi);

        let q = super::secp256k1_modulus();
        let q3 = secp256k1_modulus_cubed();
        (
            Self {
                q_n_tilde: q * &dlog_statement.N,
                q3_n_tilde: &q3 * &dlog_statement.N,
                composite_dlog_statement: dlog_statement,
            },
            dlog_proof,
        )
    }

    fn h1(&self) -> &BigInt {
        &self.composite_dlog_statement.g
    }
    fn h2(&self) -> &BigInt {
        &self.composite_dlog_statement.ni
    }
    fn n_tilde(&self) -> &BigInt {
        &self.composite_dlog_statement.N
    }
    fn commit(&self, msg: &BigInt, randomness: &BigInt) -> BigInt {
        let h1_x = self.h1().powm(&msg, self.n_tilde());
        let h2_r = self.h2().powm(&randomness, self.n_tilde());
        mulm(&h1_x, &h2_r, self.n_tilde())
    }

    pub fn verify(&self, proof: &ZkSetupProof) -> bool {
        proof.verify(&self.composite_dlog_statement).is_ok()
    }
}

impl DecryptionKey {
    pub fn correctness_proof(&self) -> EncryptionKeyProof {
        EncryptionKeyProof::proof(&self.0, None)
    }
}

impl EncryptionKey {
    pub fn verify(&self, proof: &EncryptionKeyProof) -> bool {
        proof.verify(&self.0, None).is_ok()
    }
}

// re-implement low-level BigInt functions
// so as to avoid direct dependence on curv

/// return a random BigInt in [0,n)
fn random(n: &BigInt) -> BigInt {
    assert!(*n > BigInt::zero());
    let bit_len = n.bit_length();
    let byte_len = (bit_len - 1) / 8 + 1;
    let mut bytes = vec![0u8; byte_len];
    loop {
        rand::thread_rng().fill_bytes(&mut bytes);
        let candidate = BigInt::from(&*bytes) >> (byte_len * 8 - bit_len);
        if candidate < *n {
            return candidate;
        }
    }
}

/// return x*y mod n
fn mulm(x: &BigInt, y: &BigInt, n: &BigInt) -> BigInt {
    (x.modulus(n) * y.modulus(n)).modulus(n)
}

// The order of the secp256k1 curve raised to exponent 3
const SECP256K1_CURVE_ORDER_CUBED: [u8; 96] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc,
    0x30, 0x0c, 0x96, 0xb4, 0x0d, 0xd9, 0xe0, 0xb3, 0x3f, 0x77, 0x1b, 0xa6, 0x70, 0xa2, 0xc3, 0xc7,
    0xd8, 0x35, 0x56, 0x80, 0x85, 0x53, 0xd3, 0x51, 0xb3, 0xc7, 0xe1, 0xad, 0x13, 0x67, 0x17, 0x4d,
    0x7e, 0xf3, 0x6d, 0x11, 0x11, 0xa6, 0x3c, 0x8c, 0xfd, 0x39, 0x30, 0x75, 0x16, 0xea, 0x33, 0xb3,
    0x46, 0x38, 0x5c, 0x85, 0x02, 0xd9, 0x95, 0x74, 0xd9, 0xef, 0x0f, 0x38, 0x7a, 0x1c, 0xf0, 0x66,
    0x35, 0x52, 0x09, 0x0f, 0xe1, 0xe1, 0x1b, 0x11, 0xeb, 0x69, 0x26, 0xb7, 0x85, 0x7b, 0x73, 0xc1,
];

/// secp256k1 curve order cubed as a `BigInt`
fn secp256k1_modulus_cubed() -> BigInt {
    BigInt::from(SECP256K1_CURVE_ORDER_CUBED.as_ref())
}
#[cfg(test)]
mod tests {
    use super::secp256k1_modulus_cubed;
    use crate::gg20::crypto_tools::paillier::secp256k1_modulus;

    #[test]
    fn q_cubed() {
        let q = secp256k1_modulus();
        let q3_test = q.pow(3);
        let q3 = secp256k1_modulus_cubed();
        assert_eq!(q3_test, q3);
    }
}

#[cfg(feature = "malicious")]
pub mod malicious {
    use super::*;
    pub fn corrupt_zksetup_proof(mut proof: ZkSetupProof) -> ZkSetupProof {
        proof.x += BigInt::one();
        proof
    }
    pub fn corrupt_ek_proof(mut proof: EncryptionKeyProof) -> EncryptionKeyProof {
        proof.sigma_vec[0] += BigInt::one();
        proof
    }
}
