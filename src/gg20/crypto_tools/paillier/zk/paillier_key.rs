/// We implement the protocol P_square-free from
/// https://eprint.iacr.org/2018/057.pdf
/// described in Section 3.2 to compute a zero-knowledge proof
/// that the Paillier modulus N is co-prime to phi(N)
/// (which also implies that N is square-free).
/// Parameters M = 11, alpha = 6370 have been selected from
/// Section 6.2.3 of https://eprint.iacr.org/2018/987.pdf
use libpaillier::unknown_order::BigNumber;
use serde::{Deserialize, Serialize};
use sha2::digest::*;
use sha3::Shake128;
use tracing::warn;
use zeroize::Zeroize;

use crate::gg20::{
    constants::{MODULUS_MAX_SIZE, MODULUS_MIN_SIZE, PAILLIER_KEY_PROOF_TAG},
    crypto_tools::paillier::{DecryptionKey, EncryptionKey},
};

use super::{member_of_mul_group, NIZKStatement};

/// The product of all primes less than alpha = 6370
const ALPHA_PRIMORIAL_BYTES: &[u8] = &[
    0x4D, 0xDE, 0xC7, 0x72, 0xC2, 0xEE, 0x9F, 0xB1, 0x1E, 0x7B, 0x9E, 0xD0, 0xE5, 0xF6, 0xB7, 0xDE,
    0x5B, 0x83, 0xA0, 0xF2, 0x0C, 0xFA, 0xD9, 0xF3, 0x7E, 0xC2, 0xAD, 0x15, 0x13, 0x41, 0xEB, 0xBE,
    0x75, 0xCB, 0x19, 0x04, 0x41, 0x85, 0x5D, 0x0D, 0x90, 0x14, 0xEF, 0xD6, 0x83, 0x71, 0x6A, 0xC9,
    0x3E, 0x5E, 0x53, 0x69, 0xE8, 0xF7, 0x28, 0x54, 0x97, 0x9E, 0x19, 0x8B, 0xA1, 0x84, 0xAD, 0x4E,
    0x7A, 0x4F, 0xF7, 0x6B, 0x9E, 0xFF, 0x3C, 0xD6, 0x53, 0x3E, 0x8C, 0x5B, 0x2C, 0x2A, 0x5D, 0x8B,
    0xB6, 0x2E, 0xD8, 0x6D, 0x28, 0x0D, 0x2F, 0x0F, 0xA1, 0x66, 0x6A, 0x54, 0x54, 0xD0, 0xE1, 0x0B,
    0x5E, 0x67, 0xC9, 0x6E, 0x80, 0x9F, 0xD3, 0xDA, 0xDD, 0xAB, 0x1F, 0x77, 0xBA, 0x6D, 0x5D, 0xAC,
    0xE6, 0x2A, 0x19, 0x39, 0xD3, 0xC7, 0x29, 0xE9, 0xF1, 0x31, 0xF8, 0x41, 0x90, 0xAA, 0x34, 0x07,
    0xD5, 0xF0, 0x2C, 0xF2, 0x3A, 0x90, 0xA6, 0xC5, 0x0A, 0xCE, 0xFB, 0xD1, 0x23, 0xC6, 0x6C, 0x5C,
    0xC7, 0x8C, 0x93, 0x58, 0x83, 0xC0, 0xCE, 0xE1, 0x43, 0x54, 0x37, 0x81, 0x14, 0x96, 0xB1, 0x0A,
    0x13, 0x90, 0x0F, 0x4F, 0x59, 0x79, 0x4D, 0x67, 0xB4, 0x94, 0xC5, 0x22, 0x79, 0xE3, 0x15, 0x93,
    0x30, 0xF1, 0xD0, 0x76, 0xD6, 0x23, 0xA8, 0xB0, 0xB5, 0x93, 0x22, 0x55, 0x9D, 0x16, 0xC6, 0x8D,
    0xC6, 0xF3, 0xD1, 0xD3, 0x77, 0xA1, 0x66, 0x8B, 0x7F, 0x80, 0xF9, 0x45, 0xE7, 0x40, 0x7C, 0xEE,
    0x35, 0x8E, 0x9A, 0x02, 0xBB, 0x6B, 0x98, 0x3A, 0x56, 0xE3, 0x19, 0x91, 0x56, 0xEB, 0x40, 0x21,
    0x4B, 0x09, 0x8B, 0xF3, 0xD3, 0x01, 0xBD, 0xD1, 0x32, 0x48, 0x7F, 0x13, 0x54, 0xDB, 0x37, 0x71,
    0x88, 0x57, 0x72, 0xF4, 0x9F, 0xE8, 0x6F, 0x88, 0x90, 0x66, 0x8D, 0xFB, 0x5E, 0x5F, 0x9B, 0x1B,
    0x67, 0x74, 0x31, 0x08, 0x18, 0x75, 0xF9, 0x1C, 0xC0, 0x19, 0x46, 0x1B, 0x9C, 0xAE, 0x28, 0x25,
    0x22, 0x6A, 0xE7, 0xFF, 0xE8, 0x70, 0x65, 0x8E, 0x57, 0x34, 0x01, 0x00, 0x5F, 0x33, 0x1D, 0xB9,
    0x9E, 0xB6, 0x6C, 0xA6, 0xC7, 0xFA, 0x31, 0xB6, 0xE2, 0x83, 0x8F, 0x1A, 0x7D, 0xA5, 0x9F, 0xB7,
    0x93, 0x5A, 0x61, 0x9F, 0xFA, 0xB6, 0xD0, 0x58, 0x64, 0x31, 0x99, 0x3B, 0x6A, 0x4C, 0x32, 0x86,
    0x11, 0x41, 0xD3, 0x13, 0x90, 0x15, 0x56, 0x2E, 0xA8, 0x24, 0x55, 0x0E, 0x1A, 0x26, 0xDF, 0xCC,
    0x53, 0x08, 0x5E, 0xBD, 0x08, 0x85, 0x74, 0x28, 0x32, 0xC4, 0x54, 0x2F, 0xC6, 0x43, 0x65, 0x91,
    0xB3, 0xF9, 0x73, 0xD6, 0xF9, 0xCD, 0x72, 0x35, 0x09, 0x47, 0x38, 0x73, 0x4D, 0x08, 0x2E, 0xF5,
    0x1A, 0xF2, 0x98, 0x24, 0x94, 0x08, 0x09, 0xD6, 0x60, 0xC8, 0xD3, 0x22, 0xD4, 0xA4, 0x4F, 0xCF,
    0x43, 0x07, 0x1B, 0x8B, 0x47, 0x3D, 0x12, 0xD3, 0x60, 0x19, 0xFE, 0xE1, 0x10, 0xAA, 0x59, 0xAA,
    0xEE, 0x6A, 0xB7, 0x42, 0x68, 0x89, 0xBF, 0xD0, 0x70, 0x73, 0xD9, 0xCE, 0x03, 0x47, 0x6F, 0xDB,
    0xD0, 0x4C, 0xC6, 0x47, 0x9F, 0x73, 0x50, 0x06, 0x76, 0xF2, 0x83, 0x2C, 0x6A, 0x0A, 0x00, 0xAD,
    0x6C, 0x83, 0x2F, 0x53, 0x09, 0xE9, 0x80, 0x35, 0x98, 0xE4, 0x1F, 0xFB, 0x32, 0x5E, 0x6C, 0x40,
    0x3F, 0x35, 0x73, 0x08, 0x87, 0xEF, 0x0F, 0x6E, 0x5A, 0x91, 0xFD, 0xC1, 0x47, 0xCE, 0x02, 0x2E,
    0xF9, 0xAB, 0x18, 0x51, 0x55, 0x0F, 0x9F, 0xF9, 0x31, 0x15, 0xA6, 0x26, 0xB4, 0xF9, 0xAF, 0x82,
    0xC4, 0xEA, 0xBE, 0xBA, 0xFE, 0x3B, 0x52, 0x38, 0x0D, 0x0F, 0x9F, 0x28, 0xF2, 0xF5, 0x96, 0x16,
    0x89, 0x80, 0x79, 0x34, 0xB9, 0xE5, 0x8D, 0x19, 0x56, 0x31, 0x43, 0x34, 0xDC, 0x71, 0x08, 0x8A,
    0x6B, 0xD9, 0x07, 0x71, 0x2A, 0x38, 0x10, 0x4F, 0xD5, 0xAD, 0x52, 0x3E, 0xFC, 0xB1, 0x0D, 0x02,
    0xC7, 0x6F, 0xDB, 0x84, 0x65, 0x94, 0xE0, 0x94, 0xB3, 0x20, 0x0B, 0x3C, 0x39, 0x56, 0xB1, 0x7D,
    0x2D, 0x55, 0x5B, 0x63, 0x75, 0xC1, 0xC6, 0x5C, 0x3B, 0x19, 0xFE, 0xE9, 0xF1, 0xE8, 0x72, 0x6F,
    0x9F, 0x6F, 0x0C, 0x41, 0x28, 0xF2, 0xDD, 0x4D, 0x5F, 0xDD, 0x7B, 0xE1, 0x26, 0x13, 0x71, 0xBC,
    0x53, 0x8B, 0x20, 0x15, 0xE4, 0xD3, 0xD0, 0xCE, 0x14, 0x7B, 0xCD, 0xC0, 0xCD, 0x56, 0x1D, 0x5F,
    0xE2, 0x1A, 0x9F, 0x0B, 0xF9, 0x1B, 0x58, 0x04, 0xFC, 0xA0, 0xE4, 0x1D, 0x17, 0xF5, 0xE5, 0xBC,
    0x6D, 0x53, 0xE9, 0x42, 0x20, 0xEB, 0xEC, 0x68, 0x16, 0xB0, 0x20, 0x30, 0x6B, 0x7D, 0xBD, 0x9C,
    0x63, 0x20, 0x85, 0x9D, 0xE0, 0x77, 0x1F, 0x89, 0xE7, 0x6C, 0x5A, 0xF8, 0x1F, 0x45, 0xAA, 0x29,
    0x08, 0x6E, 0x82, 0x14, 0x8C, 0xBB, 0xBC, 0x6F, 0xBE, 0x69, 0x92, 0x92, 0x88, 0xDA, 0xA6, 0x40,
    0xBB, 0xB8, 0xD0, 0x1D, 0x99, 0x5E, 0x02, 0x18, 0xB1, 0x2D, 0x70, 0xF8, 0x3B, 0x55, 0x6F, 0x05,
    0x84, 0xFB, 0x17, 0x74, 0x0A, 0x21, 0xF1, 0x2B, 0xBD, 0x78, 0x94, 0x79, 0x0B, 0x7D, 0x4B, 0xBC,
    0x58, 0xF0, 0x18, 0x44, 0xC4, 0x0C, 0xB8, 0x87, 0xE6, 0xD1, 0x81, 0x7E, 0x82, 0x54, 0x24, 0x38,
    0x84, 0xA8, 0x24, 0x43, 0xFC, 0xB9, 0xD9, 0xC9, 0x5E, 0x34, 0x22, 0xE2, 0xA8, 0xB9, 0x81, 0x0C,
    0x13, 0x09, 0xD7, 0x43, 0xE8, 0xFF, 0x2D, 0x82, 0xDE, 0x81, 0x6F, 0xEA, 0x1E, 0x13, 0x74, 0x4A,
    0x40, 0xB5, 0x4D, 0xA0, 0x10, 0x35, 0xE4, 0x26, 0x40, 0x5C, 0xEC, 0xB4, 0xBA, 0x96, 0x0D, 0x60,
    0xCC, 0xB2, 0x52, 0x9A, 0xE6, 0x62, 0x7F, 0x1F, 0xE9, 0x8C, 0xE9, 0x30, 0x7E, 0xAD, 0xAE, 0x3B,
    0x74, 0xF9, 0x0C, 0x57, 0xA6, 0xA6, 0xB0, 0x77, 0x9B, 0xE0, 0xA1, 0xFD, 0x95, 0x3A, 0x78, 0x0C,
    0x46, 0xBA, 0x19, 0xA0, 0x9A, 0x6B, 0xDF, 0xBB, 0x65, 0x9D, 0x42, 0xCB, 0x7E, 0xC1, 0xE9, 0x91,
    0x7D, 0xFB, 0xE7, 0xDA, 0x50, 0x8D, 0xB6, 0x92, 0x4A, 0x0C, 0x99, 0xAC, 0xC7, 0xB3, 0xB4, 0x07,
    0x63, 0xD7, 0x20, 0x7E, 0xBB, 0x07, 0xF2, 0x5F, 0x21, 0xC4, 0x10, 0x72, 0x6E, 0xD1, 0xD0, 0xA1,
    0x24, 0x43, 0x46, 0x68, 0x7B, 0xBB, 0x31, 0x0A, 0x14, 0xA6, 0xA6, 0x8E, 0xDB, 0x38, 0x43, 0x06,
    0x9A, 0x98, 0x76, 0x99, 0xF9, 0xF2, 0x0A, 0x6D, 0xA7, 0x25, 0x76, 0xFA, 0x14, 0xFB, 0xE8, 0xF4,
    0xED, 0x35, 0xA6, 0xCD, 0x84, 0x75, 0xBE, 0xD9, 0xC7, 0x0B, 0x51, 0xA5, 0xFD, 0x99, 0xBB, 0xBE,
    0x1A, 0x2A, 0xB4, 0x3D, 0xF1, 0xE5, 0x1F, 0xDA, 0x1C, 0x70, 0x1E, 0x78, 0x23, 0xDB, 0x06, 0x54,
    0x45, 0x45, 0x75, 0x2B, 0x92, 0x7F, 0x16, 0xFE, 0xF5, 0x8B, 0x11, 0x09, 0xFF, 0x0C, 0x94, 0x5D,
    0xFC, 0xE0, 0xA3, 0xE7, 0x11, 0x18, 0x96, 0xEB, 0x49, 0xB4, 0x70, 0xF3, 0x7A, 0x33, 0x26, 0xF3,
    0xA9, 0x85, 0xB0, 0x0B, 0x74, 0x7B, 0xDC, 0xE7, 0xFB, 0x5F, 0x38, 0x81, 0x2C, 0x29, 0x73, 0xBA,
    0xC4, 0xD7, 0x52, 0x18, 0xE0, 0xFC, 0xB1, 0xBB, 0x8B, 0xE4, 0xEC, 0xDF, 0x09, 0x9F, 0xB0, 0x97,
    0x41, 0xE3, 0x17, 0x1E, 0xF4, 0xEF, 0x3A, 0xC9, 0xF5, 0xA0, 0x5E, 0x4F, 0xA2, 0xBA, 0xA6, 0xB4,
    0x40, 0xC9, 0x9B, 0x43, 0x3C, 0xA9, 0x8A, 0xFC, 0xA7, 0x3B, 0x58, 0xD9, 0xE4, 0x08, 0x8A, 0xAF,
    0xC4, 0xF9, 0x5C, 0x22, 0x77, 0x60, 0x5D, 0x17, 0x24, 0x71, 0xFD, 0x3F, 0x74, 0x53, 0x15, 0xEF,
    0x1A, 0xB8, 0xA1, 0x7B, 0x52, 0xB4, 0x8B, 0xAD, 0x7D, 0x28, 0xB0, 0x80, 0x81, 0x56, 0x0A, 0x6D,
    0x06, 0xFC, 0x55, 0x8C, 0x96, 0xF3, 0xF7, 0x06, 0x94, 0xCE, 0x26, 0xF8, 0x1A, 0x41, 0x78, 0x6B,
    0x12, 0xCF, 0xBD, 0x79, 0xC5, 0xE3, 0xF9, 0x9A, 0x87, 0x9A, 0xDA, 0x2D, 0x4E, 0x79, 0x48, 0x0D,
    0xE1, 0x4E, 0x8B, 0x15, 0x92, 0x47, 0x77, 0x24, 0x6E, 0xF9, 0x0D, 0x21, 0x0B, 0xFE, 0xC6, 0x94,
    0x1A, 0x43, 0x08, 0x27, 0xD0, 0x5A, 0x0A, 0x66, 0xB3, 0xD6, 0xEF, 0x95, 0x52, 0x1F, 0x11, 0x4A,
    0xD7, 0x05, 0x4F, 0x36, 0x97, 0x24, 0xDE, 0x2A, 0xC4, 0x49, 0x76, 0x13, 0x62, 0x85, 0xB6, 0xF9,
    0x93, 0x48, 0xCF, 0xE8, 0x02, 0xCA, 0x6E, 0x70, 0x47, 0x0E, 0x2D, 0x21, 0xB3, 0xF6, 0x64, 0x5E,
    0xB6, 0xA2, 0x3B, 0x0B, 0x98, 0xA1, 0x77, 0x20, 0x1F, 0xA3, 0xFB, 0x87, 0xB8, 0x93, 0x12, 0x24,
    0x7E,
];
/// The number of repetitions of the Zk protocol
const PARAM_M: usize = 11;

pub type PaillierKeyStmt = EncryptionKey;

#[derive(Debug, Default, Clone, Serialize, Deserialize, Zeroize)]
pub struct PaillierKeyProof {
    pub sigmas: [BigNumber; PARAM_M],
}

/// Compute the challenge for the NIZKProof
fn compute_challenge(stmt: &PaillierKeyStmt, iteration: usize, domain: &[u8]) -> BigNumber {
    // We use an XOF (Shake128) to get an n-byte output
    // and reduce it modulo the modulus N
    let hash = Shake128::default()
        .chain(PAILLIER_KEY_PROOF_TAG.to_le_bytes())
        .chain(iteration.to_be_bytes())
        .chain(domain)
        .chain(stmt.0.n().to_bytes());

    let num_bytes = (stmt.0.n().bit_length() + 7) / 8;
    let mut buffer = vec![0; num_bytes];

    hash.finalize_xof().read(&mut buffer);

    let h = BigNumber::from_slice(buffer);

    h.modadd(&BigNumber::zero(), stmt.0.n())
}

impl NIZKStatement for PaillierKeyStmt {
    type Witness = DecryptionKey;
    type Proof = PaillierKeyProof;

    #[allow(non_snake_case)]
    fn prove(&self, wit: &Self::Witness, domain: &[u8]) -> Self::Proof {
        let n_inv = wit.0.n_inv();

        let mut proof = Self::Proof::default();

        for i in 0..PARAM_M {
            let rho = compute_challenge(self, i, domain);

            // sigma = rho^(N^-1 mod phi(N)) mod N
            let sigma = rho.modpow(n_inv, self.0.n());

            proof.sigmas[i] = sigma
        }

        proof
    }

    fn verify(&self, proof: &Self::Proof, domain: &[u8]) -> bool {
        let n = self.0.n();

        // The following checks (except upper-bound checks) on the statements are just for sanity
        // since in GG20, a malicious peer who sent a bad Paillier encryption key
        // is only harming herself as the ciphertexts under her key sent to her by other peers
        // will be compromised.
        if n <= &BigNumber::zero()
            || n.bit_length() < MODULUS_MIN_SIZE
            || n.bit_length() > MODULUS_MAX_SIZE
        {
            return false;
        }

        if n.is_prime() {
            return false;
        }

        // The remaining checks are performed using the Zk proof and are required
        let alpha_primorial = BigNumber::from_slice(ALPHA_PRIMORIAL_BYTES);

        if !n.gcd(&alpha_primorial).is_one() {
            warn!("paillier key proof: small prime factors found, failed to verify");
            return false;
        }

        let verification = proof.sigmas.iter().enumerate().all(|(i, sigma)| {
            if !member_of_mul_group(sigma, n) {
                return false;
            }

            let rho = compute_challenge(self, i, domain);

            let prover_rho = sigma.modpow(n, n);

            if rho == prover_rho {
                true
            } else {
                warn!("paillier key proof: failed to verify proof {}", i);
                false
            }
        });

        verification
    }
}

#[cfg(test)]
mod tests {
    use libpaillier::unknown_order::BigNumber;

    use crate::gg20::crypto_tools::paillier::{keygen_unsafe, zk::NIZKStatement};

    use super::ALPHA_PRIMORIAL_BYTES;

    #[test]
    fn basic_correctness() {
        let mut rng = rand::thread_rng();

        let (ek, dk) = keygen_unsafe(&mut rng).unwrap();

        let domain = &1_u32.to_be_bytes();
        let proof = ek.prove(&dk, domain);

        assert!(ek.verify(&proof, domain));

        // Fail to verify using another domain
        assert!(!ek.verify(&proof, &10_u32.to_be_bytes()));

        let (ek2, _) = keygen_unsafe(&mut rng).unwrap();

        // Fail to verify using another pub key
        assert!(!ek2.verify(&proof, domain));

        let mut proof = proof;
        proof.sigmas[0] += 1;

        // Fail to verify using an invalid proof
        assert!(!ek2.verify(&proof, domain));
    }

    #[test]
    fn test_primorial() {
        let alpha = 6370;
        let mut primorial = BigNumber::one();

        for i in 1..alpha {
            if BigNumber::from(i).is_prime() {
                primorial *= i;
            }
        }

        let primorial_from_bytes = BigNumber::from_slice(ALPHA_PRIMORIAL_BYTES);

        assert_eq!(primorial, primorial_from_bytes);
    }
}
