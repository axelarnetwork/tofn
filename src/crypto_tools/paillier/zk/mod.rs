//! Minimize direct use of paillier, zk_paillier crates
use crate::{crypto_tools::constants, sdk::api::TofnResult};

use super::{keygen, keygen_unsafe, DecryptionKey, EncryptionKey, Plaintext, Randomness};
use libpaillier::unknown_order::BigNumber;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

pub(crate) mod mta;
pub(crate) mod range;

mod paillier_key;
mod traits;
pub use traits::*;

mod composite_dlog;
use composite_dlog::{CompositeDLogProof, CompositeDLogStmtBase};

pub type EncryptionKeyProof = paillier_key::PaillierKeyProof;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Zeroize)]
pub struct ZkSetup {
    dlog_stmt: CompositeDLogStmtBase,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkSetupProof {
    dlog_proof: CompositeDLogProof, // This proves existence of dlog of h2 w.r.t h1
    dlog_proof_inv: CompositeDLogProof, // This proves existence of dlog of h1 w.r.t h2
}

/// As per the Appendix, Pg. 25 of GG18 (2019/114) and Pg. 13 of GG20, a different RSA modulus is needed for
/// the ZK proofs used in the protocol. While we don't need a Paillier keypair
/// here, we use the same keygen methods for convenience.
/// According to GG20, each peer (acting as the verifier)
/// can generate these setup parameters, comprised of the RSA modulus `N_tilde`,
/// and group elements `h1`, `h2`, such that the peer proves that the
/// discrete log between `h2` and `h1` exists. Using this setup, all other peers
/// can prove their statements (e.g. range, MtA proofs etc.) as needed in the protocol.
impl ZkSetup {
    pub fn new_unsafe(
        rng: &mut (impl CryptoRng + RngCore),
        domain: &[u8],
    ) -> TofnResult<(ZkSetup, ZkSetupProof)> {
        let keypair = keygen_unsafe(rng)?;
        Ok(Self::from_keypair(rng, keypair, domain))
    }

    pub fn new(
        rng: &mut (impl CryptoRng + RngCore),
        domain: &[u8],
    ) -> TofnResult<(ZkSetup, ZkSetupProof)> {
        let keypair = keygen(rng)?;
        Ok(Self::from_keypair(rng, keypair, domain))
    }

    /// Add a layer of domain separation on the two composite dlog proofs
    fn compute_domain(domain: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut domain1: Vec<u8> = domain.into();
        let mut domain2: Vec<u8> = domain.into();

        domain1.push(constants::COMPOSITE_DLOG_PROOF1);
        domain2.push(constants::COMPOSITE_DLOG_PROOF2);

        (domain1, domain2)
    }

    fn from_keypair(
        rng: &mut (impl CryptoRng + RngCore),
        (ek_tilde, dk_tilde): (EncryptionKey, DecryptionKey),
        domain: &[u8],
    ) -> (ZkSetup, ZkSetupProof) {
        let (dlog_stmt, witness, dlog_stmt_inv, witness_inv) = CompositeDLogStmtBase::setup(
            rng,
            ek_tilde.0.n(),
            dk_tilde.0.p(),
            dk_tilde.0.q(),
            dk_tilde.0.totient(),
        );

        let (domain, domain_inv) = Self::compute_domain(domain);

        // Prove the existence of a dlog for h1 and h2 w.r.t each other
        let zk_setup_proof = ZkSetupProof {
            dlog_proof: dlog_stmt.prove(&witness, &domain[..]),
            dlog_proof_inv: dlog_stmt_inv.prove(&witness_inv, &domain_inv[..]),
        };

        (Self { dlog_stmt }, zk_setup_proof)
    }

    fn h1(&self) -> &BigNumber {
        &self.dlog_stmt.g
    }

    fn h2(&self) -> &BigNumber {
        &self.dlog_stmt.v
    }

    fn n_tilde(&self) -> &BigNumber {
        &self.dlog_stmt.n
    }

    /// Compute the FO commitment, `h1^msg h2^r mod N~`
    fn commit(&self, msg: &Plaintext, randomness: &Randomness) -> BigNumber {
        let h1_x = self.h1().modpow(&msg.0, self.n_tilde());
        let h2_r = self.h2().modpow(&randomness.0, self.n_tilde());

        h1_x.modmul(&h2_r, self.n_tilde())
    }

    pub fn verify(&self, proof: &ZkSetupProof, domain: &[u8]) -> bool {
        let dlog_stmt_inv = self.dlog_stmt.get_inverse_statement();

        let (domain, domain_inv) = Self::compute_domain(domain);

        self.dlog_stmt.verify(&proof.dlog_proof, &domain[..])
            && dlog_stmt_inv.verify(&proof.dlog_proof_inv, &domain_inv[..])
    }
}

impl EncryptionKey {
    pub fn correctness_proof(&self, dk: &DecryptionKey, domain: &[u8]) -> EncryptionKeyProof {
        self.prove(dk, domain)
    }

    pub fn verify_correctness(&self, proof: &EncryptionKeyProof, domain: &[u8]) -> bool {
        self.verify(proof, domain)
    }
}

/// The order of the secp256k1 curve raised to exponent 3
const SECP256K1_CURVE_ORDER_CUBED: [u8; 96] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc,
    0x30, 0x0c, 0x96, 0xb4, 0x0d, 0xd9, 0xe0, 0xb3, 0x3f, 0x77, 0x1b, 0xa6, 0x70, 0xa2, 0xc3, 0xc7,
    0xd8, 0x35, 0x56, 0x80, 0x85, 0x53, 0xd3, 0x51, 0xb3, 0xc7, 0xe1, 0xad, 0x13, 0x67, 0x17, 0x4d,
    0x7e, 0xf3, 0x6d, 0x11, 0x11, 0xa6, 0x3c, 0x8c, 0xfd, 0x39, 0x30, 0x75, 0x16, 0xea, 0x33, 0xb3,
    0x46, 0x38, 0x5c, 0x85, 0x02, 0xd9, 0x95, 0x74, 0xd9, 0xef, 0x0f, 0x38, 0x7a, 0x1c, 0xf0, 0x66,
    0x35, 0x52, 0x09, 0x0f, 0xe1, 0xe1, 0x1b, 0x11, 0xeb, 0x69, 0x26, 0xb7, 0x85, 0x7b, 0x73, 0xc1,
];

/// The order of the secp256k1 curve raised to exponent 2
const SECP256K1_CURVE_ORDER_SQUARED: [u8; 64] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfd,
    0x75, 0x5d, 0xb9, 0xcd, 0x5e, 0x91, 0x40, 0x77, 0x7f, 0xa4, 0xbd, 0x19, 0xa0, 0x6c, 0x82, 0x83,
    0x9d, 0x67, 0x1c, 0xd5, 0x81, 0xc6, 0x9b, 0xc5, 0xe6, 0x97, 0xf5, 0xe4, 0x5b, 0xcd, 0x07, 0xc5,
    0x2e, 0xc3, 0x73, 0xa8, 0xbd, 0xc5, 0x98, 0xb4, 0x49, 0x3f, 0x50, 0xa1, 0x38, 0x0e, 0x12, 0x81,
];

/// secp256k1 curve order cubed as a `BigNumber`
fn secp256k1_modulus_cubed() -> BigNumber {
    BigNumber::from_slice(SECP256K1_CURVE_ORDER_CUBED.as_ref())
}

/// secp256k1 curve order squared as a `BigNumber`
fn secp256k1_modulus_squared() -> BigNumber {
    BigNumber::from_slice(SECP256K1_CURVE_ORDER_SQUARED.as_ref())
}

#[cfg(test)]
mod tests {
    use super::secp256k1_modulus_cubed;
    use crate::crypto_tools::paillier::{secp256k1_modulus, zk::secp256k1_modulus_squared};

    #[test]
    fn q_cubed() {
        let q = secp256k1_modulus();
        let q3_test = &q * &q * &q;
        let q3 = secp256k1_modulus_cubed();
        assert_eq!(q3_test, q3);
    }

    #[test]
    fn q_squared() {
        let q = secp256k1_modulus();
        let q2_test = &q * &q;
        let q2 = secp256k1_modulus_squared();
        assert_eq!(q2_test, q2);
    }
}

#[cfg(feature = "malicious")]
pub mod malicious {
    pub use super::composite_dlog::malicious::corrupt_zksetup_proof;
    pub use super::paillier_key::malicious::corrupt_ek_proof;
}
