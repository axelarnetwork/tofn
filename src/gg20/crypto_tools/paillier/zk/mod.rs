//! Minimize direct use of paillier, zk_paillier crates
use crate::sdk::api::TofnResult;

use super::{keygen, keygen_unsafe, DecryptionKey, EncryptionKey};
use libpaillier::unknown_order::BigNumber;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

pub(crate) mod mta;
pub(crate) mod range;

mod paillier_key;
mod traits;
pub use traits::*;

mod utils;
use utils::*;

mod composite_dlog;
use composite_dlog::{CompositeDLogProof, CompositeDLogStmt};

pub type EncryptionKeyProof = paillier_key::PaillierKeyProof;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Zeroize)]
pub struct ZkSetup {
    dlog_stmt: CompositeDLogStmt,
}

pub type ZkSetupProof = CompositeDLogProof;

impl ZkSetup {
    pub fn new_unsafe(rng: &mut (impl CryptoRng + RngCore)) -> TofnResult<(ZkSetup, ZkSetupProof)> {
        Ok(Self::from_keypair(keygen_unsafe(rng)?))
    }

    pub fn new(rng: &mut (impl CryptoRng + RngCore)) -> TofnResult<(ZkSetup, ZkSetupProof)> {
        Ok(Self::from_keypair(keygen(rng)?))
    }

    fn from_keypair(
        (ek_tilde, dk_tilde): (EncryptionKey, DecryptionKey),
    ) -> (ZkSetup, ZkSetupProof) {
        let (dlog_stmt, mut witness) =
            CompositeDLogStmt::setup(ek_tilde.0.n(), dk_tilde.0.p(), dk_tilde.0.q());

        let dlog_proof = dlog_stmt.prove(&witness, &[0_u8]); // TODO: Fix the domain

        witness.zeroize();

        (Self { dlog_stmt }, dlog_proof)
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

    fn commit(&self, msg: &BigNumber, randomness: &BigNumber) -> BigNumber {
        let h1_x = self.h1().modpow(msg, self.n_tilde());
        let h2_r = self.h2().modpow(randomness, self.n_tilde());

        h1_x.modmul(&h2_r, self.n_tilde())
    }

    pub fn verify(&self, proof: &ZkSetupProof) -> bool {
        self.dlog_stmt.verify(proof, &[0_u8])
    }
}

impl EncryptionKey {
    pub fn correctness_proof(&self, dk: &DecryptionKey) -> EncryptionKeyProof {
        self.prove(dk, &[0_u8]) // TODO: Fix domain
    }

    pub fn verify_correctness(&self, proof: &EncryptionKeyProof) -> bool {
        self.verify(proof, &[0_u8])
    }
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

/// secp256k1 curve order cubed as a `BigNumber`
fn secp256k1_modulus_cubed() -> BigNumber {
    BigNumber::from_slice(SECP256K1_CURVE_ORDER_CUBED.as_ref())
}

#[cfg(test)]
mod tests {
    use super::secp256k1_modulus_cubed;
    use crate::gg20::crypto_tools::paillier::secp256k1_modulus;

    #[test]
    fn q_cubed() {
        let q = secp256k1_modulus();
        let q3_test = &q * &q * &q;
        let q3 = secp256k1_modulus_cubed();
        assert_eq!(q3_test, q3);
    }
}

#[cfg(feature = "malicious")]
pub mod malicious {
    use super::*;

    pub fn corrupt_zksetup_proof(mut proof: ZkSetupProof) -> ZkSetupProof {
        proof.x += BigNumber::one();
        proof
    }

    pub fn corrupt_ek_proof(mut proof: EncryptionKeyProof) -> EncryptionKeyProof {
        proof.sigmas[0] += BigNumber::one();
        proof
    }
}
