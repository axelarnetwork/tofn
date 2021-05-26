//! Minimize direct use of paillier, zk_paillier crates
use super::{keygen_unsafe, BigInt, DecryptionKey, EncryptionKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zk_paillier::zkproofs::{CompositeDLogProof, DLogStatement};

pub(crate) mod mta;
pub(crate) mod range;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkSetup {
    composite_dlog_statement: DLogStatement,
    composite_dlog_proof: CompositeDLogProof,
    q_n_tilde: BigInt,
    q3_n_tilde: BigInt,
    q3: BigInt, // TODO constant
}

impl ZkSetup {
    pub fn new_unsafe() -> Self {
        Self::from_keypair(keygen_unsafe())
    }

    fn from_keypair((ek_tilde, dk_tilde): (EncryptionKey, DecryptionKey)) -> Self {
        // TODO constants
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
        let q3 = q.pow(3);
        Self {
            q_n_tilde: q * &dlog_statement.N,
            q3_n_tilde: &q3 * &dlog_statement.N,
            q3,
            composite_dlog_statement: dlog_statement,
            composite_dlog_proof: dlog_proof,
        }
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
    // tidied version of commitment_unknown_order from multi_party_ecdsa
    fn commit(&self, msg: &BigInt, randomness: &BigInt) -> BigInt {
        let h1_x = self.h1().powm(&msg, self.n_tilde());
        let h2_r = self.h2().powm(&randomness, self.n_tilde());
        mulm(&h1_x, &h2_r, self.n_tilde())
    }

    pub fn verify_composite_dlog_proof(&self) -> bool {
        self.composite_dlog_proof
            .verify(&self.composite_dlog_statement)
            .is_ok()
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
