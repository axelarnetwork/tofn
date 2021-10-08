/// We implement Girault's identification scheme (Fig. 1, Pg 6.) as described in
/// https://www.di.ens.fr/david.pointcheval/Documents/Papers/2000_pkcA.pdf
/// which provides Witness-Indistinguishability proof of knowledge
/// of discrete log for a composite modulus.
///
/// Parameters are chosen based on Theorem 5 on Pg.6.
/// Since we target security of 128 bits, K = K' = 128, S = 256
///
/// Assumptions:
/// 1. N is a 2^k-strong modulus, which means that
///    for N = p q, there is no prime factor less than 2^k
///    that divides (p - 1)/2 or (q - 1)/2.
///    Since we choose safe primes p and q, this is trivially satisfied.
/// 2. g is an asymmetric basis, which means that
///    g is a quadratic residue for only one of Z_p or Z_q,
///    i.e Jacobi symbol (g | n) = (g | p) (g | q) = -1
use libpaillier::unknown_order::BigNumber;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::warn;
use zeroize::Zeroize;

use crate::gg20::crypto_tools::{
    constants::{self, MODULUS_MAX_SIZE},
    paillier::Randomness,
};

use super::{super::utils::member_of_mul_group, NIZKStatement};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Zeroize)]
pub struct CompositeDLogStmt {
    pub n: BigNumber,
    pub g: BigNumber,
    pub v: BigNumber,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Zeroize)]
pub struct CompositeDLogProof {
    pub(crate) x: BigNumber,
    pub(crate) y: BigNumber,
}

pub struct CompositeDLogWitness {
    pub(crate) s: Randomness,
    pub(crate) size: usize,
}

// The challenge size is likely a conservative choice as opposed to 128.
// This was chosen since we used SHA256 to compute
// the challenge hash which is 256 bits long.
const CHALLENGE_K: usize = 256;
const SECURITY_PARAM_K_PRIME: usize = 128;
const WITNESS_SIZE: usize = 256;
/// The max witness size is `max(witness_size, modulus_max_size) = modulus_max_size`
const MAX_R_SIZE: usize = CHALLENGE_K + SECURITY_PARAM_K_PRIME + MODULUS_MAX_SIZE;

/// Compute the challenge for the NIZKProof
fn compute_challenge(stmt: &CompositeDLogStmt, domain: &[u8], x: &BigNumber) -> BigNumber {
    BigNumber::from_slice(
        Sha256::new()
            .chain(constants::COMPOSITE_DLOG_PROOF_TAG.to_be_bytes())
            .chain(domain)
            .chain(x.to_bytes())
            .chain(stmt.g.to_bytes())
            .chain(stmt.v.to_bytes())
            .chain(stmt.n.to_bytes())
            .finalize(),
    )
}

/// Compute the Legendre symbol `(a | p) = a^((p-1)/2) mod p`
fn legendre_symbol(a: &BigNumber, p: &BigNumber) -> i32 {
    debug_assert!(a.gcd(p).is_one());

    let e = (p - 1) >> 1;
    if a.modpow(&e, p).is_one() {
        1
    } else {
        -1
    }
}

/// Compute the Jacobi symbol `(a | n) = (a | p) (a | q)` where `n = pq`
fn jacobi_symbol(a: &BigNumber, p: &BigNumber, q: &BigNumber) -> i32 {
    legendre_symbol(a, p) * legendre_symbol(a, q)
}

impl CompositeDLogStmt {
    #[allow(clippy::many_single_char_names, non_snake_case)]
    /// Setup the statement for Composite Dlog proof using the modulus `N = pq`.
    /// This will generate an asymmetric basis `g` and a witness `s` such that
    /// g^(-s) is also asymmetric basis.
    pub fn setup(
        rng: &mut (impl CryptoRng + RngCore),
        n: &BigNumber,
        p: &BigNumber,
        q: &BigNumber,
        totient: &BigNumber,
    ) -> (Self, CompositeDLogWitness, CompositeDLogWitness) {
        let S = BigNumber::one() << WITNESS_SIZE;

        loop {
            // Sample an asymmetric basis g
            let g = BigNumber::random_with_rng(rng, n);

            // g is asymmetric when Jacobi symbol (g | n) = -1
            if jacobi_symbol(&g, p, q) != -1 {
                continue;
            }

            // Sample s from {0,..,S-1} which is in Z*_N~ with high probability
            let s = Randomness::generate_with_rng(rng, &S);
            let neg_s = Randomness(-&s.0);

            // v = g^(-s) mod N
            let v = g.modpow(&neg_s.0, n);

            // Check if v is asymmetric
            if jacobi_symbol(&v, p, q) != -1 {
                continue;
            }

            let s_inv = if let Some(x) = s.0.invert(totient) {
                // s^-1 mod phi(N) is treated as being sampled from {0,..,2^MAX_N_SIZE}
                // and needs to be masked using an appropriately long `r`
                CompositeDLogWitness {
                    s: Randomness(x),
                    size: MODULUS_MAX_SIZE,
                }
            } else {
                continue;
            };

            let s = CompositeDLogWitness {
                s,
                size: WITNESS_SIZE,
            };

            return (Self { n: n.clone(), g, v }, s, s_inv);
        }
    }
}

impl NIZKStatement for CompositeDLogStmt {
    type Witness = CompositeDLogWitness;
    type Proof = CompositeDLogProof;

    #[allow(non_snake_case)]
    fn prove(&self, wit: &Self::Witness, domain: &[u8]) -> Self::Proof {
        // Assume that v = g^(-s) mod N~
        debug_assert!(self.v == self.g.modpow(&(-&wit.s.0), &self.n));

        let r_size = SECURITY_PARAM_K_PRIME + CHALLENGE_K + wit.size;
        let R = BigNumber::one() << r_size;
        let r = Randomness::generate(&R);

        // x = g^r mod N
        let x = self.g.modpow(&r.0, &self.n);

        let e = compute_challenge(self, domain, &x);

        // y = r + e s
        // This operation is performed over the integers (not modulo anything)
        let y = &r.0 + e * &wit.s.0;

        Self::Proof { x, y }
    }

    fn verify(&self, proof: &Self::Proof, domain: &[u8]) -> bool {
        // The following checks (except upper-bound checks) on the statements are just for sanity
        // since in GG20, a malicious peer who sent a bad statement/ZkSetup
        // is only harming herself as the Zk proofs that use this modulus
        // won't guarantee anything.
        if self.n <= BigNumber::zero()
            || self.n.bit_length() < constants::MODULUS_MIN_SIZE
            || self.n.bit_length() > constants::MODULUS_MAX_SIZE
        {
            return false;
        }

        if self.n.is_prime() {
            return false;
        }

        // Note that we don't perform the sanity check that
        // g is an asymmetric basis
        if !member_of_mul_group(&self.g, &self.n) {
            return false;
        }

        if !member_of_mul_group(&self.v, &self.n) {
            return false;
        }

        // The remaining checks are performed using the Zk proof and are required
        if !member_of_mul_group(&proof.x, &self.n) {
            return false;
        }

        if proof.y < BigNumber::zero() || proof.y.bit_length() > MAX_R_SIZE {
            warn!("composite dlog proof: y out of allowed bounds");
            return false;
        }

        let e = compute_challenge(self, domain, &proof.x);

        // g^y v^e mod N
        let g_y_v_e = self
            .g
            .modpow(&proof.y, &self.n)
            .modmul(&self.v.modpow(&e, &self.n), &self.n);

        if g_y_v_e == proof.x {
            true
        } else {
            warn!("composite dlog proof: failed to verify");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::gg20::crypto_tools::{
        constants::MODULUS_MAX_SIZE,
        paillier::{keygen_unsafe, zk::NIZKStatement},
    };

    use super::{CompositeDLogStmt, WITNESS_SIZE};

    #[test]
    fn basic_correctness() {
        let mut rng = rand::thread_rng();

        let (ek, dk) = keygen_unsafe(&mut rng).unwrap();

        let (stmt1, witness1, witness2) = CompositeDLogStmt::setup(
            &mut rand::thread_rng(),
            ek.0.n(),
            dk.0.p(),
            dk.0.q(),
            dk.0.totient(),
        );

        let stmt2 = CompositeDLogStmt {
            n: stmt1.n.clone(),
            g: stmt1.v.clone(),
            v: stmt1.g.clone(),
        };

        assert!(witness1.s.0.bit_length() <= WITNESS_SIZE);
        assert!(witness2.s.0.bit_length() <= MODULUS_MAX_SIZE);

        let domain = &1_u32.to_be_bytes();
        let proof1 = stmt1.prove(&witness1, domain);
        let proof2 = stmt2.prove(&witness2, domain);

        assert!(stmt1.verify(&proof1, domain));
        assert!(stmt2.verify(&proof2, domain));

        // Fail to verify a proof with the incorrect domain
        assert!(!stmt1.verify(&proof1, &10_u32.to_be_bytes()));
        assert!(!stmt2.verify(&proof2, &10_u32.to_be_bytes()));

        let mut proof1 = proof1;
        proof1.y -= 1;
        let mut proof2 = proof2;
        proof2.y -= 1;

        // Fail to verify using an invalid proof
        assert!(!stmt1.verify(&proof1, domain));
        assert!(!stmt2.verify(&proof2, domain));
    }
}
