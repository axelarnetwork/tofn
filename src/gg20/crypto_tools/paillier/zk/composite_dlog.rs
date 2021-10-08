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
    // TODO no need for `pub` if we move things around a bit
    pub n: BigNumber,
    pub g: BigNumber,
    pub v: BigNumber,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Zeroize)]
pub struct CompositeDLogProof {
    x: BigNumber,
    y: BigNumber,
}

pub struct CompositeDLogWitness {
    s: Randomness,
    size: usize,
}

// The challenge size is likely a conservative choice as opposed to 128.
// This was chosen since we used SHA256 to compute
// the challenge hash which is 256 bits long.
const CHALLENGE_K: usize = 256;
const SECURITY_PARAM_K_PRIME: usize = 128;
const S_WITNESS_SIZE: usize = 256;

/// s^-1 is the inverse of the S_WITNESS_SIZE-bit number
/// s modulo phi(N) which is bounded by MODULUS_MAX_SIZE bits,
/// so the size of s^-1 is upto MODULUS_MAX_SIZE bits.
const S_INV_WITNESS_SIZE: usize = MODULUS_MAX_SIZE;

/// `r` masks a witness `s`. `MAX_R_MASK_SIZE` is the size of the largest possible such mask.
const MAX_R_MASK_SIZE: usize = r_mask_size(max(S_WITNESS_SIZE, S_INV_WITNESS_SIZE));

/// The bit length of a mask required to hide a witness whose bit length is `witness_size`.
const fn r_mask_size(witness_size: usize) -> usize {
    CHALLENGE_K + SECURITY_PARAM_K_PRIME + witness_size
}

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

    let e = Randomness((p - 1) >> 1);
    if a.modpow(&e.0, p).is_one() {
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
    /// The first statement returned is for `v = g^(-s)` with witness `s`,
    /// and the second statment returned is for `g = v^(-s^(-1))` with witness `s^(-1)`.
    pub fn setup(
        rng: &mut (impl CryptoRng + RngCore),
        n: &BigNumber,
        p: &BigNumber,
        q: &BigNumber,
        totient: &BigNumber,
    ) -> (Self, CompositeDLogWitness, Self, CompositeDLogWitness) {
        // We sample from S_WITNESS_SIZE - 1 and add a bit at the end to get an invertible element quickly
        let S_div_2 = BigNumber::one() << (S_WITNESS_SIZE - 1);

        loop {
            // Sample an asymmetric basis g
            let g = BigNumber::random_with_rng(rng, n);

            // g is asymmetric when Jacobi symbol (g | n) = -1
            if jacobi_symbol(&g, p, q) != -1 {
                continue;
            }

            // Sample s from {0,..,S-1} such that it is in Z*_phi(N)
            // If p and q are safe primes, then any odd number `s` is invertible with very high probability.
            // If p and q are not safe primes, then this can occur often, and we need to resample.
            let (s, s_inv) = loop {
                let s = Randomness((BigNumber::random_with_rng(rng, &S_div_2) << 1) + 1);

                // Inversion will fail if s is not co-prime to phi(N)
                match s.0.invert(totient) {
                    None => {
                        warn!("cryptographically unreachable (except for unsafe primes): random `s` not in `Z*_phi(n)`. trying again...");
                    }
                    Some(x) => {
                        break (s, Randomness(x));
                    }
                };
            };

            let neg_s = Randomness(-&s.0);

            // v = g^(-s) mod N
            let v = g.modpow(&neg_s.0, n);

            // Check if v is also asymmetric
            if jacobi_symbol(&v, p, q) != -1 {
                continue;
            }

            let s = CompositeDLogWitness {
                s,
                size: S_WITNESS_SIZE,
            };

            // s^-1 mod phi(N) is treated as being sampled from {0,..,2^S_INV_WITNESS_SIZE}
            // and needs to be masked using an appropriately long `r`
            let s_inv = CompositeDLogWitness {
                s: s_inv,
                size: S_INV_WITNESS_SIZE,
            };

            let stmt1 = Self { n: n.clone(), g, v };
            let stmt2 = stmt1.get_inverse_statement();

            return (stmt1, s, stmt2, s_inv);
        }
    }

    /// If the current statement is for `v = g^(-s)` for witness `s`,
    /// return the inverse statement for `g = v^(-s^(-1))` for witness `s^(-1)`.
    /// This is useful to prove that `g` and `v` have the same order.
    pub fn get_inverse_statement(&self) -> Self {
        Self {
            n: self.n.clone(),
            g: self.v.clone(),
            v: self.g.clone(),
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

        let r_size = r_mask_size(wit.size);
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

        if proof.y < BigNumber::zero() || proof.y.bit_length() > MAX_R_MASK_SIZE {
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

/// Apparently I need to roll my own const max fn :(
/// <https://stackoverflow.com/questions/53619695/calculating-maximum-value-of-a-set-of-constant-expressions-at-compile-time>
const fn max(a: usize, b: usize) -> usize {
    [a, b][(a < b) as usize]
}

#[cfg(feature = "malicious")]
pub mod malicious {
    use libpaillier::unknown_order::BigNumber;

    use crate::gg20::crypto_tools::paillier::zk::ZkSetupProof;

    pub fn corrupt_zksetup_proof(mut proof: ZkSetupProof) -> ZkSetupProof {
        proof.dlog_proof1.x += BigNumber::one();
        proof
    }
}

#[cfg(test)]
mod tests {
    use super::{CompositeDLogStmt, NIZKStatement, S_INV_WITNESS_SIZE, S_WITNESS_SIZE};
    use crate::gg20::crypto_tools::paillier::keygen_unsafe;

    #[test]
    fn basic_correctness() {
        let mut rng = rand::thread_rng();

        let (ek, dk) = keygen_unsafe(&mut rng).unwrap();

        let (stmt1, witness1, stmt2, witness2) = CompositeDLogStmt::setup(
            &mut rand::thread_rng(),
            ek.0.n(),
            dk.0.p(),
            dk.0.q(),
            dk.0.totient(),
        );

        assert!(witness1.s.0.bit_length() <= S_WITNESS_SIZE);
        assert!(witness2.s.0.bit_length() <= S_INV_WITNESS_SIZE);

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
