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
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::gg20::constants;

use super::{member_of_mul_group, NIZKProof};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Zeroize)]
pub struct CompositeDLogStmt {
    pub n: BigNumber,
    pub g: BigNumber,
    pub v: BigNumber,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Zeroize)]
pub struct CompositeDLogProof {
    x: BigNumber,
    y: BigNumber,
}

const CHALLENGE_K: usize = 128;
const SECURITY_PARAM_K_PRIME: usize = 128;
const WITNESS_SIZE: usize = 256;
const R_SIZE: usize = CHALLENGE_K + SECURITY_PARAM_K_PRIME + WITNESS_SIZE;

/// Compute the challenge for the NIZKProof
fn compute_challenge(stmt: &CompositeDLogStmt, domain: &[u8], x: &BigNumber) -> BigNumber {
    BigNumber::from_slice(
        Sha256::new()
            .chain(constants::COMPOSITE_DLOG_PROOF_TAG.to_le_bytes())
            .chain(domain)
            .chain(x.to_bytes())
            .chain(stmt.g.to_bytes())
            .chain(stmt.v.to_bytes()) // TODO: The old code didn't depend on this
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
    pub fn setup(n: &BigNumber, p: &BigNumber, q: &BigNumber) -> (Self, BigNumber) {
        let g = loop {
            let g = BigNumber::random(n);

            if jacobi_symbol(&g, p, q) == -1 {
                break g;
            }
        };

        let S = BigNumber::one() << WITNESS_SIZE;
        let s = BigNumber::random(&S); // TODO: Does negation work for modpow?

        let v = g.modpow(&(-&s), n);

        (Self { n: n.clone(), g, v }, s)
    }
}

impl NIZKProof for CompositeDLogStmt {
    type Witness = BigNumber;
    type Proof = CompositeDLogProof;

    #[allow(non_snake_case)]
    fn prove(&self, wit: &Self::Witness, domain: &[u8]) -> Self::Proof {
        let R = BigNumber::one() << R_SIZE;
        let r = BigNumber::random(&R);
        let x = self.g.modpow(&r, &self.n);

        // TODO: The challenge should only be K bits long. Here we are hashing with SHA256 giving us 256 bits
        let e = compute_challenge(self, domain, &x);

        // y = r + e s
        // This operation is performed over the integers which is
        // simulated with a large enough modulus
        let modulus = R << 1;
        let y = r.modadd(&e.modmul(wit, &modulus), &modulus);

        Self::Proof { x, y }
    }

    fn verify(&self, proof: &Self::Proof, domain: &[u8]) -> bool {
        // Check x is in Z*n and smaller than n
        // TODO: Check that N is positive? and composite?
        if self.n <= BigNumber::zero()
            || self.n.bit_length() < constants::MODULUS_MIN_SIZE
            || self.n.bit_length() > constants::MODULUS_MAX_SIZE
        {
            return false;
        }

        // TODO: Verify the serialization of BigNumber
        if self.n.is_prime() {
            return false;
        }

        // TODO: Check g's order? Should we check if jacobi(g, n) = -1?
        if !member_of_mul_group(&self.g, &self.n) {
            return false;
        }

        if !member_of_mul_group(&self.v, &self.n) {
            return false;
        }

        if !member_of_mul_group(&proof.x, &self.n) {
            return false;
        }

        // TODO: Check that y is not negative?
        if proof.y < BigNumber::zero() || proof.y.bit_length() > R_SIZE + 1 {
            return false;
        }

        let e = compute_challenge(self, domain, &proof.x);

        // g^y v^e mod N
        let g_y_v_e = self
            .g
            .modpow(&proof.y, &self.n)
            .modmul(&self.v.modpow(&e, &self.n), &self.n);

        g_y_v_e == proof.x
    }
}

#[cfg(test)]
mod tests {
    use crate::gg20::crypto_tools::paillier::{keygen_unsafe, zk::NIZKProof};

    use super::CompositeDLogStmt;

    #[test]
    fn basic_correctness() {
        let mut rng = rand::thread_rng();

        let (ek, dk) = keygen_unsafe(&mut rng);

        let (stmt, witness) = CompositeDLogStmt::setup(ek.0.n(), dk.0.p(), dk.0.q());

        let proof = stmt.prove(&witness, &[0_u8]);

        assert!(stmt.verify(&proof, &[0_u8]));
    }
}
