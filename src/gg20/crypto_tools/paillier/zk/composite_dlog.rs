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

use crate::{
    collections::TypedUsize,
    gg20::{constants, keygen::KeygenPartyId},
};

use super::{member_of_mul_group, NIZKStatement};

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

// The challenge size is likely a conservative choice as opposed to 128.
// This was chosen since we used SHA256 to compute
// the challenge hash which is 256 bits long.
const CHALLENGE_K: usize = 256;
const SECURITY_PARAM_K_PRIME: usize = 128;
const WITNESS_SIZE: usize = 256;
const R_SIZE: usize = CHALLENGE_K + SECURITY_PARAM_K_PRIME + WITNESS_SIZE;

/// Compute the challenge for the NIZKProof
fn compute_challenge(
    stmt: &CompositeDLogStmt,
    prover_id: <CompositeDLogStmt as NIZKStatement>::Domain,
    x: &BigNumber,
) -> BigNumber {
    BigNumber::from_slice(
        Sha256::new()
            .chain(constants::COMPOSITE_DLOG_PROOF_TAG.to_le_bytes())
            .chain(prover_id.to_bytes())
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
    /// Setup the statement for Composite Dlog proof using the modulus `N = pq`
    /// This will generate an asymmetric basis `g` and witness `s` to be used
    /// for the
    pub fn setup(
        rng: &mut (impl CryptoRng + RngCore),
        n: &BigNumber,
        p: &BigNumber,
        q: &BigNumber,
    ) -> (Self, BigNumber) {
        // Sample an asymmetric basis g
        let g = loop {
            let g = BigNumber::random_with_rng(rng, n);

            // g is asymmetric when Jacobi symbol (g | n) = -1
            if jacobi_symbol(&g, p, q) == -1 {
                break g;
            }
        };

        let S = BigNumber::one() << WITNESS_SIZE;
        let s = BigNumber::random_with_rng(rng, &S);

        // v = g^(-s) mod N
        let v = g.modpow(&(-&s), n);

        (Self { n: n.clone(), g, v }, s)
    }
}

impl NIZKStatement for CompositeDLogStmt {
    type Witness = BigNumber;
    type Proof = CompositeDLogProof;
    type Domain = TypedUsize<KeygenPartyId>;

    #[allow(non_snake_case)]
    fn prove(&self, wit: &Self::Witness, domain: Self::Domain) -> Self::Proof {
        let R = BigNumber::one() << R_SIZE;
        let r = BigNumber::random(&R);

        // x = g^r mod N
        let x = self.g.modpow(&r, &self.n);

        let e = compute_challenge(self, domain, &x);

        // y = r + e s
        // This operation is performed over the integers
        let y = r + e * wit;

        Self::Proof { x, y }
    }

    fn verify(&self, proof: &Self::Proof, domain: Self::Domain) -> bool {
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

        if proof.y < BigNumber::zero() || proof.y.bit_length() > R_SIZE + 1 {
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
    use crate::{
        collections::TypedUsize,
        gg20::crypto_tools::paillier::{keygen_unsafe, zk::NIZKStatement},
    };

    use super::{CompositeDLogStmt, WITNESS_SIZE};

    #[test]
    fn basic_correctness() {
        let mut rng = rand::thread_rng();

        let (ek, dk) = keygen_unsafe(&mut rng).unwrap();

        let (stmt, witness) =
            CompositeDLogStmt::setup(&mut rand::thread_rng(), ek.0.n(), dk.0.p(), dk.0.q());

        assert!(witness.bit_length() <= WITNESS_SIZE);

        let proof = stmt.prove(&witness, TypedUsize::from_usize(1));

        assert!(stmt.verify(&proof, TypedUsize::from_usize(1)));

        // Fail to verify a proof with the incorrect domain
        assert!(!stmt.verify(&proof, TypedUsize::from_usize(10)));
    }
}
