use curv::{
    cryptographic_primitives::hashing::{hash_sha256::HSha256, traits::Hash},
    elliptic::curves::traits::{ECPoint, ECScalar},
    BigInt, FE, GE,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug)]
pub struct Statement<'a> {
    pub commit: &'a GE,
}
#[derive(Clone, Debug)]
pub struct Witness<'a> {
    pub msg: &'a FE,
    pub randomness: &'a FE,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    alpha: GE,
    t: FE,
    u: FE,
}

#[derive(Clone, Debug)]
pub struct StatementWc<'a> {
    pub stmt: Statement<'a>,
    pub msg_g: &'a GE,
    pub g: &'a GE,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofWc {
    proof: Proof,
    beta: GE,
}

// commit returns (commitment, randomness)
pub fn commit(msg: &FE) -> (GE, FE) {
    let randomness = FE::new_random();
    (commit_with_randomness(msg, &randomness), randomness)
}
pub fn commit_with_randomness(msg: &FE, randomness: &FE) -> GE {
    (GE::generator() * msg) + (GE::base_point2() * randomness)
}

// statement (commitment), witness (msg, randomness)
//   such that commitment = commit(msg, randomness)
// notation follows section 3.3 of GG20 https://eprint.iacr.org/2020/540.pdf
pub fn prove(stmt: &Statement, wit: &Witness) -> Proof {
    prove_inner(stmt, None, wit).0
}

pub fn verify(stmt: &Statement, proof: &Proof) -> Result<(), &'static str> {
    verify_inner(stmt, proof, None)
}

// statement (msg_g, g, commitment), witness (msg, randomness)
//   such that commitment = commit(msg, randomness)
//   and msg_g = msg * g (this is the additional "check")
// notation follows section 3.3 of GG20 https://eprint.iacr.org/2020/540.pdf
pub fn prove_wc(stmt: &StatementWc, wit: &Witness) -> ProofWc {
    let (proof, beta) = prove_inner(&stmt.stmt, Some((stmt.msg_g, stmt.g)), wit);
    ProofWc {
        proof,
        beta: beta.unwrap(),
    }
}

pub fn verify_wc(stmt: &StatementWc, proof: &ProofWc) -> Result<(), &'static str> {
    verify_inner(
        &stmt.stmt,
        &proof.proof,
        Some((stmt.msg_g, stmt.g, &proof.beta)),
    )
}

fn prove_inner(
    stmt: &Statement,
    msg_g_g: Option<(&GE, &GE)>, // (msg_g, g)
    wit: &Witness,
) -> (Proof, Option<GE>) {
    let (a, b) = (FE::new_random(), FE::new_random());
    let alpha = commit_with_randomness(&a, &b);
    let beta = msg_g_g.map(|(_, g)| g * &a);
    let c: FE = ECScalar::from(&HSha256::create_hash(&[
        &stmt.commit.bytes_compressed_to_big_int(),
        &msg_g_g.map_or(BigInt::zero(), |(msg_g, _)| {
            msg_g.bytes_compressed_to_big_int()
        }),
        &msg_g_g.map_or(BigInt::zero(), |(_, g)| g.bytes_compressed_to_big_int()),
        &alpha.bytes_compressed_to_big_int(),
        &beta.map_or(BigInt::zero(), |beta| beta.bytes_compressed_to_big_int()),
    ]));
    (
        Proof {
            alpha,
            t: a + c * wit.msg,
            u: b + c * wit.randomness,
        },
        beta,
    )
}

fn verify_inner(
    stmt: &Statement,
    proof: &Proof,
    msg_g_g_beta: Option<(&GE, &GE, &GE)>, // (msg_g, g, beta))
) -> Result<(), &'static str> {
    let c: FE = ECScalar::from(&HSha256::create_hash(&[
        &stmt.commit.bytes_compressed_to_big_int(),
        &msg_g_g_beta.map_or(BigInt::zero(), |(msg_g, _, _)| {
            msg_g.bytes_compressed_to_big_int()
        }),
        &msg_g_g_beta.map_or(BigInt::zero(), |(_, g, _)| g.bytes_compressed_to_big_int()),
        &proof.alpha.bytes_compressed_to_big_int(),
        &msg_g_g_beta.map_or(BigInt::zero(), |(_, _, beta)| {
            beta.bytes_compressed_to_big_int()
        }),
    ]));
    if let Some((msg_g, g, beta)) = msg_g_g_beta {
        let lhs = g * &proof.t;
        let rhs = msg_g * &c + beta;
        if lhs != rhs {
            return Err("'wc' check fail");
        }
    }
    let lhs = commit_with_randomness(&proof.t, &proof.u);
    let rhs = proof.alpha + stmt.commit * &c;
    if lhs != rhs {
        return Err("verify fail");
    }
    Ok(())
}

// TODO #[cfg(feature = "malicious")]
pub fn corrupt_proof(proof: &Proof) -> Proof {
    let proof = proof.clone();
    let one: FE = ECScalar::from(&BigInt::from(1));
    Proof {
        u: proof.u + one,
        ..proof
    }
}

// TODO #[cfg(feature = "malicious")]
pub fn corrupt_proof_wc(proof: &ProofWc) -> ProofWc {
    let proof = proof.clone();
    ProofWc {
        beta: proof.beta + GE::generator(),
        ..proof
    }
}

#[cfg(test)]
mod tests {
    use super::{
        commit, corrupt_proof, corrupt_proof_wc, prove, prove_wc, verify, verify_wc, Statement,
        StatementWc, Witness,
    };
    use curv::{
        elliptic::curves::traits::{ECPoint, ECScalar},
        BigInt, FE, GE,
    };

    #[test]
    fn basic_correctness() {
        let msg = &FE::new_random();
        let g = &GE::generator();
        let msg_g = &(g * msg);
        let (commit, randomness) = &commit(msg);

        let stmt_wc = &StatementWc {
            stmt: Statement { commit },
            msg_g,
            g,
        };
        let stmt = &stmt_wc.stmt;
        let wit = &Witness { msg, randomness };

        // test: valid proof
        let proof = prove(stmt, wit);
        verify(&stmt, &proof).unwrap();

        // test: valid proof wc (with check)
        let proof_wc = prove_wc(stmt_wc, wit);
        verify_wc(stmt_wc, &proof_wc).unwrap();

        // test: bad proof
        let bad_proof = corrupt_proof(&proof);
        verify(&stmt, &bad_proof).unwrap_err();

        // test: bad proof wc (with check)
        let bad_proof_wc = corrupt_proof_wc(&proof_wc);
        verify_wc(stmt_wc, &bad_proof_wc).unwrap_err();

        // test: bad witness
        let one: FE = ECScalar::from(&BigInt::from(1));
        let bad_wit = &Witness {
            msg: &(*wit.msg + one),
            ..*wit
        };
        let bad_proof = prove(stmt, bad_wit);
        verify(stmt, &bad_proof).unwrap_err();

        // test: bad witness wc (with check)
        let bad_wit_proof_wc = prove_wc(stmt_wc, bad_wit);
        verify_wc(stmt_wc, &bad_wit_proof_wc).unwrap_err();
    }
}
