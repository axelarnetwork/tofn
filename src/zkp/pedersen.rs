use curv::{
    cryptographic_primitives::hashing::{hash_sha256::HSha256, traits::Hash},
    elliptic::curves::traits::{ECPoint, ECScalar},
    FE, GE,
};
use serde::{Deserialize, Serialize};

pub struct Statement<'a> {
    pub commit: &'a GE,
}
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
    let (a, b) = (FE::new_random(), FE::new_random());
    let alpha = commit_with_randomness(&a, &b);
    let c: FE = ECScalar::from(&HSha256::create_hash(&[
        &stmt.commit.bytes_compressed_to_big_int(),
        &alpha.bytes_compressed_to_big_int(),
    ]));
    Proof {
        alpha,
        t: a + c * wit.msg,
        u: b + c * wit.randomness,
    }
}

pub fn verify(stmt: &Statement, proof: &Proof) -> Result<(), &'static str> {
    let c: FE = ECScalar::from(&HSha256::create_hash(&[
        &stmt.commit.bytes_compressed_to_big_int(),
        &proof.alpha.bytes_compressed_to_big_int(),
    ]));
    let lhs = commit_with_randomness(&proof.t, &proof.u);
    let rhs = proof.alpha + stmt.commit * &c;
    if lhs != rhs {
        return Err("verify fail");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{commit, prove, verify, Proof, Statement, Witness};
    use curv::{elliptic::curves::traits::ECScalar, BigInt, FE};

    #[test]
    fn basic_correctness() {
        let msg = &FE::new_random();
        let (commit, randomness) = &commit(msg);
        let stmt = Statement { commit };
        let wit = Witness { msg, randomness };

        // test: valid proof
        let proof = prove(&stmt, &wit);
        verify(&stmt, &proof).unwrap();

        // test: bad proof
        let one: FE = ECScalar::from(&BigInt::from(1));
        let bad_proof = Proof {
            u: proof.u + one,
            ..proof
        };
        verify(&stmt, &bad_proof).unwrap_err();

        // test: bad witness
        let bad_wit = Witness {
            msg: &(*wit.msg + one),
            ..wit
        };
        let bad_proof = prove(&stmt, &bad_wit);
        verify(&stmt, &bad_proof).unwrap_err();
    }
}
