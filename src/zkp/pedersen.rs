use curv::{
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
pub struct Proof {}

// commit returns (commitment, randomness)
pub fn commit(msg: &FE) -> (GE, FE) {
    let randomness: FE = ECScalar::new_random();
    (
        (GE::generator() * msg) + (GE::base_point2() * randomness),
        randomness,
    )
}

pub fn prove(stmt: &Statement, wit: &Witness) -> Proof {
    Proof {}
}

pub fn verify(stmt: &Statement, proof: &Proof) -> Result<(), &'static str> {
    todo!()
}
