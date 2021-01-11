//! Helpers for verifiable secret sharing
//!
//! A quick-and-dirty wrapper to clean up vss code from https://github.com/ZenGo-X/curv/blob/master/src/cryptographic_primitives/secret_sharing/feldman_vss.rs
//!
//! TODO clean up
use curv::{
    cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS,
    elliptic::curves::traits::{ECPoint, ECScalar},
    BigInt,
    ErrorSS::{self, VerifyShareError},
    FE, GE,
};

// wrap VerifiableSS::share to strip out the cruft
pub fn share(t: usize, n: usize, secret: &FE) -> (Vec<GE>, Vec<FE>) {
    let (vss_scheme, secret_shares) = VerifiableSS::share(t, n, secret);
    (vss_scheme.commitments, secret_shares)
}

// The following 3 functions are tweaked from curv library:
// 1. accept &[GE] instead of taking ownership of a Vec<GE>
// 2. satisfy clippy
pub fn validate_share(commitments: &[GE], secret_share: &FE, index: usize) -> Result<(), ErrorSS> {
    let g: GE = ECPoint::generator();
    let ss_point = g * secret_share;
    validate_share_public(commitments, &ss_point, index)
}

pub fn validate_share_public(
    commitments: &[GE],
    ss_point: &GE,
    index: usize,
) -> Result<(), ErrorSS> {
    let comm_to_point = get_point_commitment(commitments, index);
    if *ss_point == comm_to_point {
        Ok(())
    } else {
        Err(VerifyShareError)
    }
}

pub fn get_point_commitment(commitments: &[GE], index: usize) -> GE {
    let index_fe: FE = ECScalar::from(&BigInt::from(index as u32));
    let mut comm_iterator = commitments.iter().rev();
    let head = comm_iterator.next().unwrap();
    let tail = comm_iterator;
    tail.fold(*head, |acc, x: &GE| *x + acc * index_fe)
}
