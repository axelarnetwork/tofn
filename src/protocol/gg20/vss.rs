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

// The following functions are tweaked from curv library:
// 1. accept &[T] instead of taking ownership of a Vec<T>
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
    let index_fe: FE = ECScalar::from(&BigInt::from(index as u32 + 1)); // vss indices start at 1
    let mut comm_iterator = commitments.iter().rev();
    let head = comm_iterator.next().unwrap();
    let tail = comm_iterator;
    tail.fold(*head, |acc, x: &GE| *x + acc * index_fe)
}

// compute \lambda_{index,S}, a lagrangian coefficient that change the (t,n) scheme to (|S|,|S|)
// was: curv::map_share_to_new_params
// TODO: lots of unnecessary BigInts, no need for share_count argument
pub fn lagrangian_coefficient(share_count: usize, index: usize, s: &[usize]) -> FE {
    let s_len = s.len();
    //     assert!(s_len > self.reconstruct_limit());
    // add one to indices to get points
    let points: Vec<FE> = (0..share_count)
        .map(|i| {
            let index_bn = BigInt::from(i as u32 + 1 as u32);
            ECScalar::from(&index_bn)
        })
        .collect::<Vec<FE>>();

    let xi = &points[index];
    let num: FE = ECScalar::from(&BigInt::one());
    let denum: FE = ECScalar::from(&BigInt::one());
    let num = (0..s_len).fold(num, |acc, i| {
        if s[i] != index {
            acc * points[s[i]]
        } else {
            acc
        }
    });
    let denum = (0..s_len).fold(denum, |acc, i| {
        if s[i] != index {
            let xj_sub_xi = points[s[i]].sub(&xi.get_element());
            acc * xj_sub_xi
        } else {
            acc
        }
    });
    let denum = denum.invert();
    num * denum
}
