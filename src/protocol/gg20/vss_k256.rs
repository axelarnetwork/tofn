//! Helpers for verifiable secret sharing

use k256::elliptic_curve::Field;

pub fn share(
    t: usize,
    n: usize,
    secret: &k256::Scalar,
) -> (Vec<k256::ProjectivePoint>, Vec<k256::Scalar>) {
    // sample a polynomial
    let coeffs: Vec<k256::Scalar> = (0..=t)
        .map(|i| {
            if i == 0 {
                secret.clone()
            } else {
                k256::Scalar::random(rand::thread_rng())
            }
        })
        .collect();

    // compute shares by evaluating the polynomial at 1,..,n
    let shares = (1..=n as u32)
        .map(|i|
        // evaluate the polynomial using Horner's method
        coeffs.iter().rev().fold(k256::Scalar::one(), |acc, coeff| acc.mul(&k256::Scalar::from(i)).add(coeff)))
        .collect();

    // compute commitment
    let commit = coeffs
        .iter()
        .map(|&coeff| k256::ProjectivePoint::generator() * coeff)
        .collect();

    (commit, shares)
}
