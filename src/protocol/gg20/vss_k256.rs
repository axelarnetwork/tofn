//! Helpers for verifiable secret sharing
use k256::elliptic_curve::Field;
use serde::{Deserialize, Serialize};

use crate::k256_serde;

pub struct Vss {
    secret_coeffs: Vec<k256::Scalar>,
    commit: Commit,
}

impl Vss {
    pub fn new(t: usize) -> Self {
        let secret_coeffs: Vec<k256::Scalar> = (0..=t)
            .map(|_| k256::Scalar::random(rand::thread_rng()))
            .collect();
        let commit = Commit(
            secret_coeffs
                .iter()
                .map(|coeff| (k256::ProjectivePoint::generator() * coeff).into())
                .collect(),
        );
        Self {
            secret_coeffs,
            commit,
        }
    }
    pub fn get_threshold(&self) -> usize {
        self.secret_coeffs.len() - 1
    }
    pub fn get_secret(&self) -> &k256::Scalar {
        &self.secret_coeffs[0]
    }
    pub fn get_secret_commit(&self) -> &k256::ProjectivePoint {
        &self.get_commit().secret_commit()
    }
    pub fn get_commit(&self) -> &Commit {
        &self.commit
    }
    pub fn shares(&self, n: usize) -> Vec<Share> {
        assert!(self.get_threshold() < n); // also ensures n > 0
        (0..n)
            .map(|index| {
                let index_scalar = k256::Scalar::from(index as u32 + 1); // vss indices start at 1
                Share {
                    // evaluate the polynomial at i using Horner's method
                    scalar: self
                        .secret_coeffs
                        .iter()
                        .rev()
                        .fold(k256::Scalar::zero(), |acc, coeff| {
                            acc * &index_scalar + coeff
                        }),
                    index,
                }
            })
            .collect()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Commit(Vec<k256_serde::ProjectivePoint>);

impl Commit {
    pub fn share_commit(&self, index: usize) -> k256::ProjectivePoint {
        let index_scalar = k256::Scalar::from(index as u32 + 1); // vss indices start at 1
        self.0
            .iter()
            .rev()
            .fold(k256::ProjectivePoint::identity(), |acc, p| {
                acc * &index_scalar + p.unwrap()
            })
    }
    pub fn secret_commit(&self) -> &k256::ProjectivePoint {
        &self.0[0].unwrap()
    }
    pub fn validate_share_commit(
        &self,
        share_commit: &k256::ProjectivePoint,
        index: usize,
    ) -> bool {
        self.share_commit(index) == *share_commit
    }
    pub fn validate_share(&self, share: &Share) -> bool {
        self.validate_share_commit(
            &(k256::ProjectivePoint::generator() * share.get_scalar()),
            share.get_index(),
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Share {
    scalar: k256::Scalar,
    index: usize,
}

impl Share {
    pub fn from_scalar(scalar: k256::Scalar, index: usize) -> Self {
        Self { scalar, index }
    }
    pub fn get_scalar(&self) -> &k256::Scalar {
        &self.scalar
    }
    pub fn get_index(&self) -> usize {
        self.index
    }
}

pub fn recover_secret(shares: &[Share], threshold: usize) -> k256::Scalar {
    assert!(shares.len() > threshold);
    let points: Vec<Point> = shares
        .iter()
        .take(threshold + 1)
        .map(|s| Point {
            x: k256::Scalar::from(s.index as u32 + 1), // vss indices start at 1
            y: s.scalar,
        })
        .collect();
    points
        .iter()
        .enumerate()
        .fold(k256::Scalar::zero(), |sum, (i, point_i)| {
            sum + point_i.y * {
                let (numerator, denominator) = points.iter().enumerate().fold(
                    (k256::Scalar::one(), k256::Scalar::one()),
                    |(num, den), (j, point_j)| {
                        if j == i {
                            (num, den)
                        } else {
                            (num * point_j.x, den * (point_j.x - point_i.x))
                        }
                    },
                );
                numerator * denominator.invert().unwrap()
            }
        })
}

struct Point {
    x: k256::Scalar,
    y: k256::Scalar,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::prelude::SliceRandom;

    #[test]
    fn recover_secret_correctness() {
        let (t, n) = (2, 5);
        let vss = Vss::new(t);
        let secret = vss.get_secret();
        let shuffled_shares = {
            let mut shares = vss.shares(n);
            shares.shuffle(&mut rand::thread_rng());
            shares
        };
        let recovered_secret = recover_secret(&shuffled_shares, t);
        assert_eq!(recovered_secret, *secret);
    }

    #[test]
    fn polynomial_evaluation() {
        let vss = Vss {
            secret_coeffs: vec![
                k256::Scalar::from(2u32),
                k256::Scalar::from(2u32),
                k256::Scalar::from(2u32),
            ],
            commit: Commit(Vec::new()), // ignore commit, we are testing only secret_coeffs
        };
        let shares = vss.shares(3);
        let expected_shares = vec![
            Share {
                scalar: k256::Scalar::from(6u32),
                index: 0,
            },
            Share {
                scalar: k256::Scalar::from(14u32),
                index: 1,
            },
            Share {
                scalar: k256::Scalar::from(26u32),
                index: 2,
            },
        ];
        assert_eq!(shares, expected_shares);
    }

    #[test]
    fn share_validation() {
        let (t, n) = (2, 5);
        let vss = Vss::new(t);
        let shares = vss.shares(n);
        let commit = vss.get_commit();
        for s in shares.iter() {
            assert!(commit.validate_share(s));
        }
    }
}
