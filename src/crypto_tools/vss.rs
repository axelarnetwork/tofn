//! Helpers for verifiable secret sharing
use crate::{
    crypto_tools::k256_serde,
    sdk::api::{TofnFatal, TofnResult},
};
use k256::elliptic_curve::Field;
use serde::{Deserialize, Serialize};
use tracing::error;
use zeroize::Zeroize;

#[derive(Debug, Zeroize)]
#[zeroize(drop)]
pub struct Vss {
    secret_coeffs: Vec<k256::Scalar>,
}

impl Vss {
    pub fn new(threshold: usize) -> Self {
        let secret_coeffs: Vec<k256::Scalar> = (0..=threshold)
            .map(|_| k256::Scalar::random(rand::thread_rng()))
            .collect();
        Self { secret_coeffs }
    }

    pub fn get_threshold(&self) -> usize {
        self.secret_coeffs.len() - 1
    }

    pub fn get_secret(&self) -> &k256::Scalar {
        &self.secret_coeffs[0]
    }

    pub fn commit(&self) -> Commit {
        Commit {
            coeff_commits: self
                .secret_coeffs
                .iter()
                .map(|coeff| (k256::ProjectivePoint::generator() * coeff).into())
                .collect(),
        }
    }

    pub fn shares(&self, n: usize) -> Vec<Share> {
        debug_assert!(self.get_threshold() < n); // also ensures that n > 0

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
                            acc * index_scalar + coeff
                        })
                        .into(),
                    index,
                }
            })
            .collect()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Commit {
    coeff_commits: Vec<k256_serde::ProjectivePoint>,
}

impl Commit {
    pub fn len(&self) -> usize {
        self.coeff_commits.len()
    }

    pub fn share_commit(&self, index: usize) -> k256::ProjectivePoint {
        let index_scalar = k256::Scalar::from(index as u32 + 1); // vss indices start at 1
        self.coeff_commits
            .iter()
            .rev()
            .fold(k256::ProjectivePoint::identity(), |acc, p| {
                acc * index_scalar + p.as_ref()
            })
    }

    pub fn secret_commit(&self) -> &k256::ProjectivePoint {
        self.coeff_commits[0].as_ref()
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

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct Share {
    scalar: k256_serde::Scalar,
    index: usize,
}

impl Share {
    pub fn from_scalar(scalar: k256::Scalar, index: usize) -> Self {
        Self {
            scalar: scalar.into(),
            index,
        }
    }

    pub fn get_scalar(&self) -> &k256::Scalar {
        self.scalar.as_ref()
    }

    pub fn get_index(&self) -> usize {
        self.index
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ShareCommit {
    index: usize,
    point: k256_serde::ProjectivePoint,
}

impl ShareCommit {
    pub fn from_point(index: usize, point: k256_serde::ProjectivePoint) -> Self {
        Self { point, index }
    }
}

pub fn recover_secret_commit(
    share_commits: &[ShareCommit],
    threshold: usize,
) -> TofnResult<k256::ProjectivePoint> {
    debug_assert!(share_commits.len() > threshold);

    let indices: Vec<usize> = share_commits.iter().map(|s| s.index).collect();
    share_commits.iter().enumerate().try_fold(
        k256::ProjectivePoint::identity(),
        |sum, (i, share_commit)| {
            Ok(sum + share_commit.point.as_ref() * &lagrange_coefficient(i, &indices)?)
        },
    )
}

pub fn lagrange_coefficient(i: usize, indices: &[usize]) -> TofnResult<k256::Scalar> {
    let scalars: Vec<k256::Scalar> = indices
        .iter()
        .map(|&index| k256::Scalar::from(index as u32 + 1))
        .collect();

    let (numerator, denominator) = scalars.iter().enumerate().fold(
        (k256::Scalar::one(), k256::Scalar::one()),
        |(num, den), (j, scalar_j)| {
            if j == i {
                (num, den)
            } else {
                (num * scalar_j, den * (scalar_j - &scalars[i]))
            }
        },
    );

    let den_inv = denominator.invert();

    if bool::from(den_inv.is_none()) {
        error!("Denominator in lagrange coefficient computation is 0");
        return Err(TofnFatal);
    }

    Ok(numerator * den_inv.unwrap())
}

#[cfg(feature = "malicious")]
pub mod malicious {
    use super::*;
    impl Share {
        pub fn corrupt(&mut self) {
            *self.scalar.as_mut() += k256::Scalar::one();
        }
    }
}

#[cfg(test)]
pub(crate) fn recover_secret(shares: &[Share]) -> k256::Scalar {
    let indices: Vec<usize> = shares.iter().map(|s| s.index).collect();
    shares
        .iter()
        .enumerate()
        .fold(k256::Scalar::zero(), |sum, (i, share)| {
            sum + share.scalar.as_ref() * &lagrange_coefficient(i, &indices).unwrap()
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::prelude::SliceRandom;

    #[test]
    fn polynomial_evaluation() {
        // secret polynomial p(x) = 2 + 2x + 2x^2
        let vss = Vss {
            secret_coeffs: vec![
                k256::Scalar::from(2u32),
                k256::Scalar::from(2u32),
                k256::Scalar::from(2u32),
            ],
        };
        let shares = vss.shares(3);
        // expected shares:
        // index: 0, share: p(1) = 6
        // index: 1, share: p(2) = 14
        // index: 2, share: p(3) = 26
        let expected_shares = vec![
            Share {
                scalar: k256::Scalar::from(6u32).into(),
                index: 0,
            },
            Share {
                scalar: k256::Scalar::from(14u32).into(),
                index: 1,
            },
            Share {
                scalar: k256::Scalar::from(26u32).into(),
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
        let commit = vss.commit();
        for s in shares.iter() {
            assert!(commit.validate_share(s));
        }
    }

    impl Vss {
        fn shuffled_shares(&self, n: usize) -> Vec<Share> {
            let mut shares = self.shares(n);
            shares.shuffle(&mut rand::thread_rng());
            shares
        }
    }

    #[test]
    fn secret_recovery() {
        let (t, n) = (2, 5);
        let vss = Vss::new(t);
        let secret = vss.get_secret();
        let shuffled_shares = vss.shuffled_shares(n);
        let recovered_secret = recover_secret(&shuffled_shares);
        assert_eq!(recovered_secret, *secret);

        let secret_commit = *vss.commit().secret_commit();
        let shuffled_share_commits: Vec<ShareCommit> = shuffled_shares
            .iter()
            .map(|share| ShareCommit {
                point: (k256::ProjectivePoint::generator() * share.get_scalar()).into(),
                index: share.get_index(),
            })
            .collect();
        let recovered_secret_commit = recover_secret_commit(&shuffled_share_commits, t).unwrap();
        assert_eq!(recovered_secret_commit, secret_commit);
    }

    #[test]
    fn additive_shares() {
        let (t, s, n) = (2, 4, 6);
        let vss = Vss::new(t);

        // take a random subset of s shares
        let shares: Vec<Share> = vss.shuffled_shares(n).into_iter().take(s).collect();
        let indices: Vec<usize> = shares.iter().map(|share| share.index).collect();

        // convert polynomial shares to additive shares
        let additive_shares: Vec<Share> = shares
            .iter()
            .enumerate()
            .map(|(i, share)| Share {
                scalar: (share.get_scalar() * &lagrange_coefficient(i, &indices).unwrap()).into(),
                ..*share
            })
            .collect();

        let recovered_secret = additive_shares
            .iter()
            .fold(k256::Scalar::zero(), |acc, share| acc + share.get_scalar());
        assert_eq!(recovered_secret, *vss.get_secret());
    }
}
