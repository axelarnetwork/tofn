//! Helpers for verifiable secret sharing

use k256::elliptic_curve::Field;
use serde::{Deserialize, Serialize};
use std::ops::{Add, Mul};

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
    // pub fn get_secret_commit(&self) -> &k256::ProjectivePoint {
    //     &self.commit.0[0].unwrap()
    // }
    pub fn get_commit(&self) -> &Commit {
        &self.commit
    }
    pub fn shares(&self, n: usize) -> Vec<Share> {
        assert!(self.get_threshold() < n); // also ensures n > 0
        (1..=n as u32)
            .map(|i| {
                let i_scalar = k256::Scalar::from(i);
                Share(
                    // evaluate the polynomial at i using Horner's method
                    self.secret_coeffs
                        .iter()
                        .rev()
                        .fold(k256::Scalar::one(), |acc, coeff| {
                            acc.mul(&i_scalar).add(coeff)
                        }),
                )
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
                acc.mul(&index_scalar).add(p.unwrap())
            })
    }

    /// Equal to share_commit(0)
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
    pub fn validate_share(&self, share: Share, index: usize) -> bool {
        self.validate_share_commit(&(k256::ProjectivePoint::generator() * share.0), index)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Share(k256::Scalar);

impl Share {
    pub fn unwrap(&self) -> &k256::Scalar {
        &self.0
    }
}

// impl std::ops::Deref for Share {
//     type Target = k256::Scalar;
//     fn deref(&self) -> &Self::Target {
//         &self.0
//     }
// }
