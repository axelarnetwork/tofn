//! Helpers for secret sharing
use crate::crypto_tools::k256_serde;
use elliptic_curve::Field;
use serde::{Deserialize, Serialize};
// use tracing::error;
use zeroize::Zeroize;

#[derive(Debug, Zeroize)]
#[zeroize(drop)]
pub struct Ss {
    secret_coeffs: Vec<k256::Scalar>,
}
impl Ss {
    /// Recall that a t-of-n sharing requires t+1 points of a degree t polynomial to recover the secret.
    /// Therefore, select t-1 random coefficients, for a total of t coefficients after including Alice's key.
    pub fn new_byok(threshold: usize, alice_key: k256::Scalar) -> Self {
        let secret_coeffs: Vec<k256::Scalar> = vec![alice_key]
            .into_iter()
            .chain(
                std::iter::repeat_with(|| k256::Scalar::random(rand::thread_rng()))
                    .take(threshold - 1),
            )
            .collect();
        Self { secret_coeffs }
    }

    #[allow(dead_code)]
    pub fn new(threshold: usize) -> Self {
        let secret_coeffs: Vec<k256::Scalar> = (0..=threshold)
            .map(|_| k256::Scalar::random(rand::thread_rng()))
            .collect();
        Self { secret_coeffs }
    }

    pub fn get_threshold(&self) -> usize {
        self.secret_coeffs.len() - 1
    }

    #[allow(dead_code)]
    pub fn get_secret(&self) -> &k256::Scalar{
        &self.secret_coeffs[0]
    }

    pub fn shares(&self, n: usize) -> Vec<Share> {
        debug_assert!(self.get_threshold() < n); // also ensures that n > 0

        (0..n)
            .map(|index| {
                let index_scalar = k256::Scalar::from(index as u32 + 1); // ss indices start at 1
                Share {
                    // evaluate the polynomial at i using Horner's method
                    scalar: self
                        .secret_coeffs
                        .iter()
                        .rev()
                        .fold(k256::Scalar::zero(), |acc, coeff| acc * index_scalar + coeff)
                        .into(),
                    index,
                }
            })
            .collect()
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

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use crate::crypto_tools::vss::{lagrange_coefficient, recover_secret};
    use rand::prelude::SliceRandom;

    #[test]
    fn polynomial_evaluation() {
        // secret polynomial p(x) = 2 + 2x + 2x^2
        let ss = Ss {
            secret_coeffs: vec![
                k256::Scalar::from(2u32),
                k256::Scalar::from(2u32),
                k256::Scalar::from(2u32),
            ],
        };
        let shares = ss.shares(3);
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

    impl Ss {
        fn shuffled_shares(&self, n: usize) -> Vec<Share> {
            let mut shares = self.shares(n);
            shares.shuffle(&mut rand::thread_rng());
            shares
        }
    }

    #[test]
    fn additive_shares() {
        let (t, s, n) = (2, 4, 6);
        let ss = Ss::new(t);

        // take a random subset of s shares
        let shares: Vec<Share> = ss.shuffled_shares(n).into_iter().take(s).collect();
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
        assert_eq!(recovered_secret, *ss.get_secret());
    }
}
