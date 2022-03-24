//! Helpers for verifiable secret sharing
use crate::{
    crypto_tools::k256_serde,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Debug, Zeroize)]
#[zeroize(drop)]
pub struct Vss {
    secret_coeffs: Vec<k256::Scalar>,
}

pub type Coefficient = k256::Scalar;
pub type Coefficients = Vec<Coefficient>;

// todo: move this somewhere sensible
#[derive(Debug, Zeroize)]
#[zeroize(drop)]
pub struct Ss {
    secret_coeffs: Coefficients,
}
impl Ss {
    pub fn new_byok(threshold: usize, alice_key: Coefficient) -> Self {
        let secret_coeffs: Coefficients = vec![alice_key]
            .into_iter()
            .chain(
                std::iter::repeat_with(|| {
                    <Coefficient as ecdsa::elliptic_curve::Field>::random(rand::thread_rng())
                })
                .take(threshold),
            )
            .collect();
        Self { secret_coeffs }
    }

    pub fn get_threshold(&self) -> usize {
        self.secret_coeffs.len() - 1
    }

    pub fn _get_secret(&self) -> &Coefficient {
        &self.secret_coeffs[0]
    }

    pub fn shares(&self, n: usize) -> Vec<Share> {
        debug_assert!(self.get_threshold() < n); // also ensures that n > 0

        (0..n)
            .map(|index| {
                let index_scalar = Coefficient::from(index as u32 + 1); // vss indices start at 1
                Share {
                    // evaluate the polynomial at i using Horner's method
                    scalar: self
                        .secret_coeffs
                        .iter()
                        .rev()
                        .fold(Coefficient::zero(), |acc, coeff| acc * index_scalar + coeff)
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
    pub fn from_scalar(scalar: Coefficient, index: usize) -> Self {
        Self {
            scalar: scalar.into(),
            index,
        }
    }

    pub fn get_scalar(&self) -> &Coefficient {
        self.scalar.as_ref()
    }

    pub fn get_index(&self) -> usize {
        self.index
    }
}
