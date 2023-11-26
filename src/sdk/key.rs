use std::{
    array::TryFromSliceError,
    convert::{TryFrom, TryInto},
};
use zeroize::Zeroize;

#[derive(Debug, Clone, Zeroize)]
#[zeroize(drop)]
pub struct SecretRecoveryKey(pub(crate) [u8; 64]);

impl TryFrom<&[u8]> for SecretRecoveryKey {
    type Error = TryFromSliceError;

    fn try_from(v: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(v.try_into()?))
    }
}

#[cfg(test)]
/// return the all-zero array with the first bytes set to the bytes of `index`
pub fn dummy_secret_recovery_key(index: usize) -> SecretRecoveryKey {
    let index_bytes = index.to_be_bytes();
    let mut result = [0; 64];
    for (i, &b) in index_bytes.iter().enumerate() {
        result[i] = b;
    }
    SecretRecoveryKey(result)
}
