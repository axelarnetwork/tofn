use serde::{Deserialize, Serialize};
use std::{
    array::TryFromSliceError,
    convert::{TryFrom, TryInto},
};

/// Sign only 32-byte hash digests
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MessageDigest(pub(crate) [u8; 32]);

impl TryFrom<&[u8]> for MessageDigest {
    type Error = TryFromSliceError;
    fn try_from(v: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(v.try_into()?))
    }
}

impl AsRef<[u8]> for MessageDigest {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
