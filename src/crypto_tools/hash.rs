use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::collections::TypedUsize;

// can't derive Serialize, Deserialize for sha3::digest::Output<Sha3_256>
// so use [u8; 32] instead
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Output([u8; 32]);

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct Randomness([u8; 32]);

pub fn commit<K>(tag: u8, peer_id: TypedUsize<K>, msg: impl AsRef<[u8]>) -> (Output, Randomness) {
    let mut randomness = Randomness([0; 32]);
    rand::thread_rng().fill_bytes(&mut randomness.0);
    (
        commit_with_randomness(tag, peer_id, msg, &randomness),
        randomness,
    )
}

pub fn commit_with_randomness<K>(
    tag: u8,
    peer_id: TypedUsize<K>,
    msg: impl AsRef<[u8]>,
    randomness: &Randomness,
) -> Output {
    Output(
        Sha256::new()
            .chain(tag.to_be_bytes())
            .chain(peer_id.to_bytes())
            .chain(msg)
            .chain(randomness.0)
            .finalize()
            .into(),
    )
}

#[cfg(feature = "malicious")]
mod malicious {
    use super::*;
    impl Output {
        pub fn corrupt(mut self) -> Self {
            self.0[0] = self.0[0].wrapping_add(1); // add 1 to the first byte
            self
        }
    }
    impl Randomness {
        pub fn corrupt(&mut self) {
            self.0[0] = self.0[0].wrapping_add(1); // add 1 to the first byte
        }
    }
}
