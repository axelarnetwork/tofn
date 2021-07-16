#![allow(clippy::result_unit_err)] // TODO idiomatic solution?
use execute::*;
use tofn::refactor::{
    collections::VecMap,
    keygen::{KeygenPartyIndex, SecretKeyShare},
    protocol::api::Protocol,
};

use tracing_test::traced_test; // enable logs in tests

/// A simple test to illustrate use of the library
/// TODO change file hierarchy
#[test]
#[traced_test]
fn main() {
    let (share_count, threshold) = (5, 2);

    let mut parties = keygen::initialize_honest_parties(share_count, threshold);

    parties = execute_protocol(parties).expect("internal tofn error");

    let _results: VecMap<KeygenPartyIndex, SecretKeyShare> = parties
        .into_iter()
        .map(|(i, party)| match party {
            Protocol::NotDone(_) => panic!("party {} not done yet", i),
            Protocol::Done(result) => result.expect("party finished with error"),
        })
        .collect();

    // TODO sign something
}

mod keygen {
    use tofn::{
        refactor::collections::{TypedUsize, VecMap},
        refactor::keygen::{new_keygen, KeygenPartyIndex, KeygenProtocol, SecretRecoveryKey},
    };

    #[cfg(feature = "malicious")]
    use tofn::refactor::keygen::malicious::Behaviour;

    pub fn initialize_honest_parties(
        share_count: usize,
        threshold: usize,
    ) -> VecMap<KeygenPartyIndex, KeygenProtocol> {
        let session_nonce = b"foobar";
        (0..share_count)
            .map(|index| {
                let index = TypedUsize::from_usize(index);
                new_keygen(
                    share_count,
                    threshold,
                    index,
                    &dummy_secret_recovery_key(index),
                    session_nonce,
                    #[cfg(feature = "malicious")]
                    Behaviour::Honest,
                )
                .expect("`new_keygen` failure")
            })
            .collect()
    }

    /// return the all-zero array with the first bytes set to the bytes of `index`
    pub fn dummy_secret_recovery_key<K>(index: TypedUsize<K>) -> SecretRecoveryKey {
        let index_bytes = index.as_usize().to_be_bytes();
        let mut result = [0; 64];
        for (i, &b) in index_bytes.iter().enumerate() {
            result[i] = b;
        }
        result
    }
}

mod execute;

#[cfg(feature = "malicious")]
mod malicious;
