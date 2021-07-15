#![allow(clippy::result_unit_err)] // TODO idiomatic solution?
use execute::*;
use tofn::{
    refactor::collections::{TypedUsize, VecMap},
    refactor::{
        keygen::{new_keygen, KeygenPartyIndex, KeygenProtocol, SecretKeyShare, SecretRecoveryKey},
        protocol::api::Protocol,
    },
};

use tracing::info;
use tracing_test::traced_test; // enable logs in tests

/// A simple test to illustrate use of the library
/// TODO change file hierarchy
#[test]
#[traced_test]
fn main() {
    let (share_count, threshold) = (5, 2);
    let session_nonce = b"foobar";

    let mut parties: VecMap<KeygenPartyIndex, KeygenProtocol> = (0..share_count)
        .map(|index| {
            let secret_recovery_key: SecretRecoveryKey =
                *b"super secret recovery key whose size measures 64 bytes long, foo";
            new_keygen(
                share_count,
                threshold,
                TypedUsize::from_usize(index),
                &secret_recovery_key,
                session_nonce,
                #[cfg(feature = "malicious")]
                tofn::refactor::keygen::malicious::Behaviour::Honest,
            )
            .expect("`new_keygen` failure")
        })
        .collect();

    parties = execute_protocol(parties).expect("internal tofn error");

    let results: Vec<SecretKeyShare> = parties
        .into_iter()
        .map(|(i, party)| match party {
            Protocol::NotDone(_) => panic!("party {} not done yet", i),
            Protocol::Done(result) => result.expect("party finished with error"),
        })
        .collect();

    info!("group info: {:?}", results[0].group);
    for (i, result) in results.iter().enumerate() {
        info!("party {} secret info: {:?}", i, result.share);
    }
}

mod execute;

#[cfg(feature = "malicious")]
mod malicious;
