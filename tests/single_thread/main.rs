use execute::*;
use rand::RngCore;
use tofn::{
    protocol::gg20::SecretKeyShare,
    refactor::{
        keygen::{new_keygen, KeygenPartyIndex, KeygenProtocol},
        protocol::Protocol,
    },
    vecmap::{Index, VecMap},
};
// use tracing::{error, info};
use tracing_test::traced_test; // enable logs in tests

/// TODO rename parent dir to `example`
/// TODO clean up
// TODO generic over final output F

#[test]
#[traced_test]
fn main() {
    let (share_count, threshold) = (5, 2);
    let session_nonce = b"foobar";

    let mut parties: VecMap<KeygenPartyIndex, KeygenProtocol> = (0..share_count)
        .map(|index| {
            let mut secret_recovery_key = [0; 64];
            rand::thread_rng().fill_bytes(&mut secret_recovery_key);
            new_keygen(
                share_count,
                threshold,
                Index::from_usize(index),
                &secret_recovery_key,
                session_nonce,
            )
            .expect("`new_keygen` failure")
        })
        .collect();

    parties = execute_protocol(parties);

    let results: Vec<SecretKeyShare> = parties
        .into_iter()
        .map(|(i, party)| match party {
            Protocol::NotDone(_) => panic!("party {} not done yet", i),
            Protocol::Done(result) => result.expect("party finished with error"),
        })
        .collect();

    println!("group info: {:?}", results[0].group);
    for (i, result) in results.iter().enumerate() {
        println!("party {} secret info: {:?}", i, result.share);
    }
}

mod execute;
