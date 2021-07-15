use tofn::refactor::{
    collections::{FillVecMap, TypedUsize, VecMap},
    keygen::{new_keygen, KeygenPartyIndex, KeygenProtocol, SecretRecoveryKey},
    protocol::api::{Fault, Protocol},
};
use tracing::info;
use tracing_test::traced_test; // enable logs in tests

use crate::malicious::execute::{execute_protocol, FaultType, RoundMessage, TestFault};

pub mod execute;
pub mod keygen;

// TODO generalize to arbitrary TestFault
#[test]
#[traced_test]
fn single_bcast_timeout() {
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

    // drop bcast message from `faulty_party` in round 2
    let faulty_party = TypedUsize::from_usize(3);
    let fault = TestFault {
        party: faulty_party,
        round: 2,
        msg: RoundMessage::P2p {
            victim: TypedUsize::from_usize(0),
        },
        fault_type: FaultType::Timeout,
    };

    parties = execute_protocol(parties, &fault).expect("internal tofn error");

    let mut expected_faulters = FillVecMap::with_size(5);
    expected_faulters
        .set(faulty_party, Fault::MissingMessage)
        .unwrap();

    // TEST: honest parties finished and produced the expected output
    for (i, party) in parties.iter() {
        if i != faulty_party {
            let result = match party {
                Protocol::NotDone(_) => panic!("honest party {} not done yet", i),
                Protocol::Done(result) => result,
            };
            match result {
                Ok(_) => panic!("expect failure, got success"),
                Err(got_faulters) => {
                    assert_eq!(*got_faulters, expected_faulters);
                }
            }
        }
    }
}
