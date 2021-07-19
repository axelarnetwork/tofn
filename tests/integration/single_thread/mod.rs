use crate::common::keygen;
use execute::*;
use tofn::refactor::{
    collections::VecMap,
    keygen::{KeygenPartyIndex, SecretKeyShare},
    sdk::{api::Protocol, implementer_api::PartyShareCounts},
};
use tracing_test::traced_test; // enable logs in tests

/// A simple test to illustrate use of the library
/// TODO change file hierarchy
#[test]
#[traced_test]
fn basic_correctness() {
    let party_share_counts = PartyShareCounts::from_vec(vec![1, 2, 3, 4]); // 10 total shares
    let threshold = 5;
    let mut shares = keygen::initialize_honest_parties(&party_share_counts, threshold);

    shares = execute_protocol(shares).expect("internal tofn error");

    let _results: VecMap<KeygenPartyIndex, SecretKeyShare> = shares
        .into_iter()
        .map(|(i, party)| match party {
            Protocol::NotDone(_) => panic!("share_id {} not done yet", i),
            Protocol::Done(result) => result.expect("share finished with error"),
        })
        .collect();

    // TODO sign something
}

mod execute;

#[cfg(feature = "malicious")]
mod malicious;
