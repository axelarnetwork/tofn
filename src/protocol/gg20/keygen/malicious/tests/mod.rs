// TODO refactor copied code from sign protocol
use super::Behaviour;
use crate::protocol::{gg20::keygen::Keygen, tests::execute_protocol_vec, Protocol};
use tracing::info;
use tracing_test::traced_test; // enable logs in tests

mod test_cases;
use test_cases::*;

lazy_static::lazy_static! {
    static ref BASIC_CASES: Vec<TestCase> = generate_basic_cases();
}

#[test]
#[traced_test]
fn basic_tests() {
    execute_test_case_list(&BASIC_CASES);
}

fn execute_test_case_list(test_cases: &[test_cases::TestCase]) {
    for t in test_cases {
        info!(
            "share_count [{}] threshold [{}]",
            t.share_count(),
            t.threshold
        );
        let malicious_parties: Vec<(usize, Behaviour)> = t
            .parties
            .iter()
            .enumerate()
            .filter(|(_, p)| !p.behaviour.is_honest())
            .map(|(i, p)| (i, p.behaviour.clone()))
            .collect();
        info!("malicious participants {:?}", malicious_parties);
        execute_test_case(t);
    }
}

fn execute_test_case(t: &test_cases::TestCase) {
    let mut keygen_parties: Vec<Keygen> = t
        .parties
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let mut k = Keygen::new(t.share_count(), t.threshold, i).unwrap();
            k.behaviour = p.behaviour.clone();
            k
        })
        .collect();

    let mut protocols: Vec<&mut dyn Protocol> = keygen_parties
        .iter_mut()
        .map(|p| p as &mut dyn Protocol)
        .collect();

    execute_protocol_vec(&mut protocols, t.allow_self_delivery);

    // TEST: honest parties finished and correctly computed the criminals list
    for keygen_party in keygen_parties.iter().filter(|k| k.behaviour.is_honest()) {
        let output = keygen_party
            .clone_output()
            .unwrap_or_else(|| panic!("honest party {} did not finish", keygen_party.my_index,));
        t.assert_expected_output(&output);
    }
}
