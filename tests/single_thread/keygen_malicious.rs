use tofn::{
    refactor::{
        keygen::{
            malicious::Behaviour::{self, *},
            new_keygen_with_behaviour,
            Fault::{self, *},
            KeygenOutput, KeygenPartyIndex, KeygenProtocol, SecretRecoveryKey,
        },
        protocol::Protocol::*,
    },
    vecmap::{Behave, Index, VecMap},
};
use tracing::info;
use tracing_test::traced_test;

use crate::execute::execute_protocol;

#[test]
#[traced_test]
fn single_faults() {
    execute_test_case_list(&single_fault_test_case_list())
}

/// TODO make generic over K, Behaviour, Fault?
pub struct TestCase {
    pub threshold: usize,
    pub behaviours: VecMap<KeygenPartyIndex, Behaviour>,
    pub expected_honest_output: KeygenOutput,
}

impl TestCase {
    pub fn assert_expected_output(&self, output: &KeygenOutput) {
        match output {
            Ok(_) => assert!(
                self.expected_honest_output.is_ok(),
                "expect failure, got success"
            ),
            Err(got_faulters) => {
                if let Err(ref want_faulters) = self.expected_honest_output {
                    assert_eq!(got_faulters, want_faulters);
                } else {
                    panic!("expect success, got failure");
                }
            }
        }
    }
    pub fn share_count(&self) -> usize {
        self.behaviours.len()
    }
}
//     pub(crate) fn assert_expected_waiting_on(&self, output: &[Vec<Crime>]) {
//         let mut expected_output = vec![];
//         for p in &self.parties {
//             expected_output.push(p.expected_crimes.clone());
//         }
//         assert_eq!(output, expected_output);
//     }
//     pub(super) fn share_count(&self) -> usize {
//         self.parties.len()
//     }
// }

pub fn single_fault_test_case_list() -> Vec<TestCase> {
    // let zero = Index::from_usize(0);
    vec![
        single_fault_test_case(R1BadCommit, R3BadReveal),
        single_fault_test_case(R1BadEncryptionKeyProof, R2BadEncryptionKeyProof),
        single_fault_test_case(R1BadZkSetupProof, R2BadZkSetupProof),
        // single_fault_test_case(R2BadShare { victim: zero }, R4FailBadVss { victim: zero }),
    ]
}

fn single_fault_test_case(behaviour: Behaviour, fault: Fault) -> TestCase {
    // 3 parties (threshold 1)
    // party 1 is malicious
    // honest parties should identify party 1 as faulter
    TestCase {
        threshold: 1,
        behaviours: VecMap::from_vec(vec![Honest, behaviour, Honest]),
        expected_honest_output: Err(vec![(Index::from_usize(1), fault)]),
    }
}

/// return the all-zero array with the first bytes set to the bytes of `index`
pub fn dummy_secret_recovery_key<K>(index: Index<K>) -> SecretRecoveryKey
where
    K: Behave,
{
    let index_bytes = index.as_usize().to_be_bytes();
    let mut result = [0; 64];
    for (i, &b) in index_bytes.iter().enumerate() {
        result[i] = b;
    }
    result
}

fn execute_test_case(test_case: &TestCase) {
    let session_nonce = b"keygen malicious test session";

    let mut parties: VecMap<KeygenPartyIndex, KeygenProtocol> = test_case
        .behaviours
        .iter()
        .map(|(index, behaviour)| {
            new_keygen_with_behaviour(
                test_case.share_count(),
                test_case.threshold,
                index,
                &dummy_secret_recovery_key(index),
                session_nonce,
                behaviour.clone(),
            )
            .expect("`new_keygen_with_behaviour` failure")
        })
        .collect();

    parties = execute_protocol(parties);

    // TEST: honest parties finished and correctly computed the criminals list
    for (index, behaviour) in test_case.behaviours.iter() {
        if behaviour.is_honest() {
            match parties.get(index) {
                NotDone(_) => panic!("honest party {} not done yet", index),
                Done(output) => test_case.assert_expected_output(output),
            }
        }
    }
}

fn execute_test_case_list(test_cases: &[TestCase]) {
    for test_case in test_cases {
        info!(
            "share_count [{}] threshold [{}]",
            test_case.share_count(),
            test_case.threshold
        );
        // print a pretty list of malicious parties
        let malicious_parties: Vec<(usize, &Behaviour)> = test_case
            .behaviours
            .iter()
            .filter_map(|(i, b)| {
                if b.is_honest() {
                    None
                } else {
                    Some((i.as_usize(), b))
                }
            })
            .collect();
        info!("malicious participants {:?}", malicious_parties);
        execute_test_case(test_case);
    }
}
