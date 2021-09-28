use tofn::{
    collections::{FillVecMap, TypedUsize, VecMap},
    gg20::keygen::{
        create_party_keypair_and_zksetup_unsafe,
        malicious::Behaviour::{self, *},
        new_keygen, KeygenPartyId, KeygenProtocol, KeygenShareId, SecretKeyShare,
    },
    sdk::api::{Fault, PartyShareCounts, Protocol::*, ProtocolOutput},
};
use tracing::info;

use crate::{
    common::dummy_secret_recovery_key,
    single_thread::{execute::execute_protocol, set_up_logs},
};

#[test]
fn single_faults() {
    set_up_logs();
    execute_test_case_list(&single_fault_test_case_list())
}

pub fn single_fault_test_case_list() -> Vec<TestCase> {
    let zero = TypedUsize::from_usize(0);
    vec![
        single_fault_test_case(R1BadCommit),
        single_fault_test_case(R1BadEncryptionKeyProof),
        single_fault_test_case(R1BadZkSetupProof),
        single_fault_test_case(R2BadShare { victim: zero }),
        single_fault_test_case(R2BadEncryption { victim: zero }),
        single_fault_test_case(R3FalseAccusation { victim: zero }),
        single_fault_test_case(R3BadXIWitness),
    ]
}

fn single_fault_test_case(behaviour: Behaviour) -> TestCase {
    // 2 parties, 2 shares per party
    // share 1 (party 0) is malicious
    let mut faulters = FillVecMap::with_size(2);
    faulters
        .set(TypedUsize::from_usize(0), Fault::ProtocolFault)
        .unwrap();
    TestCase {
        party_share_counts: PartyShareCounts::from_vec(vec![2, 2]).unwrap(),
        threshold: 2,
        share_behaviours: VecMap::from_vec(vec![Honest, behaviour, Honest, Honest]),
        expected_honest_output: Err(faulters),
    }
}

pub struct TestCase {
    pub party_share_counts: PartyShareCounts<KeygenPartyId>,
    pub threshold: usize,
    pub share_behaviours: VecMap<KeygenShareId, Behaviour>,
    pub expected_honest_output: ProtocolOutput<SecretKeyShare, KeygenPartyId>,
}

impl TestCase {
    pub fn assert_expected_output(&self, output: &ProtocolOutput<SecretKeyShare, KeygenPartyId>) {
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
    pub fn initialize_malicious_parties(&self) -> VecMap<KeygenShareId, KeygenProtocol> {
        let session_nonce = b"foobar";
        self.share_behaviours
            .iter()
            .map(|(share_id, behaviour)| {
                let (party_id, subshare_id) = self
                    .party_share_counts
                    .share_to_party_subshare_ids(share_id)
                    .unwrap();

                let party_keygen_data = create_party_keypair_and_zksetup_unsafe(
                    party_id,
                    &dummy_secret_recovery_key(share_id),
                    session_nonce,
                )
                .unwrap();

                new_keygen(
                    self.party_share_counts.clone(),
                    self.threshold,
                    party_id,
                    subshare_id,
                    &party_keygen_data,
                    behaviour.clone(),
                )
                .unwrap()
            })
            .collect()
    }
}

fn execute_test_case_list(test_cases: &[TestCase]) {
    for test_case in test_cases {
        info!(
            "test: party_share_counts [{:?}] threshold [{}]",
            test_case.party_share_counts, test_case.threshold
        );
        // print a pretty list of malicious parties
        let malicious_parties: Vec<(usize, &Behaviour)> = test_case
            .share_behaviours
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

fn execute_test_case(test_case: &TestCase) {
    let mut parties = test_case.initialize_malicious_parties();

    parties = execute_protocol(parties).expect("internal tofn error");

    // TEST: honest parties finished and produced the expected output
    for (index, behaviour) in test_case.share_behaviours.iter() {
        if behaviour.is_honest() {
            match parties.get(index).unwrap() {
                NotDone(_) => panic!("honest party {} not done yet", index),
                Done(output) => test_case.assert_expected_output(output),
            }
        }
    }
}
