use std::convert::TryFrom;

use tofn::refactor::{
    collections::{FillVecMap, TypedUsize, VecMap},
    keygen::RealKeygenPartyIndex,
    sdk::api::{BytesVec, Fault, PartyShareCounts, Protocol::*, ProtocolOutput},
    sign::malicious::Behaviour::{self, *},
    sign::{
        new_sign, MessageDigest, RealSignParticipantIndex, SignParticipantIndex, SignParties,
        SignProtocol,
    },
};
use tracing::info;
// use tracing_test::traced_test;
// use test_env_log::test;

use crate::{
    common::keygen,
    single_thread::{execute::execute_protocol, set_up_logs},
};

#[test]
// #[traced_test]
fn single_faults() {
    set_up_logs();
    execute_test_case_list(&single_fault_test_case_list())
}

pub fn single_fault_test_case_list() -> Vec<TestCase> {
    let zero = TypedUsize::from_usize(0);
    let three = TypedUsize::from_usize(3);
    vec![
        single_fault_test_case(R1BadProof { victim: zero }),
        single_fault_test_case(R1BadGammaI),
        single_fault_test_case(R2FalseAccusation { victim: zero }),
        single_fault_test_case(R2FalseAccusation { victim: three }), // self accusation
        single_fault_test_case(R2BadMta { victim: zero }),
    ]
}

fn single_fault_test_case(behaviour: Behaviour) -> TestCase {
    // 3 keygen parties: 2,3,4 shares per party
    // 2 sign participants: keygen parties 0,2
    // share 3 (keygen party 2, sign party 1) is malicious
    let (keygen_party_count, sign_party_count) = (3, 2);

    let mut sign_parties = SignParties::with_max_size(keygen_party_count);
    sign_parties.add(TypedUsize::from_usize(0)).unwrap();
    sign_parties.add(TypedUsize::from_usize(2)).unwrap();

    let mut faulters = FillVecMap::with_size(sign_party_count);
    faulters
        .set(TypedUsize::from_usize(1), Fault::ProtocolFault)
        .unwrap();

    TestCase {
        party_share_counts: PartyShareCounts::from_vec(vec![2, 3, 4]).unwrap(),
        threshold: 4,
        sign_parties,
        share_behaviours: VecMap::from_vec(vec![Honest, Honest, Honest, behaviour, Honest, Honest]),
        //                                         ^       ^       ^        ^         ^       ^
        // keygen parties:                      keygen0 keygen0 keygen2  keygen2   keygen2 keygen2
        expected_honest_output: Err(faulters),
    }
}

pub struct TestCase {
    pub party_share_counts: PartyShareCounts<RealKeygenPartyIndex>,
    pub threshold: usize,
    pub sign_parties: SignParties,
    pub share_behaviours: VecMap<SignParticipantIndex, Behaviour>,
    pub expected_honest_output: ProtocolOutput<BytesVec, RealSignParticipantIndex>,
}

impl TestCase {
    pub fn assert_expected_output(
        &self,
        output: &ProtocolOutput<BytesVec, RealSignParticipantIndex>,
    ) {
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
    pub fn initialize_malicious_parties(&self) -> VecMap<SignParticipantIndex, SignProtocol> {
        // generate secret key shares by doing a keygen
        let secret_key_shares = execute_protocol(keygen::initialize_honest_parties(
            &self.party_share_counts,
            self.threshold,
        ))
        .unwrap()
        .map(|output| match output {
            NotDone(_) => panic!("share not done yet"),
            Done(result) => result.expect("share finished with error"),
        });

        // generate sign parties
        info!("keygen done, initiating sign...");
        let keygen_share_ids = VecMap::<SignParticipantIndex, _>::from_vec(
            self.party_share_counts
                .share_id_subset(&self.sign_parties)
                .unwrap(),
        );
        let msg_to_sign = MessageDigest::try_from(&[42; 32][..]).unwrap();
        self.share_behaviours
            .iter()
            .map(|(share_id, behaviour)| {
                let secret_key_share = secret_key_shares
                    .get(*keygen_share_ids.get(share_id).unwrap())
                    .unwrap();
                new_sign(
                    secret_key_share.group(),
                    secret_key_share.share(),
                    &self.sign_parties,
                    &msg_to_sign,
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
            "test: party_share_counts [{:?}], sign participant set {:?}",
            test_case.party_share_counts, test_case.sign_parties
        );

        // print a pretty list of malicious participant shares
        let malicious_share_ids: Vec<(usize, &Behaviour)> = test_case
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
        info!(
            "malicious sign participant share_ids {:?}",
            malicious_share_ids
        );

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
