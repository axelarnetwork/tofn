use super::{super::*, *};
use crate::protocol::{
    gg20::keygen::tests::execute_keygen, tests::execute_protocol_vec, CrimeType, Criminal, Protocol,
};
use tracing_test::traced_test; // enable logs in tests

lazy_static::lazy_static! {
    pub static ref ONE_CRIMINAL_TEST_CASES: Vec<OneCrimeTestCase> = vec![
        OneCrimeTestCase{
            share_count: 5,
            threshold: 2,
            participant_indices: vec![4,1,2],
            criminal: 1,
            victim: 0,
        },
        OneCrimeTestCase{
            share_count: 7,
            threshold: 4,
            participant_indices: vec![6,4,2,0,3],
            criminal: 2,
            victim: 4,
        },
    ];
}

pub struct OneCrimeTestCase {
    pub share_count: usize,
    pub threshold: usize,
    pub participant_indices: Vec<usize>,
    pub criminal: usize,
    pub victim: usize,
}

#[test]
#[traced_test]
fn r1_bad_proof() {
    for t in ONE_CRIMINAL_TEST_CASES.iter() {
        malicious_behaviour_protocol(t, true, R1BadProof { victim: t.victim });
        malicious_behaviour_protocol(t, false, R1BadProof { victim: t.victim });
    }
}

#[test]
#[traced_test]
fn r1_false_accusation() {
    for t in ONE_CRIMINAL_TEST_CASES.iter() {
        malicious_behaviour_protocol(t, true, R1FalseAccusation { victim: t.victim });
        malicious_behaviour_protocol(t, false, R1FalseAccusation { victim: t.victim });
    }
}

#[test]
#[traced_test]
fn r2_bad_mta_proof() {
    for t in ONE_CRIMINAL_TEST_CASES.iter() {
        malicious_behaviour_protocol(t, true, R2BadMta { victim: t.victim });
        malicious_behaviour_protocol(t, false, R2BadMta { victim: t.victim });
    }
}

#[test]
#[traced_test]
fn r2_bad_mta_wc_proof() {
    for t in ONE_CRIMINAL_TEST_CASES.iter() {
        malicious_behaviour_protocol(t, true, R2BadMtaWc { victim: t.victim });
        malicious_behaviour_protocol(t, false, R2BadMtaWc { victim: t.victim });
    }
}

#[test]
#[traced_test]
fn r2_false_accusation_mta() {
    for t in ONE_CRIMINAL_TEST_CASES.iter() {
        malicious_behaviour_protocol(t, true, R2FalseAccusationMta { victim: t.victim });
        malicious_behaviour_protocol(t, false, R2FalseAccusationMta { victim: t.victim });
    }
}

#[test]
#[traced_test]
fn r2_false_accusation_mta_wc() {
    for t in ONE_CRIMINAL_TEST_CASES.iter() {
        malicious_behaviour_protocol(t, true, R2FalseAccusationMtaWc { victim: t.victim });
        malicious_behaviour_protocol(t, false, R2FalseAccusationMtaWc { victim: t.victim });
    }
}

#[test]
#[traced_test]
fn r3_bad_proof() {
    for t in ONE_CRIMINAL_TEST_CASES.iter() {
        malicious_behaviour_protocol(t, true, R3BadProof);
        malicious_behaviour_protocol(t, false, R3BadProof);
    }
}

#[test]
#[traced_test]
fn r3_false_accusation() {
    for t in ONE_CRIMINAL_TEST_CASES.iter() {
        malicious_behaviour_protocol(t, true, R3FalseAccusation { victim: t.victim });
        malicious_behaviour_protocol(t, false, R3FalseAccusation { victim: t.victim });
    }
}

#[test]
#[traced_test]
fn r4_bad_reveal() {
    for t in ONE_CRIMINAL_TEST_CASES.iter() {
        malicious_behaviour_protocol(t, true, R4BadReveal);
        malicious_behaviour_protocol(t, false, R4BadReveal);
    }
}

#[test]
#[traced_test]
fn r4_false_accusation() {
    for t in ONE_CRIMINAL_TEST_CASES.iter() {
        malicious_behaviour_protocol(t, true, R4FalseAccusation { victim: t.victim });
        malicious_behaviour_protocol(t, false, R4FalseAccusation { victim: t.victim });
    }
}

#[test]
#[traced_test]
fn r5_bad_proof() {
    for t in ONE_CRIMINAL_TEST_CASES.iter() {
        malicious_behaviour_protocol(t, true, R5BadProof { victim: t.victim });
        malicious_behaviour_protocol(t, false, R5BadProof { victim: t.victim });
    }
}

#[test]
#[traced_test]
fn r5_false_accusation() {
    for t in ONE_CRIMINAL_TEST_CASES.iter() {
        malicious_behaviour_protocol(t, true, R5FalseAccusation { victim: t.victim });
        malicious_behaviour_protocol(t, false, R5FalseAccusation { victim: t.victim });
    }
}

#[test]
#[traced_test]
fn r6_bad_proof() {
    for t in ONE_CRIMINAL_TEST_CASES.iter() {
        malicious_behaviour_protocol(t, true, R6BadProof);
        malicious_behaviour_protocol(t, false, R6BadProof);
    }
}

#[test]
#[traced_test]
fn r6_false_accusation() {
    for t in ONE_CRIMINAL_TEST_CASES.iter() {
        malicious_behaviour_protocol(t, true, R6FalseAccusation { victim: t.victim });
        malicious_behaviour_protocol(t, false, R6FalseAccusation { victim: t.victim });
    }
}

#[test]
#[traced_test]
fn r7_bad_sig_share() {
    for t in ONE_CRIMINAL_TEST_CASES.iter() {
        malicious_behaviour_protocol(t, true, R7BadSigSummand);
        malicious_behaviour_protocol(t, false, R7BadSigSummand);
    }
}

// generic malicious behaviour test
fn malicious_behaviour_protocol(
    t: &OneCrimeTestCase,
    allow_self_delivery: bool,
    malicious_type: MaliciousType,
) {
    assert!(t.participant_indices.len() >= 2);
    let key_shares = execute_keygen(t.share_count, t.threshold);

    let mut bad_guy = BadSign::new(
        &key_shares[t.participant_indices[t.criminal]],
        &t.participant_indices,
        &MESSAGE_TO_SIGN,
        malicious_type,
    )
    .unwrap();

    let mut good_guys: Vec<Sign> = t
        .participant_indices
        .iter()
        .enumerate()
        .filter(|(p, _)| *p != t.criminal)
        .map(|(_, i)| Sign::new(&key_shares[*i], &t.participant_indices, &MESSAGE_TO_SIGN).unwrap())
        .collect();

    let mut protocols: Vec<&mut dyn Protocol> = good_guys
        .iter_mut()
        .map(|p| p as &mut dyn Protocol)
        .collect();
    protocols.insert(t.criminal, &mut bad_guy as &mut dyn Protocol);

    execute_protocol_vec(&mut protocols, allow_self_delivery);

    // TEST: everyone correctly computed the culprit list
    let actual_culprits = vec![Criminal {
        index: t.criminal,
        crime_type: CrimeType::Malicious,
    }];
    assert_eq!(
        bad_guy.clone_output().unwrap().unwrap_err(),
        actual_culprits
    );
    for good_guy in good_guys {
        assert_eq!(
            good_guy.clone_output().unwrap().unwrap_err(),
            actual_culprits
        );
    }
}

use strum::IntoEnumIterator;
// generate simple test cases using strum to iterate malicious types.
// Strum fills all additional data on enum variants with Default::default()
// https://docs.rs/strum_macros/0.20.1/strum_macros/derive.EnumIter.html
// this means that all criminals in these test cases target index 0
fn generate_simple_test_cases() -> Vec<TestCase> {
    let mut test_cases = Vec::new();
    let share_count = 5;
    let threshold = 2;
    let allow_self_delivery = true;
    // skip honest bahaviour
    for malicous_type in MaliciousType::iter().skip(1) {
        test_cases.push(TestCase {
            share_count,
            threshold,
            allow_self_delivery,
            sign_participants: vec![
                SignParticipant {
                    party_index: 1,
                    behaviour: Honest,
                },
                SignParticipant {
                    party_index: 2,
                    behaviour: Honest,
                },
                SignParticipant {
                    party_index: 3,
                    behaviour: malicous_type, // initialize enum values with Default::default()
                },
            ],
            sign_expected_criminals: vec![Criminal {
                index: 2,
                crime_type: CrimeType::Malicious,
            }],
        })
    }
    test_cases
}

// The conention we make is that self-targetting corruptions are skipped
// TODO: Ask @Gus why some FalseAccusations still produce criminals. Is is because they broadcast?
fn generate_self_targetting_signers() -> Vec<TestCase> {
    let self_targetting_types = vec![
        R1BadProof { victim: 2 },
        R1FalseAccusation { victim: 2 },
        R2BadMta { victim: 2 },
        R2BadMtaWc { victim: 2 },
        R2FalseAccusationMta { victim: 2 },
        R2FalseAccusationMtaWc { victim: 2 },
        // R3FalseAccusation { victim: 2 }, // this produces criminals
        // R4FalseAccusation { victim: 2 }, // this produces criminals
        R5BadProof { victim: 2 },
        R5FalseAccusation { victim: 2 },
        // R6FalseAccusation { victim: 2 }, // this produces criminals
    ];

    let mut test_cases = Vec::new();
    let share_count = 5;
    let threshold = 2;
    let allow_self_delivery = true;
    for malicous_type in self_targetting_types {
        test_cases.push(TestCase {
            share_count,
            threshold,
            allow_self_delivery,
            sign_participants: vec![
                SignParticipant {
                    party_index: 1,
                    behaviour: Honest,
                },
                SignParticipant {
                    party_index: 2,
                    behaviour: Honest,
                },
                SignParticipant {
                    party_index: 3,
                    behaviour: malicous_type,
                },
            ],
            sign_expected_criminals: vec![],
        })
    }
    test_cases
}

// TODO: Add more cases here
fn generate_multiple_faults() -> Vec<TestCase> {
    vec![
        TestCase {
            share_count: 5,
            threshold: 2,
            allow_self_delivery: true,
            sign_participants: vec![
                SignParticipant {
                    party_index: 4,
                    behaviour: Honest,
                },
                SignParticipant {
                    party_index: 2,
                    behaviour: Honest,
                },
                SignParticipant {
                    party_index: 1,
                    behaviour: R1BadProof { victim: 0 },
                },
            ],
            sign_expected_criminals: vec![Criminal {
                index: 2,
                crime_type: CrimeType::Malicious,
            }],
        },
        TestCase {
            share_count: 5,
            threshold: 4,
            allow_self_delivery: false,
            sign_participants: vec![
                SignParticipant {
                    party_index: 0,
                    behaviour: Honest,
                },
                SignParticipant {
                    party_index: 1,
                    behaviour: R1BadProof { victim: 2 },
                },
                SignParticipant {
                    party_index: 2,
                    behaviour: Honest,
                },
                SignParticipant {
                    party_index: 3,
                    behaviour: R3BadProof,
                },
                SignParticipant {
                    party_index: 4,
                    behaviour: Honest,
                },
            ],
            sign_expected_criminals: vec![Criminal {
                index: 1,
                crime_type: CrimeType::Malicious,
            }],
        },
    ]
}

lazy_static::lazy_static! {
    static ref SIMPLE_TEST_CASES: Vec<TestCase> = generate_simple_test_cases();
    static ref SELF_TARGET_TEST_CASES: Vec<TestCase> = generate_self_targetting_signers();
    static ref TEST_CASES: Vec<TestCase> = generate_multiple_faults();
}

static MESSAGE_TO_SIGN: [u8; 2] = [42, 24];

struct SignParticipant {
    party_index: usize,
    behaviour: MaliciousType,
}

struct TestCase {
    share_count: usize,
    threshold: usize,
    allow_self_delivery: bool,
    sign_participants: Vec<SignParticipant>,
    sign_expected_criminals: Vec<Criminal>,
}

#[test]
#[traced_test]
fn self_targetting() {
    test_cases(&SELF_TARGET_TEST_CASES);
}

#[test]
#[traced_test]
fn simple_cases() {
    test_cases(&SIMPLE_TEST_CASES);
}

#[test]
#[traced_test]
fn multiple_faults() {
    test_cases(&TEST_CASES);
}

fn test_cases(test_cases: &[TestCase]) {
    for t in test_cases {
        let malicious_count = t
            .sign_participants
            .iter()
            .filter(|p| !matches!(p.behaviour, Honest))
            .count();
        info!(
            "malicious_count [{}] share_count [{}] threshold [{}]",
            malicious_count, t.share_count, t.threshold
        );
        execute_test_case(t);
    }
}

fn execute_test_case(t: &TestCase) {
    let participant_indices: Vec<usize> =
        t.sign_participants.iter().map(|p| p.party_index).collect();
    let key_shares = execute_keygen(t.share_count, t.threshold);

    let mut signers: Vec<BadSign> = t
        .sign_participants
        .iter()
        .map(|p| {
            BadSign::new(
                &key_shares[p.party_index],
                &participant_indices,
                &MESSAGE_TO_SIGN,
                p.behaviour.clone(),
            )
            .unwrap()
        })
        .collect();

    let mut protocols: Vec<&mut dyn Protocol> =
        signers.iter_mut().map(|p| p as &mut dyn Protocol).collect();

    execute_protocol_vec(&mut protocols, t.allow_self_delivery);

    // TEST: everyone correctly computed the culprit list
    for signer in signers {
        // We also need to take valid output into account because we skip some
        // self-targetting malicious behaviours, resulting to valid SignOutput
        let criminals = match signer.clone_output().unwrap() {
            Ok(_) => vec![],
            Err(criminals) => criminals,
        };
        assert_eq!(criminals, t.sign_expected_criminals);
    }
}
