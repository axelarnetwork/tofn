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

lazy_static::lazy_static! {
    static ref TEST_CASES: Vec<TestCase> = vec![
        TestCase{
            share_count: 5,
            threshold: 2,
            allow_self_delivery: true,
            sign_participants: vec![
                SignParticipant{party_index: 4, behaviour: Honest},
                SignParticipant{party_index: 2, behaviour: Honest},
                SignParticipant{party_index: 1, behaviour: R1BadProof{victim:0}},
            ],
            sign_expected_criminals: vec![Criminal{index: 2, crime_type: CrimeType::Malicious}]
        },
    ];
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
fn new_r1_bad_proof() {
    for t in TEST_CASES.iter() {
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
        assert_eq!(
            signer.clone_output().unwrap().unwrap_err(),
            t.sign_expected_criminals
        );
    }
}
