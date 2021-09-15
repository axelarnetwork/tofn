use crate::{
    common::keygen,
    single_thread::{execute::execute_protocol, set_up_logs},
};
use std::convert::TryFrom;
use tofn::{
    collections::{FillVecMap, TypedUsize, VecMap},
    gg20::{
        keygen::KeygenPartyId,
        sign::{
            malicious::Behaviour::{self, *},
            new_sign, MessageDigest, SignParties, SignPartyId, SignShareId,
        },
    },
    sdk::api::{BytesVec, Fault, PartyShareCounts, Protocol::*, ProtocolOutput},
};
use tracing::info;

#[test]
fn single_faults() {
    set_up_logs();

    let test_cases = single_fault_test_cases();

    info!("generate secret key shares",);

    // generate secret key shares by doing a keygen
    let secret_key_shares = execute_protocol(keygen::initialize_honest_parties(
        &test_cases.party_share_counts,
        test_cases.threshold,
    ))
    .unwrap()
    .map(|output| match output {
        NotDone(_) => panic!("share not done yet"),
        Done(result) => result.expect("share finished with error"),
    });

    let keygen_share_ids = &VecMap::<SignShareId, _>::from_vec(
        test_cases
            .party_share_counts
            .share_id_subset(&test_cases.sign_parties)
            .unwrap(),
    );
    let msg_to_sign = MessageDigest::try_from(&[42; 32][..]).unwrap();

    for case in test_cases.cases.iter() {
        info!("sign with malicious behaviour {:?}", case);
        let parties = keygen_share_ids
            .clone()
            .map2(|(_sign_share_id, keygen_share_id)| {
                let behaviour = if _sign_share_id == test_cases.malicious_sign_share_id {
                    case.clone()
                } else {
                    Honest
                };
                let secret_key_share = secret_key_shares.get(keygen_share_id).unwrap();
                new_sign(
                    secret_key_share.group(),
                    secret_key_share.share(),
                    &test_cases.sign_parties,
                    &msg_to_sign,
                    behaviour,
                )
                .unwrap()
            });
        let results = execute_protocol(parties).unwrap();

        // TEST: honest parties finished and produced the expected output
        for (sign_share_id, result) in results.iter() {
            if sign_share_id != test_cases.malicious_sign_share_id {
                match result {
                    NotDone(_) => panic!("honest sign share_id {} not done yet", sign_share_id),
                    Done(output) => test_cases.assert_expected_output(output),
                }
            }
        }
    }
}

fn single_fault_test_cases() -> SingleFaultTestCaseList {
    // 3 keygen parties: 1,2,3 shares per party
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

    let zero = TypedUsize::from_usize(0);

    let cases = vec![
        R1BadProof { victim: zero },
        R1BadGammaI,
        R2FalseAccusation { victim: zero },
        R2BadMta { victim: zero },
        R2BadMtaWc { victim: zero },
        R3BadSigmaI,
        R3FalseAccusationMta { victim: zero },
        R3FalseAccusationMtaWc { victim: zero },
        R3BadProof,
        R3BadDeltaI,
        R3BadKI,
        R3BadAlpha { victim: zero },
        R3BadBeta { victim: zero },
        R4BadReveal,
        R5BadProof { victim: zero },
        R6FalseAccusation { victim: zero },
        R6BadProof,
        R6FalseType5Claim,
        R7BadSI,
        R7FalseType7Claim,
    ];

    SingleFaultTestCaseList {
        party_share_counts: PartyShareCounts::from_vec(vec![1, 2, 3]).unwrap(),
        threshold: 3,
        sign_parties,
        expected_honest_output: Err(faulters),
        cases,
        malicious_sign_share_id: TypedUsize::from_usize(3),
    }
}

pub struct SingleFaultTestCaseList {
    pub party_share_counts: PartyShareCounts<KeygenPartyId>,
    pub threshold: usize,
    pub sign_parties: SignParties,
    // pub share_behaviours: VecMap<SignParticipantIndex, Behaviour>,
    pub expected_honest_output: ProtocolOutput<BytesVec, SignPartyId>,
    pub cases: Vec<Behaviour>,
    pub malicious_sign_share_id: TypedUsize<SignShareId>,
}

impl SingleFaultTestCaseList {
    pub fn assert_expected_output(&self, output: &ProtocolOutput<BytesVec, SignPartyId>) {
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
}
