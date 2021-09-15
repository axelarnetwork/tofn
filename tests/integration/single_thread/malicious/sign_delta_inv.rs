use std::convert::TryFrom;

use tofn::{
    collections::{FillVecMap, HoleVecMap, TypedUsize, VecMap},
    gg20::{
        keygen::{KeygenPartyId, KeygenShareId},
        sign::{
            malicious::{delta_inverse_r3, delta_inverse_r4, Behaviour, DeltaInvFaultType},
            new_sign, MessageDigest, SignParties, SignPartyId, SignProtocol, SignShareId,
        },
    },
    sdk::api::{BytesVec, Fault, PartyShareCounts, Protocol, ProtocolOutput, TofnResult},
};
use tracing::{info, warn};

use crate::{
    common::keygen,
    single_thread::{
        execute::{execute_protocol, nobody_done},
        set_up_logs,
    },
};

#[test]
fn delta_inverse() {
    set_up_logs();

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

    let fault_types = vec![
        DeltaInvFaultType::delta_i,
        DeltaInvFaultType::alpha_ij {
            victim: TypedUsize::from_usize(0),
        },
        DeltaInvFaultType::beta_ij {
            victim: TypedUsize::from_usize(0),
        },
        DeltaInvFaultType::k_i,
        DeltaInvFaultType::gamma_i,
        DeltaInvFaultType::Gamma_i_gamma_i,
    ];
    let mut test_case = DeltaInvTestData {
        party_share_counts: PartyShareCounts::from_vec(vec![1, 2, 3]).unwrap(),
        threshold: 3,
        sign_parties,
        expected_honest_output: Err(faulters),
        faulter_share_id: TypedUsize::from_usize(3),
        fault_type: DeltaInvFaultType::delta_i,
        delta_i_change: None,
    };

    info!("generate secret key shares");

    // generate secret key shares by doing a keygen
    let secret_key_shares = execute_protocol(keygen::initialize_honest_parties(
        &test_case.party_share_counts,
        test_case.threshold,
    ))
    .unwrap()
    .map(|output| match output {
        Protocol::NotDone(_) => panic!("share not done yet"),
        Protocol::Done(result) => result.expect("share finished with error"),
    });

    let keygen_share_ids = &VecMap::<SignShareId, TypedUsize<KeygenShareId>>::from_vec(
        test_case
            .party_share_counts
            .share_id_subset(&test_case.sign_parties)
            .unwrap(),
    );
    let msg_to_sign = MessageDigest::try_from(&[42; 32][..]).unwrap();

    for fault_type in fault_types {
        info!(
            "sign with malicious delta-inverse attacker [{:?}]",
            fault_type
        );
        test_case.fault_type = fault_type;

        let shares = keygen_share_ids
            .clone()
            .map2(|(_sign_share_id, keygen_share_id)| {
                let secret_key_share = secret_key_shares.get(keygen_share_id).unwrap();
                new_sign(
                    secret_key_share.group(),
                    secret_key_share.share(),
                    &test_case.sign_parties,
                    &msg_to_sign,
                    Behaviour::Honest,
                )
                .unwrap()
            });

        let outputs = execute_sign_protocol(shares, &mut test_case).unwrap();

        // TEST: honest parties finished and produced the expected output
        for (sign_share_id, result) in outputs.iter() {
            if sign_share_id != test_case.faulter_share_id {
                match result {
                    Protocol::NotDone(_) => {
                        panic!("honest sign share_id {} not done yet", sign_share_id)
                    }
                    Protocol::Done(output) => test_case.assert_expected_output(output),
                }
            }
        }
    }
}

pub struct DeltaInvTestData {
    pub party_share_counts: PartyShareCounts<KeygenPartyId>,
    pub threshold: usize,
    pub sign_parties: SignParties,
    pub expected_honest_output: ProtocolOutput<BytesVec, SignPartyId>,
    pub faulter_share_id: TypedUsize<SignShareId>,
    pub fault_type: DeltaInvFaultType,
    pub delta_i_change: Option<k256::Scalar>,
}

impl DeltaInvTestData {
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

pub fn execute_sign_protocol(
    mut shares: VecMap<SignShareId, SignProtocol>,
    test_case: &mut DeltaInvTestData,
) -> TofnResult<VecMap<SignShareId, SignProtocol>> {
    let mut current_round = 0;
    while nobody_done(&shares) {
        current_round += 1;
        shares = next_sign_round(shares, test_case, current_round)?;
    }
    Ok(shares)
}

fn next_sign_round(
    shares: VecMap<SignShareId, SignProtocol>,
    test_case: &mut DeltaInvTestData,
    current_round: usize,
) -> TofnResult<VecMap<SignShareId, SignProtocol>> {
    // extract current round from parties
    let mut rounds: VecMap<SignShareId, _> = shares
        .into_iter()
        .map(|(i, party)| match party {
            Protocol::NotDone(round) => round,
            Protocol::Done(_) => panic!("next_round called but party {} is done", i),
        })
        .collect();

    // collect bcasts and p2ps
    let mut all_bcasts: VecMap<SignShareId, Option<BytesVec>> = rounds
        .iter()
        .map(|(_, round)| round.bcast_out().cloned())
        .collect();
    let mut all_p2ps: VecMap<SignShareId, Option<HoleVecMap<_, BytesVec>>> = rounds
        .iter()
        .map(|(_, round)| round.p2ps_out().cloned())
        .collect();

    // execute delta-inverse attack: round 3 corrupt delta_i
    if current_round == 3 {
        let (all_bcasts_corrupted, delta_i_change) =
            delta_inverse_r3(test_case.faulter_share_id, all_bcasts);
        all_bcasts = all_bcasts_corrupted;
        test_case.delta_i_change = Some(delta_i_change);
    }

    // execute delta-inverse attack: round 4 corrupt alpha_ij, beta_ij, k_i, gamma_i
    if current_round == 4 {
        delta_inverse_r4(
            &test_case.fault_type,
            test_case.delta_i_change.unwrap(),
            test_case.faulter_share_id,
            all_bcasts
                .get_mut(test_case.faulter_share_id)
                .unwrap()
                .as_mut()
                .unwrap(),
            &mut all_p2ps
                .get_mut(test_case.faulter_share_id)
                .unwrap()
                .as_mut()
                .unwrap(),
        )
    }

    // deliver bcasts
    for (from, bcast) in all_bcasts.into_iter() {
        if let Some(bytes) = bcast {
            for (_, round) in rounds.iter_mut() {
                round.msg_in(
                    round
                        .info()
                        .party_share_counts()
                        .share_to_party_id(from)
                        .unwrap(),
                    &bytes,
                )?;
            }
        }
    }

    // deliver p2ps
    for (from, p2ps) in all_p2ps.into_iter() {
        if let Some(p2ps) = p2ps {
            for (_, bytes) in p2ps {
                for (_, round) in rounds.iter_mut() {
                    round.msg_in(
                        round
                            .info()
                            .party_share_counts()
                            .share_to_party_id(from)
                            .unwrap(), // no easy access to from_party_id
                        &bytes,
                    )?;
                }
            }
        }
    }

    // compute next round's parties
    rounds
        .into_iter()
        .map(|(i, round)| {
            if round.expecting_more_msgs_this_round() {
                warn!(
                    "all messages delivered this round but party {} still expecting messages",
                    i,
                );
            }
            round.execute_next_round()
        })
        .collect::<TofnResult<_>>()
}
