use super::{Sign, Status};
use crate::zkp::range;

impl Sign {
    pub(super) fn r3fail(&self) -> Vec<usize> {
        assert!(matches!(self.status, Status::R2Fail));
        assert!(self.in_r2bcasts_fail.some_count() > 0);

        let mut culprits = vec![false; self.participant_indices.len()];

        for accuser in 0..self.participant_indices.len() {
            if let Some(fail_bcast) = self.in_r2bcasts_fail.vec_ref()[accuser].as_ref() {
                for accused in fail_bcast.culprits.iter() {
                    let prover_ek = &self.my_secret_key_share.all_eks
                        [self.participant_indices[accused.participant_index]]; // TODO clarify confusion: participant vs party indices
                    let prover_encrypted_ecdsa_nonce_summand = &self.in_r1bcasts.vec_ref()
                        [accused.participant_index]
                        .as_ref()
                        .unwrap()
                        .encrypted_ecdsa_nonce_summand
                        .c;
                    let verifier_zkp = &self.my_secret_key_share.all_zkps[accuser];

                    let stmt = &range::Statement {
                        ciphertext: &prover_encrypted_ecdsa_nonce_summand,
                        ek: prover_ek,
                    };
                    let proof = &self.in_all_r1p2ps[accused.participant_index].vec_ref()[accuser]
                        .as_ref()
                        .unwrap()
                        .range_proof;
                    let verification = verifier_zkp.verify_range_proof(stmt, proof);

                    let culprit_index = match verification {
                        Ok(_) => {
                            println!(
                                "participant {} detect false accusation by {} against {}",
                                self.my_participant_index, accuser, accused.participant_index
                            );
                            accuser
                        }
                        Err(e) => {
                            println!(
                                "participant {} detect bad proof from {} to {} because [{}]",
                                self.my_participant_index, accused.participant_index, accuser, e
                            );
                            accused.participant_index
                        }
                    };
                    culprits[culprit_index] = true;
                }
            }
        }

        culprits
            .into_iter()
            .enumerate()
            .filter_map(|(i, b)| if b { Some(i) } else { None })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::protocol::gg20::sign::tests::{MSG_TO_SIGN, TEST_CASES};
    use crate::{
        protocol::gg20::keygen::{tests::execute_keygen, SecretKeyShare},
        zkp::range::tests::corrupt_proof,
    };

    #[test]
    fn one_bad_proof() {
        for (share_count, threshold, participant_indices) in TEST_CASES.iter() {
            if *share_count < 2 {
                continue; // need at least 2 shares for this test
            }
            let key_shares = execute_keygen(*share_count, *threshold);
            one_bad_proof_inner(&key_shares, participant_indices, &MSG_TO_SIGN);
        }
    }

    fn one_bad_proof_inner(
        key_shares: &[SecretKeyShare],
        participant_indices: &[usize],
        msg_to_sign: &[u8],
    ) {
        assert!(participant_indices.len() > 1);
        let (criminal, victim) = (1, 0);

        let mut participants: Vec<Sign> = participant_indices
            .iter()
            .map(|i| Sign::new(&key_shares[*i], participant_indices, msg_to_sign).unwrap())
            .collect();

        // execute round 1 all participants and store their outputs
        let mut all_r1_bcasts = FillVec::with_len(participants.len());
        let mut all_r1_p2ps = Vec::with_capacity(participants.len());
        for (i, participant) in participants.iter_mut().enumerate() {
            let (state, bcast, p2ps) = participant.r1();
            participant.r1state = Some(state);
            participant.status = Status::R1;
            all_r1_bcasts.insert(i, bcast).unwrap();
            all_r1_p2ps.push(p2ps);
        }

        // corrupt the proof from party `criminal` to party `victim`
        let proof = &mut all_r1_p2ps[criminal].vec_ref_mut()[victim]
            .as_mut()
            .unwrap()
            .range_proof;
        *proof = corrupt_proof(proof);

        // deliver round 1 msgs
        for participant in participants.iter_mut() {
            participant.in_all_r1p2ps = all_r1_p2ps.clone();
            participant.in_r1bcasts = all_r1_bcasts.clone();
        }

        // execute round 2 all participants and store their outputs
        let mut all_r2_p2ps = Vec::with_capacity(participants.len());
        let mut all_r2_bcasts_fail = FillVec::with_len(participants.len());
        for (i, participant) in participants.iter_mut().enumerate() {
            match participant.r2() {
                r2::Output::Success { state, out_p2ps } => {
                    if i == victim {
                        panic!(
                            "r2 party {} expect failure but found success",
                            participant.my_secret_key_share.my_index
                        );
                    }
                    participant.r2state = Some(state);
                    all_r2_p2ps.push(out_p2ps);
                }
                r2::Output::Fail { out_bcast } => {
                    if i != victim {
                        panic!(
                            "r2 party {} expect success but found failure with culprits {:?}",
                            participant.my_secret_key_share.my_index, out_bcast.culprits
                        );
                    }
                    all_r2_bcasts_fail.insert(i, out_bcast).unwrap();
                    all_r2_p2ps.push(FillVec::with_len(0)); // dummy TODO use FillVec instead of Vec?
                }
            }
        }

        // deliver round 2 msgs
        for participant in participants.iter_mut() {
            participant.in_all_r2p2ps = all_r2_p2ps.clone();
            participant.in_r2bcasts_fail = all_r2_bcasts_fail.clone();

            // all participants transition to R2Fail because they all received at least one r2::FailBcast
            participant.status = Status::R2Fail;
        }

        // execute round 2 sad path all participants and store their outputs
        let mut all_culprit_lists = Vec::with_capacity(participants.len());
        for participant in participants.iter_mut() {
            let culprits = participant.r3fail();
            participant.status = Status::Fail;
            all_culprit_lists.push(culprits);
        }

        // TEST: everyone correctly computed the culprit list
        let actual_culprits: Vec<usize> = vec![criminal];
        for culprit_list in all_culprit_lists {
            assert_eq!(culprit_list, actual_culprits);
        }
    }

    #[test]
    fn one_false_accusation() {
        for (share_count, threshold, participant_indices) in TEST_CASES.iter() {
            if *share_count < 2 {
                continue; // need at least 2 shares for this test
            }
            let key_shares = execute_keygen(*share_count, *threshold);
            one_false_accusation_inner(&key_shares, participant_indices, &MSG_TO_SIGN);
        }
    }

    fn one_false_accusation_inner(
        key_shares: &[SecretKeyShare],
        participant_indices: &[usize],
        msg_to_sign: &[u8],
    ) {
        assert!(participant_indices.len() > 1);
        let (criminal_accuser, victim_accused) = (1, 0);

        let mut participants: Vec<Sign> = participant_indices
            .iter()
            .map(|i| Sign::new(&key_shares[*i], participant_indices, msg_to_sign).unwrap())
            .collect();

        // execute round 1 all participants and store their outputs
        let mut all_r1_bcasts = FillVec::with_len(participants.len());
        let mut all_r1_p2ps = Vec::with_capacity(participants.len());
        for (i, participant) in participants.iter_mut().enumerate() {
            let (state, bcast, p2ps) = participant.r1();
            participant.r1state = Some(state);
            participant.status = Status::R1;
            all_r1_bcasts.insert(i, bcast).unwrap();
            all_r1_p2ps.push(p2ps);
        }

        // deliver round 1 msgs
        for participant in participants.iter_mut() {
            participant.in_all_r1p2ps = all_r1_p2ps.clone();
            participant.in_r1bcasts = all_r1_bcasts.clone();
        }

        // execute round 2 all participants and store their outputs
        let mut all_r2_p2ps = Vec::with_capacity(participants.len());
        let mut all_r2_bcasts_fail = FillVec::with_len(participants.len());
        for (i, participant) in participants.iter_mut().enumerate() {
            match participant.r2() {
                r2::Output::Success { state, out_p2ps } => {
                    // insert a false accusation by party 1 against party 0
                    if i == criminal_accuser {
                        all_r2_bcasts_fail
                            .insert(
                                i,
                                r2::FailBcast {
                                    culprits: vec![r2::Culprit {
                                        participant_index: victim_accused,
                                    }],
                                },
                            )
                            .unwrap();
                        all_r2_p2ps.push(FillVec::with_len(0)); // dummy TODO use FillVec instead of Vec?
                    } else {
                        participant.r2state = Some(state);
                        all_r2_p2ps.push(out_p2ps);
                    }
                }
                r2::Output::Fail { out_bcast } => {
                    panic!(
                        "r2 party {} expect success got failure with culprits: {:?}",
                        participant.my_secret_key_share.my_index, out_bcast
                    );
                }
            }
        }

        // deliver round 2 msgs
        for participant in participants.iter_mut() {
            participant.in_all_r2p2ps = all_r2_p2ps.clone();
            participant.in_r2bcasts_fail = all_r2_bcasts_fail.clone();

            // all participants transition to R2Fail because they all received at least one r2::FailBcast
            participant.status = Status::R2Fail;
        }

        // execute round 2 sad path all participants and store their outputs
        let mut all_culprit_lists = Vec::with_capacity(participants.len());
        for participant in participants.iter_mut() {
            let culprits = participant.r3fail();
            participant.status = Status::Fail;
            all_culprit_lists.push(culprits);
        }

        // TEST: everyone correctly computed the culprit list
        let actual_culprits: Vec<usize> = vec![criminal_accuser];
        for (i, culprit_list) in all_culprit_lists.iter().enumerate() {
            assert_eq!(
                culprit_list, &actual_culprits,
                "party {} unexpected culprit list",
                i
            );
        }
    }
}
