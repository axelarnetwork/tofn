use super::{Sign, Status};
use crate::fillvec::FillVec;
use crate::zkp::{mta, range};
use curv::{elliptic::curves::traits::ECPoint, FE, GE};
use multi_party_ecdsa::utilities::mta as mta_zengo;
use serde::{Deserialize, Serialize};

// round 2

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2p {
    pub mta_response_blind: mta_zengo::MessageB,
    pub mta_proof: mta::Proof,
    pub mta_response_keyshare: mta_zengo::MessageB,
    pub mta_proof_wc: mta::ProofWc,
}
#[derive(Debug)] // do not derive Clone, Serialize, Deserialize
pub struct State {
    pub(super) my_mta_blind_summands_rhs: Vec<Option<FE>>,
    pub(super) my_mta_keyshare_summands_rhs: Vec<Option<FE>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Culprit {
    // the crime is implicit: there is only one possible crime: zkp verification failure
    pub participant_index: usize, // list of malicious participant indices
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailBcast {
    pub culprits: Vec<Culprit>,
}

// TODO is it better to have `State` and `P2p` be enum types?
pub enum Output {
    Success {
        state: State,
        out_p2ps: FillVec<P2p>,
    },
    Fail {
        out_bcast: FailBcast,
    },
}

impl Sign {
    pub(super) fn r2(&self) -> Output {
        assert!(matches!(self.status, Status::R1));

        // response msg for MtA protocols:
        // 1. my_ecdsa_nonce_summand (other) * my_secret_blind_summand (me)
        // 2. my_ecdsa_nonce_summand (other) * my_secret_key_summand (me)
        // both MtAs use my_ecdsa_nonce_summand, so I use the same message for both

        let r1state = self.r1state.as_ref().unwrap();
        let my_public_key_summand = GE::generator() * r1state.my_secret_key_summand;

        let mut out_p2ps = FillVec::with_len(self.participant_indices.len());
        let mut my_mta_blind_summands_rhs = FillVec::with_len(self.participant_indices.len());
        let mut my_mta_keyshare_summands_rhs = FillVec::with_len(self.participant_indices.len());
        let mut culprits = Vec::new();

        // verify zk proofs for first message of MtA
        for (i, participant_index) in self.participant_indices.iter().enumerate() {
            // TODO make a self.iter_others_enumerate method that automatically skips my index
            if *participant_index == self.my_secret_key_share.my_index {
                continue;
            }

            // TODO don't use mta!  It sucks!
            // 1. unused return values in MessageB::b()
            // 2. MessageA arg is passed by value
            let other_ek = &self.my_secret_key_share.all_eks[*participant_index];
            let other_encrypted_ecdsa_nonce_summand = &self.in_r1bcasts.vec_ref()[i]
                .as_ref()
                .unwrap()
                .encrypted_ecdsa_nonce_summand;

            // verify zk proof for first message of MtA
            let stmt = &range::Statement {
                ciphertext: &other_encrypted_ecdsa_nonce_summand.c,
                ek: other_ek,
            };
            let proof = &self.in_all_r1p2ps[i].vec_ref()[self.my_participant_index]
                .as_ref()
                .unwrap()
                .range_proof;
            self.my_secret_key_share
                .my_zkp
                .verify_range_proof(stmt, proof)
                .unwrap_or_else(|e| {
                    println!(
                        "party {} says: range proof failed to verify for party {} because [{}]",
                        self.my_secret_key_share.my_index, participant_index, e
                    );
                    culprits.push(Culprit {
                        participant_index: i,
                    });
                });

            // MtA for nonce * blind
            // TODO tidy scoping: don't need randomness, beta_prime after these two statements
            let (mta_response_blind, my_mta_blind_summand_rhs, randomness, beta_prime) = // (m_b_gamma, beta_gamma)
                mta_zengo::MessageB::b(&r1state.my_secret_blind_summand, other_ek, other_encrypted_ecdsa_nonce_summand.clone());
            let other_zkp = &self.my_secret_key_share.all_zkps[*participant_index];
            let mta_proof = other_zkp.mta_proof(
                &mta::Statement {
                    ciphertext1: &other_encrypted_ecdsa_nonce_summand.c,
                    ciphertext2: &mta_response_blind.c,
                    ek: other_ek,
                },
                &mta::Witness {
                    x: &r1state.my_secret_blind_summand,
                    msg: &beta_prime,
                    randomness: &randomness,
                },
            );

            // MtAwc for nonce * keyshare
            let (mta_response_keyshare, my_mta_keyshare_summand_rhs, randomness_wc, beta_prime_wc) = // (m_b_w, beta_wi)
                mta_zengo::MessageB::b(&r1state.my_secret_key_summand, other_ek, other_encrypted_ecdsa_nonce_summand.clone());
            let mta_proof_wc = other_zkp.mta_proof_wc(
                &mta::StatementWc {
                    stmt: mta::Statement {
                        ciphertext1: &other_encrypted_ecdsa_nonce_summand.c,
                        ciphertext2: &mta_response_keyshare.c,
                        ek: other_ek,
                    },
                    x_g: &my_public_key_summand,
                },
                &mta::Witness {
                    x: &r1state.my_secret_key_summand,
                    msg: &beta_prime_wc,
                    randomness: &randomness_wc,
                },
            );

            // TODO I'm not sending my rhs summands even though zengo does https://github.com/axelarnetwork/tofn/issues/7#issuecomment-771379525

            out_p2ps
                .insert(
                    i,
                    P2p {
                        mta_response_blind,
                        mta_proof,
                        mta_response_keyshare,
                        mta_proof_wc,
                    },
                )
                .unwrap();
            my_mta_blind_summands_rhs
                .insert(i, my_mta_blind_summand_rhs)
                .unwrap();
            my_mta_keyshare_summands_rhs
                .insert(i, my_mta_keyshare_summand_rhs)
                .unwrap();
        }

        if culprits.is_empty() {
            Output::Success {
                state: State {
                    my_mta_blind_summands_rhs: my_mta_blind_summands_rhs.into_vec(),
                    my_mta_keyshare_summands_rhs: my_mta_keyshare_summands_rhs.into_vec(),
                    // my_public_key_summand,
                },
                out_p2ps,
            }
        } else {
            Output::Fail {
                out_bcast: FailBcast { culprits },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::protocol::{
        gg20::keygen::{tests::execute_keygen, SecretKeyShare},
        gg20::sign::tests::{MSG_TO_SIGN, TEST_CASES},
    };

    #[test]
    fn one_false_accusation() {
        for (share_count, threshold, participant_indices) in TEST_CASES.iter() {
            if participant_indices.len() < 2 {
                continue; // need at least 2 participants for this test
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
