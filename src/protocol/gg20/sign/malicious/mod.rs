use super::{
    crimes::Crime, r2, r3, r4, r5, r6, r7, MsgType, ParamsError, Sign, SignOutput, Status,
};
use crate::paillier_k256;
use crate::protocol::gg20::{GroupPublicInfo, MessageDigest, ShareSecretInfo};
use crate::protocol::{IndexRange, MsgBytes, Protocol, ProtocolResult};
use crate::zkp::pedersen_k256;
use strum_macros::EnumIter;
use tracing::{error, info, warn};

// all malicious behaviours
// names have the form <round><fault> where
// <round> indicates round where the first malicious tampering occurs, and
// <fault> is a description
// example: R1BadProof -> fault injected to the output of r1()
#[derive(Clone, Debug, EnumIter)]
pub enum Behaviour {
    // TODO R1BadCommit,
    Honest,
    UnauthenticatedSender { victim: usize, status: Status },
    Staller { msg_type: MsgType },
    DisrupringSender { msg_type: MsgType },
    R3BadSigmaI, // triggers r7::Output::FailType7
    R1BadProof { victim: usize },
    R1BadGammaI, // triggers r6::Output::FailType5
    R2FalseAccusation { victim: usize },
    R2BadMta { victim: usize },
    R2BadMtaWc { victim: usize },
    R3FalseAccusationMta { victim: usize },
    R3FalseAccusationMtaWc { victim: usize },
    R3BadProof,
    R3BadDeltaI,                  // triggers r6::Output::FailType5
    R3BadKI,                      // triggers r6::Output::FailType5
    R3BadAlpha { victim: usize }, // triggers r6::Output::FailType5
    R3BadBeta { victim: usize },  // triggers r6::Output::FailType5
    R4BadReveal,
    R5BadProof { victim: usize },
    R6FalseAccusation { victim: usize },
    R6BadProof,
    R6FalseFailRandomizer,
    R7BadSI,
}
use Behaviour::*;

pub struct BadSign {
    sign: Sign,
    behaviour: Behaviour,
}

impl BadSign {
    pub fn new(
        key_group: &GroupPublicInfo,
        key_share: &ShareSecretInfo,
        participant_indices: &[usize],
        msg_to_sign: &MessageDigest,
        behaviour: Behaviour,
    ) -> Result<Self, ParamsError> {
        // TODO hack type7 fault
        let mut sign = Sign::new(key_group, key_share, participant_indices, msg_to_sign)?;
        sign.behaviour = behaviour.clone();
        Ok(Self { sign, behaviour })
    }

    pub fn waiting_on(&self) -> Vec<Vec<Crime>> {
        self.sign.waiting_on()
    }

    pub fn found_disrupting(&self) -> bool {
        self.sign.found_disrupting()
    }

    pub fn clone_output(&self) -> Option<SignOutput> {
        self.sign.clone_output()
    }
}

impl Protocol for BadSign {
    fn next_round(&mut self) -> ProtocolResult {
        // TODO refactor copied code from Sign::next_round():
        // expecting_more_msgs_this_round() and move_to_sad_path()
        if self.expecting_more_msgs_this_round() {
            return Err(From::from("can't prceed yet"));
        }
        self.sign.move_to_sad_path();

        match self.behaviour.clone() {
            Honest => self.sign.next_round(),
            UnauthenticatedSender {
                // act normal, spoofing occurs at the routing level
                victim: _,
                status: _,
            } => self.sign.next_round(),
            Staller { msg_type: _ } => self.sign.next_round(), // act normal, stalling occurs at the routing level
            DisrupringSender {
                // act normal, faulty serialization occurs at the routing level
                msg_type: _,
            } => self.sign.next_round(),
            R3BadSigmaI => self.sign.next_round(), // TODO hack type7 fault
            R1BadProof { victim } => {
                if !matches!(self.sign.status, Status::New) {
                    return self.sign.next_round();
                };
                if victim == self.sign.my_participant_index {
                    warn!(
                        "malicious participant {} can't do {:?} on myself; reverting to honesty",
                        self.sign.my_participant_index, self.behaviour
                    );
                    return self.sign.next_round();
                }
                let (state, bcast, mut p2ps) = self.sign.r1();
                info!(
                    "malicious participant {} do {:?}",
                    self.sign.my_participant_index, self.behaviour
                );
                let proof_k256 = &mut p2ps.vec_ref_mut()[victim]
                    .as_mut()
                    .unwrap()
                    .range_proof_k256;
                *proof_k256 = paillier_k256::zk::range::malicious::corrupt_proof(proof_k256);
                self.sign.update_state_r1(state, bcast, p2ps)
            }
            R1BadGammaI => {
                if !matches!(self.sign.status, Status::New) {
                    return self.sign.next_round();
                };
                let (mut state, bcast, p2ps) = self.sign.r1();

                info!(
                    "malicious participant {} do {:?}",
                    self.sign.my_participant_index, self.behaviour
                );

                // curv: don't do anything
                // let one: FE = ECScalar::from(&BigInt::from(1));
                // let my_secret_blind_summand = &mut state.gamma_i;
                // *my_secret_blind_summand = *my_secret_blind_summand + one;

                // k256
                state.gamma_i_k256 += k256::Scalar::one();

                self.sign.update_state_r1(state, bcast, p2ps)
            }
            R2FalseAccusation { victim } => {
                if !matches!(self.sign.status, Status::R1) {
                    return self.sign.next_round();
                };
                // no need to execute self.s.r2()
                info!(
                    "malicious participant {} do {:?}",
                    self.sign.my_participant_index, self.behaviour
                );
                self.sign.update_state_r2fail(r2::FailBcast {
                    culprits: vec![r2::Culprit {
                        participant_index: victim,
                        crime: r2::Crime::RangeProof,
                    }],
                })
            }
            R2BadMta { victim } => {
                if !matches!(self.sign.status, Status::R1) {
                    return self.sign.next_round();
                };
                if victim == self.sign.my_participant_index {
                    warn!(
                        "malicious participant {} can't do {:?} on myself; reverting to honesty",
                        self.sign.my_participant_index, self.behaviour
                    );
                    return self.sign.next_round();
                }
                match self.sign.r2() {
                    r2::Output::Success {
                        state,
                        mut out_p2ps,
                    } => {
                        info!(
                            "malicious participant {} do {:?}",
                            self.sign.my_participant_index, self.behaviour
                        );
                        let proof_k256 = &mut out_p2ps.vec_ref_mut()[victim]
                            .as_mut()
                            .unwrap()
                            .alpha_proof_k256;
                        *proof_k256 = paillier_k256::zk::mta::malicious::corrupt_proof(proof_k256);
                        self.sign.update_state_r2(state, out_p2ps)
                    }
                    r2::Output::Fail { out_bcast } => {
                        warn!(
                            "malicious participant {} can't do {:?} because protocol has failed; reverting to honesty",
                            self.sign.my_participant_index, victim
                        );
                        self.sign.update_state_r2fail(out_bcast)
                    }
                }
            }
            R2BadMtaWc { victim } => {
                if !matches!(self.sign.status, Status::R1) {
                    return self.sign.next_round();
                };
                if victim == self.sign.my_participant_index {
                    warn!(
                        "malicious participant {} can't do {:?} on myself; reverting to honesty",
                        self.sign.my_participant_index, self.behaviour
                    );
                    return self.sign.next_round();
                }
                match self.sign.r2() {
                    r2::Output::Success {
                        state,
                        mut out_p2ps,
                    } => {
                        info!(
                            "malicious participant {} do {:?}",
                            self.sign.my_participant_index, self.behaviour
                        );
                        let proof_k256 = &mut out_p2ps.vec_ref_mut()[victim]
                            .as_mut()
                            .unwrap()
                            .mu_proof_k256;
                        *proof_k256 =
                            paillier_k256::zk::mta::malicious::corrupt_proof_wc(proof_k256);
                        self.sign.update_state_r2(state, out_p2ps)
                    }
                    r2::Output::Fail { out_bcast } => {
                        warn!(
                            "malicious participant {} can't do {:?} because protocol has failed; reverting to honesty",
                            self.sign.my_participant_index, victim
                        );
                        self.sign.update_state_r2fail(out_bcast)
                    }
                }
            }
            R3FalseAccusationMta { victim } => {
                if !matches!(self.sign.status, Status::R2) {
                    return self.sign.next_round();
                };
                // no need to execute self.s.r3()
                info!(
                    "malicious participant {} do {:?}",
                    self.sign.my_participant_index, self.behaviour
                );
                self.sign.update_state_r3fail(r3::FailBcast {
                    culprits: vec![r3::Culprit {
                        participant_index: victim,
                        crime: r3::Crime::Mta,
                    }],
                })
            }
            R3FalseAccusationMtaWc { victim } => {
                if !matches!(self.sign.status, Status::R2) {
                    return self.sign.next_round();
                };
                // no need to execute self.s.r3()
                info!(
                    "malicious participant {} do {:?}",
                    self.sign.my_participant_index, self.behaviour
                );
                self.sign.update_state_r3fail(r3::FailBcast {
                    culprits: vec![r3::Culprit {
                        participant_index: victim,
                        crime: r3::Crime::MtaWc,
                    }],
                })
            }
            R3BadProof => {
                if !matches!(self.sign.status, Status::R2) {
                    return self.sign.next_round();
                };
                match self.sign.r3() {
                    r3::Output::Success {
                        state,
                        mut out_bcast,
                    } => {
                        info!(
                            "malicious participant {} do {:?}",
                            self.sign.my_participant_index, self.behaviour
                        );
                        let proof_k256 = &mut out_bcast.T_i_proof_k256;
                        *proof_k256 = pedersen_k256::malicious::corrupt_proof(proof_k256);
                        self.sign.update_state_r3(state, out_bcast)
                    }
                    r3::Output::Fail { out_bcast } => {
                        warn!(
                            "malicious participant {} instructed to corrupt r3 pedersen proof but r3 has already failed so reverting to honesty",
                            self.sign.my_participant_index
                        );
                        self.sign.update_state_r3fail(out_bcast)
                    }
                }
            }
            R3BadDeltaI => {
                if !matches!(self.sign.status, Status::R2) {
                    return self.sign.next_round();
                };
                match self.sign.r3() {
                    r3::Output::Success {
                        state,
                        mut out_bcast,
                    } => {
                        info!(
                            "malicious participant {} do {:?} (delta_i)",
                            self.sign.my_participant_index, self.behaviour
                        );

                        // curv: don't do anything
                        // need to corrupt both state and out_bcast
                        // because they both contain a copy of nonce_x_blind_summand
                        // let one: FE = ECScalar::from(&BigInt::from(1));
                        // let nonce_x_blind_summand = &mut out_bcast.delta_i;
                        // *nonce_x_blind_summand = *nonce_x_blind_summand + one;
                        // let nonce_x_blind_summand_state = &mut state.delta_i;
                        // *nonce_x_blind_summand_state = *nonce_x_blind_summand_state + one;

                        // k256
                        *out_bcast.delta_i_k256.unwrap_mut() += k256::Scalar::one();

                        self.sign.update_state_r3(state, out_bcast)
                    }
                    r3::Output::Fail { out_bcast } => {
                        warn!(
                            "malicious participant {} instructed to corrupt r3 delta_i but r3 has already failed so reverting to honesty",
                            self.sign.my_participant_index
                        );
                        self.sign.update_state_r3fail(out_bcast)
                    }
                }
            }
            R3BadKI => {
                if !matches!(self.sign.status, Status::R2 | Status::R5) {
                    return self.sign.next_round();
                };
                match &self.sign.status {
                    Status::R2 => {
                        match self.sign.r3() {
                            r3::Output::Success {
                                state,
                                mut out_bcast,
                            } => {
                                info!(
                                    "malicious participant {} do {:?} (delta_i)",
                                    self.sign.my_participant_index, self.behaviour
                                );
                                // later we will corrupt k_i by adding 1
                                // => need to add gamma_i to delta_i to maintain consistency

                                // curv: don't do anything
                                // need to corrupt both state and out_bcast
                                // because they both contain a copy of nonce_x_blind_summand
                                // let nonce_x_blind_summand = &mut out_bcast.delta_i;
                                // *nonce_x_blind_summand = *nonce_x_blind_summand
                                //     + self.sign.r1state.as_ref().unwrap().gamma_i;
                                // let nonce_x_blind_summand_state = &mut state.delta_i;
                                // *nonce_x_blind_summand_state = *nonce_x_blind_summand_state
                                //     + self.sign.r1state.as_ref().unwrap().gamma_i;

                                // k256
                                *out_bcast.delta_i_k256.unwrap_mut() +=
                                    self.sign.r1state.as_ref().unwrap().gamma_i_k256;

                                self.sign.update_state_r3(state, out_bcast)
                            }
                            r3::Output::Fail { out_bcast } => {
                                warn!(
                                    "malicious participant {} can't do {:?} because protocol has failed; reverting to honesty",
                                    self.sign.my_participant_index, self.behaviour
                                );
                                self.sign.update_state_r3fail(out_bcast)
                            }
                        }
                    }
                    Status::R5 => match self.sign.r6() {
                        r6::Output::Success { out_bcast } => {
                            error!(
                                    "malicious participant {} round 6 expect fail due to my earlier malicious behaviour in round 3, got success; can't do {:?}; reverting to honesty",
                                    self.sign.my_participant_index, self.behaviour
                                );
                            self.sign.update_state_r6(out_bcast)
                        }
                        r6::Output::Fail { out_bcast } => {
                            warn!(
                                    "malicious participant {} can't do {:?} because protocol has failed; reverting to honesty",
                                    self.sign.my_participant_index, self.behaviour
                                );
                            self.sign.update_state_r6fail(out_bcast)
                        }
                        r6::Output::FailType5 { mut out_bcast } => {
                            info!(
                                "malicious participant {} do {:?} (k_i)",
                                self.sign.my_participant_index, self.behaviour
                            );

                            // curv: don't do anything
                            // let k_i = &mut out_bcast.k_i;
                            // let one: FE = ECScalar::from(&BigInt::from(1));
                            // *k_i = *k_i + one;

                            // k256
                            *out_bcast.k_i_256.unwrap_mut() += k256::Scalar::one();

                            self.sign.update_state_r6fail_type5(out_bcast)
                        }
                    },
                    status => {
                        error!(
                            "malicious participant {} unexpected status {:?}, can't do {:?}",
                            self.sign.my_participant_index, status, self.behaviour
                        );
                        self.sign.next_round()
                    }
                }
            }
            R3BadAlpha { victim } => {
                if !matches!(self.sign.status, Status::R2 | Status::R5) {
                    return self.sign.next_round();
                };
                if victim == self.sign.my_participant_index {
                    warn!(
                        "malicious participant {} can't do {:?} on myself; reverting to honesty",
                        self.sign.my_participant_index, self.behaviour
                    );
                    return self.sign.next_round();
                }
                match &self.sign.status {
                    Status::R2 => {
                        match self.sign.r3() {
                            r3::Output::Success {
                                state,
                                mut out_bcast,
                            } => {
                                info!(
                                    "malicious participant {} do {:?} (delta_i)",
                                    self.sign.my_participant_index, self.behaviour
                                );
                                // later we will corrupt alpha_ij by adding 1
                                // => need to add 1 to delta_i to maintain consistency

                                // curv: don't do anything
                                // need to corrupt both state and out_bcast because they both contain a copy of nonce_x_blind_summand
                                // let one: FE = ECScalar::from(&BigInt::from(1));
                                // let nonce_x_blind_summand = &mut out_bcast.delta_i;
                                // *nonce_x_blind_summand = *nonce_x_blind_summand + one;
                                // let nonce_x_blind_summand_state = &mut state.delta_i;
                                // *nonce_x_blind_summand_state = *nonce_x_blind_summand_state + one;

                                // k256
                                *out_bcast.delta_i_k256.unwrap_mut() += k256::Scalar::one();

                                self.sign.update_state_r3(state, out_bcast)
                            }
                            r3::Output::Fail { out_bcast } => {
                                warn!(
                                    "malicious participant {} can't do {:?} because protocol has failed; reverting to honesty",
                                    self.sign.my_participant_index, self.behaviour
                                );
                                self.sign.update_state_r3fail(out_bcast)
                            }
                        }
                    }
                    Status::R5 => match self.sign.r6() {
                        r6::Output::Success { out_bcast } => {
                            error!(
                                    "malicious participant {} round 6 expect fail due to my earlier malicious behaviour in round 3, got success; can't do {:?}; reverting to honesty",
                                    self.sign.my_participant_index, self.behaviour
                                );
                            self.sign.update_state_r6(out_bcast)
                        }
                        r6::Output::Fail { out_bcast } => {
                            warn!(
                                    "malicious participant {} can't do {:?} because protocol has failed; reverting to honesty",
                                    self.sign.my_participant_index, self.behaviour
                                );
                            self.sign.update_state_r6fail(out_bcast)
                        }
                        r6::Output::FailType5 { mut out_bcast } => {
                            info!(
                                "malicious participant {} do {:?} (alpha_ij)",
                                self.sign.my_participant_index, self.behaviour
                            );
                            let mta_plaintext = out_bcast.mta_plaintexts[victim].as_mut().unwrap();

                            // curv: don't do anything
                            // mta_plaintext.alpha_plaintext =
                            //     &mta_plaintext.alpha_plaintext + BigInt::from(1);

                            // k256
                            mta_plaintext.alpha_plaintext_k256.corrupt();

                            self.sign.update_state_r6fail_type5(out_bcast)
                        }
                    },
                    status => {
                        error!(
                            "malicious participant {} unexpected status {:?}, can't do {:?}",
                            self.sign.my_participant_index, status, self.behaviour
                        );
                        self.sign.next_round()
                    }
                }
            }
            R3BadBeta { victim } => {
                if !matches!(self.sign.status, Status::R2 | Status::R5) {
                    return self.sign.next_round();
                };
                if victim == self.sign.my_participant_index {
                    warn!(
                        "malicious participant {} can't do {:?} on myself; reverting to honesty",
                        self.sign.my_participant_index, self.behaviour
                    );
                    return self.sign.next_round();
                }
                match &self.sign.status {
                    Status::R2 => {
                        match self.sign.r3() {
                            r3::Output::Success {
                                state,
                                mut out_bcast,
                            } => {
                                info!(
                                    "malicious participant {} do {:?} (delta_i)",
                                    self.sign.my_participant_index, self.behaviour
                                );
                                // later we will corrupt beta_ji by adding 1
                                // => need to add 1 to delta_i to maintain consistency

                                // curv: don't do anything
                                // need to corrupt both state and out_bcast because they both contain a copy of nonce_x_blind_summand
                                // let one: FE = ECScalar::from(&BigInt::from(1));
                                // let nonce_x_blind_summand = &mut out_bcast.delta_i;
                                // *nonce_x_blind_summand = *nonce_x_blind_summand + one;
                                // let nonce_x_blind_summand_state = &mut state.delta_i;
                                // *nonce_x_blind_summand_state = *nonce_x_blind_summand_state + one;

                                // k256
                                *out_bcast.delta_i_k256.unwrap_mut() += k256::Scalar::one();

                                self.sign.update_state_r3(state, out_bcast)
                            }
                            r3::Output::Fail { out_bcast } => {
                                warn!(
                                    "malicious participant {} can't do {:?} because protocol has failed; reverting to honesty",
                                    self.sign.my_participant_index, self.behaviour
                                );
                                self.sign.update_state_r3fail(out_bcast)
                            }
                        }
                    }
                    Status::R5 => match self.sign.r6() {
                        r6::Output::Success { out_bcast } => {
                            error!(
                                    "malicious participant {} round 6 expect fail due to my earlier malicious behaviour in round 3, got success; can't do {:?}; reverting to honesty",
                                    self.sign.my_participant_index, self.behaviour
                                );
                            self.sign.update_state_r6(out_bcast)
                        }
                        r6::Output::Fail { out_bcast } => {
                            warn!(
                                    "malicious participant {} can't do {:?} because protocol has failed; reverting to honesty",
                                    self.sign.my_participant_index, self.behaviour
                                );
                            self.sign.update_state_r6fail(out_bcast)
                        }
                        r6::Output::FailType5 { mut out_bcast } => {
                            info!(
                                "malicious participant {} do {:?} (beta_ij)",
                                self.sign.my_participant_index, self.behaviour
                            );
                            let mta_plaintext = out_bcast.mta_plaintexts[victim].as_mut().unwrap();

                            // curv: don't do anything
                            // let one: FE = ECScalar::from(&BigInt::from(1));
                            // mta_plaintext.beta = mta_plaintext.beta + one;

                            // k256
                            *mta_plaintext.beta_secrets_k256.beta.unwrap_mut() +=
                                k256::Scalar::one();

                            self.sign.update_state_r6fail_type5(out_bcast)
                        }
                    },
                    status => {
                        error!(
                            "malicious participant {} unexpected status {:?}, can't do {:?}",
                            self.sign.my_participant_index, status, self.behaviour
                        );
                        self.sign.next_round()
                    }
                }
            }
            R4BadReveal => {
                if !matches!(self.sign.status, Status::R3) {
                    return self.sign.next_round();
                };
                match self.sign.r4() {
                    r4::Output::Success {
                        state,
                        mut out_bcast,
                    } => {
                        info!(
                            "malicious participant {} do {:?}",
                            self.sign.my_participant_index, self.behaviour
                        );
                        out_bcast.Gamma_i_reveal_k256.corrupt();
                        self.sign.update_state_r4(state, out_bcast)
                    }
                    r4::Output::Fail { criminals } => {
                        warn!(
                            "malicious participant {} can't do {:?} because protocol has failed; reverting to honesty",
                            self.sign.my_participant_index, self.behaviour,
                        );
                        self.sign.update_state_fail(criminals);
                        Ok(())
                    }
                }
            }
            R5BadProof { victim } => {
                if !matches!(self.sign.status, Status::R4) {
                    return self.sign.next_round();
                };
                if victim == self.sign.my_participant_index {
                    warn!(
                        "malicious participant {} can't do {:?} on myself; reverting to honesty",
                        self.sign.my_participant_index, self.behaviour
                    );
                    return self.sign.next_round();
                }
                match self.sign.r5() {
                    r5::Output::Success {
                        state,
                        out_bcast,
                        mut out_p2ps,
                    } => {
                        info!(
                            "malicious participant {} do {:?}",
                            self.sign.my_participant_index, self.behaviour
                        );

                        // k256
                        let proof_k256 = &mut out_p2ps.vec_ref_mut()[victim]
                            .as_mut()
                            .unwrap()
                            .k_i_range_proof_wc_k256;
                        *proof_k256 =
                            paillier_k256::zk::range::malicious::corrupt_proof_wc(proof_k256);

                        self.sign.update_state_r5(state, out_bcast, out_p2ps)
                    }
                    r5::Output::Fail { criminals } => {
                        warn!(
                            "malicious participant {} can't do {:?} because protocol has failed; reverting to honesty",
                            self.sign.my_participant_index, self.behaviour
                        );
                        self.sign.update_state_fail(criminals);
                        Ok(())
                    }
                }
            }
            R6FalseAccusation { victim } => {
                if !matches!(self.sign.status, Status::R5) {
                    return self.sign.next_round();
                };
                // no need to execute self.s.r6()
                info!(
                    "malicious participant {} do {:?}",
                    self.sign.my_participant_index, self.behaviour
                );
                self.sign.update_state_r6fail(r6::BcastFail {
                    culprits: vec![r6::Culprit {
                        participant_index: victim,
                        crime: r6::Crime::RangeProofWc,
                    }],
                })
            }
            R6BadProof => {
                if !matches!(self.sign.status, Status::R5) {
                    return self.sign.next_round();
                };
                match self.sign.r6() {
                    r6::Output::Success { mut out_bcast } => {
                        info!(
                            "malicious participant {} do {:?}",
                            self.sign.my_participant_index, self.behaviour
                        );

                        // k256
                        let proof_k256 = &mut out_bcast.S_i_proof_wc_k256;
                        *proof_k256 = pedersen_k256::malicious::corrupt_proof_wc(proof_k256);

                        self.sign.update_state_r6(out_bcast)
                    }
                    r6::Output::Fail { out_bcast } => {
                        warn!(
                            "malicious participant {} can't do {:?} because protocol has failed; reverting to honesty",
                            self.sign.my_participant_index, self.behaviour
                        );
                        self.sign.update_state_r6fail(out_bcast)
                    }
                    r6::Output::FailType5 { out_bcast } => {
                        warn!(
                            "malicious participant {} can't do {:?} because protocol has failed; reverting to honesty",
                            self.sign.my_participant_index, self.behaviour
                        );
                        self.sign.update_state_r6fail_type5(out_bcast)
                    }
                }
            }
            R6FalseFailRandomizer => {
                if !matches!(self.sign.status, Status::R5) {
                    return self.sign.next_round();
                };
                // no need to execute self.s.r6()
                info!(
                    "malicious participant {} do {:?}",
                    self.sign.my_participant_index, self.behaviour
                );
                self.sign
                    .update_state_r6fail_type5(self.sign.type5_fault_output())
            }
            R7BadSI => {
                if !matches!(self.sign.status, Status::R6) {
                    return self.sign.next_round();
                };
                match self.sign.r7() {
                    r7::Output::Success {
                        state,
                        mut out_bcast,
                    } => {
                        info!(
                            "malicious participant {} do {:?}",
                            self.sign.my_participant_index, self.behaviour
                        );

                        // curv: don't do anything
                        // need to corrupt both state and out_bcast
                        // because they both contain a copy of ecdsa_sig_summand
                        // let one: FE = ECScalar::from(&BigInt::from(1));
                        // let ecdsa_sig_summand = &mut out_bcast.s_i;
                        // *ecdsa_sig_summand = *ecdsa_sig_summand + one;
                        // let ecdsa_sig_summand_state = &mut state.s_i;
                        // *ecdsa_sig_summand_state = *ecdsa_sig_summand_state + one;

                        // k256
                        *out_bcast.s_i_k256.unwrap_mut() += k256::Scalar::one();

                        self.sign.update_state_r7(state, out_bcast)
                    }
                    r7::Output::Fail { criminals } => {
                        warn!(
                            "malicious participant {} can't do {:?} because protocol has failed; reverting to honesty",
                            self.sign.my_participant_index, self.behaviour
                        );
                        self.sign.update_state_fail(criminals);
                        Ok(())
                    }
                    r7::Output::FailType7 { out_bcast } => {
                        warn!(
                            "malicious participant {} can't do {:?} because protocol has failed; reverting to honesty",
                            self.sign.my_participant_index, self.behaviour
                        );
                        self.sign.update_state_r7fail_type7(out_bcast)
                    }
                }
            }
        }
    }
    fn set_msg_in(&mut self, msg: &[u8], index_range: &IndexRange) {
        self.sign.set_msg_in(msg, index_range);
    }
    fn get_bcast_out(&self) -> &Option<MsgBytes> {
        self.sign.get_bcast_out()
    }
    fn get_p2p_out(&self) -> &Option<Vec<Option<MsgBytes>>> {
        self.sign.get_p2p_out()
    }
    fn expecting_more_msgs_this_round(&self) -> bool {
        self.sign.expecting_more_msgs_this_round()
    }
    fn done(&self) -> bool {
        self.sign.done()
    }
}

// #[cfg(test)]
// mod tests;
