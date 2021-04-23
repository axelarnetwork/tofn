use super::{r2, r3, r4, r5, r6, r7, ParamsError, Sign, SignOutput, Status};
use crate::protocol::{gg20::keygen::SecretKeyShare, MsgBytes, Protocol, ProtocolResult};
use crate::zkp::{mta, pedersen, range};
use curv::{elliptic::curves::traits::ECScalar, BigInt, FE};
use tracing::{info, warn};

#[derive(Clone)]
pub enum MaliciousType {
    // TODO R1BadCommit,
    Honest,
    R1BadProof { victim: usize },
    R1FalseAccusation { victim: usize },
    R2BadMta { victim: usize },
    R2BadMtaWc { victim: usize },
    R2FalseAccusationMta { victim: usize },
    R2FalseAccusationMtaWc { victim: usize },
    R3BadProof,
    R3FalseAccusation { victim: usize },
    R4BadReveal,
    R4FalseAccusation { victim: usize },
    R5BadProof { victim: usize },
    R5FalseAccusation { victim: usize },
    R6BadProof,
    R6FalseAccusation { victim: usize },
    R7BadSigSummand,
}
use MaliciousType::*;

pub struct BadSign {
    sign: Sign,
    malicious_type: MaliciousType,
}

impl BadSign {
    pub fn new(
        my_secret_key_share: &SecretKeyShare,
        participant_indices: &[usize],
        msg_to_sign: &[u8],
        malicious_type: MaliciousType,
    ) -> Result<Self, ParamsError> {
        Ok(Self {
            sign: Sign::new(my_secret_key_share, participant_indices, msg_to_sign)?,
            malicious_type,
        })
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

        match self.malicious_type {
            Honest => self.sign.next_round(),
            R1BadProof { victim } => {
                if !matches!(self.sign.status, Status::New) {
                    return self.sign.next_round();
                };
                let (state, bcast, mut p2ps) = self.sign.r1();

                info!(
                    "malicious participant {} r1 corrupt proof to {}",
                    self.sign.my_participant_index, victim
                );
                let proof = &mut p2ps.vec_ref_mut()[victim].as_mut().unwrap().range_proof;
                *proof = range::malicious::corrupt_proof(proof);

                self.sign.update_state_r1(state, bcast, p2ps)
            }
            R1FalseAccusation { victim } => {
                if !matches!(self.sign.status, Status::R1) {
                    return self.sign.next_round();
                };
                // no need to execute self.s.r2()
                info!(
                    "malicious participant {} r1 falsely accuse {}",
                    self.sign.my_participant_index, victim
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
                match self.sign.r2() {
                    r2::Output::Success {
                        state,
                        mut out_p2ps,
                    } => {
                        info!(
                            "malicious participant {} r2 corrupt mta proof to {}",
                            self.sign.my_participant_index, victim
                        );
                        let proof = &mut out_p2ps.vec_ref_mut()[victim].as_mut().unwrap().mta_proof;
                        *proof = mta::malicious::corrupt_proof(proof);

                        self.sign.update_state_r2(state, out_p2ps)
                    }
                    r2::Output::Fail { out_bcast } => {
                        warn!(
                            "malicious participant {} instructed to corrupt r2 mta proof to {} but r2 has already failed so reverting to honesty",
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
                match self.sign.r2() {
                    r2::Output::Success {
                        state,
                        mut out_p2ps,
                    } => {
                        info!(
                            "malicious participant {} r2 corrupt mta_wc proof to {}",
                            self.sign.my_participant_index, victim
                        );
                        let proof = &mut out_p2ps.vec_ref_mut()[victim]
                            .as_mut()
                            .unwrap()
                            .mta_proof_wc;
                        *proof = mta::malicious::corrupt_proof_wc(proof);

                        self.sign.update_state_r2(state, out_p2ps)
                    }
                    r2::Output::Fail { out_bcast } => {
                        warn!(
                            "malicious participant {} instructed to corrupt r2 mta_wc proof to {} but r2 has already failed so reverting to honesty",
                            self.sign.my_participant_index, victim
                        );
                        self.sign.update_state_r2fail(out_bcast)
                    }
                }
            }
            R2FalseAccusationMta { victim } => {
                if !matches!(self.sign.status, Status::R2) {
                    return self.sign.next_round();
                };
                // no need to execute self.s.r3()
                info!(
                    "malicious participant {} r2 falsely accuse {} mta",
                    self.sign.my_participant_index, victim
                );
                self.sign.update_state_r3fail(r3::FailBcast {
                    culprits: vec![r3::Culprit {
                        participant_index: victim,
                        crime: r3::Crime::Mta,
                    }],
                })
            }
            R2FalseAccusationMtaWc { victim } => {
                // TODO refactor copied code from R2FalseAccusationMta
                if !matches!(self.sign.status, Status::R2) {
                    return self.sign.next_round();
                };
                // no need to execute self.s.r3()
                info!(
                    "malicious participant {} r2 falsely accuse {} mta_wc",
                    self.sign.my_participant_index, victim
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
                            "malicious participant {} r3 corrupt pedersen proof",
                            self.sign.my_participant_index
                        );
                        let proof = &mut out_bcast.nonce_x_keyshare_summand_proof;
                        *proof = pedersen::malicious::corrupt_proof(proof);

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
            R3FalseAccusation { victim } => {
                if !matches!(self.sign.status, Status::R3) {
                    return self.sign.next_round();
                };
                // no need to execute self.s.r4()
                info!(
                    "malicious participant {} r3 falsely accuse {}",
                    self.sign.my_participant_index, victim
                );
                self.sign.update_state_r4fail(r4::FailBcast {
                    culprits: vec![r4::Culprit {
                        participant_index: victim,
                        crime: r4::Crime::PedersenProof,
                    }],
                })
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
                            "malicious participant {} r4 corrupt commit reveal",
                            self.sign.my_participant_index
                        );
                        let reveal = &mut out_bcast.reveal;
                        *reveal += BigInt::from(1);

                        self.sign.update_state_r4(state, out_bcast)
                    }
                    r4::Output::Fail { out_bcast } => {
                        warn!(
                            "malicious participant {} instructed to corrupt r4 commit reveal but r4 has already failed so reverting to honesty",
                            self.sign.my_participant_index
                        );
                        self.sign.update_state_r4fail(out_bcast)
                    }
                }
            }
            R4FalseAccusation { victim } => {
                if !matches!(self.sign.status, Status::R4) {
                    return self.sign.next_round();
                };
                // no need to execute self.s.r5()
                info!(
                    "malicious participant {} r4 falsely accuse {}",
                    self.sign.my_participant_index, victim
                );
                self.sign.update_state_r5fail(r5::FailBcast {
                    culprits: vec![r5::Culprit {
                        participant_index: victim,
                        crime: r5::Crime::CommitReveal,
                    }],
                })
            }
            R5BadProof { victim } => {
                if !matches!(self.sign.status, Status::R4) {
                    return self.sign.next_round();
                };
                match self.sign.r5() {
                    r5::Output::Success {
                        state,
                        out_bcast,
                        mut out_p2ps,
                    } => {
                        info!(
                            "malicious participant {} r5 corrupt range proof wc",
                            self.sign.my_participant_index
                        );
                        let proof = &mut out_p2ps.vec_ref_mut()[victim]
                            .as_mut()
                            .unwrap()
                            .ecdsa_randomizer_x_nonce_summand_proof;
                        *proof = range::malicious::corrupt_proof_wc(proof);

                        self.sign.update_state_r5(state, out_bcast, out_p2ps)
                    }
                    r5::Output::Fail { out_bcast } => {
                        warn!(
                            "malicious participant {} instructed to corrupt r5 range proof wc but r5 has already failed so reverting to honesty",
                            self.sign.my_participant_index
                        );
                        self.sign.update_state_r5fail(out_bcast)
                    }
                }
            }
            R5FalseAccusation { victim } => {
                if !matches!(self.sign.status, Status::R5) {
                    return self.sign.next_round();
                };
                // no need to execute self.s.r6()
                info!(
                    "malicious participant {} r5 falsely accuse {}",
                    self.sign.my_participant_index, victim
                );
                self.sign.update_state_r6fail(r6::FailBcast {
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
                    r6::Output::Success {
                        state,
                        mut out_bcast,
                    } => {
                        info!(
                            "malicious participant {} r6 corrupt pedersen proof Wc",
                            self.sign.my_participant_index
                        );
                        let proof = &mut out_bcast.ecdsa_public_key_check_proof_wc;
                        *proof = pedersen::malicious::corrupt_proof_wc(proof);

                        self.sign.update_state_r6(state, out_bcast)
                    }
                    r6::Output::Fail { out_bcast } => {
                        warn!(
                            "malicious participant {} instructed to corrupt r6 pedersen proof wc but r6 has already failed so reverting to honesty",
                            self.sign.my_participant_index
                        );
                        self.sign.update_state_r6fail(out_bcast)
                    }
                }
            }
            R6FalseAccusation { victim } => {
                if !matches!(self.sign.status, Status::R6) {
                    return self.sign.next_round();
                };
                // no need to execute self.s.r7()
                info!(
                    "malicious participant {} r6 falsely accuse {}",
                    self.sign.my_participant_index, victim
                );
                self.sign.update_state_r7fail(r7::FailBcast {
                    culprits: vec![r7::Culprit {
                        participant_index: victim,
                        crime: r7::Crime::PedersenProofWc,
                    }],
                })
            }
            R7BadSigSummand => {
                if !matches!(self.sign.status, Status::R6) {
                    return self.sign.next_round();
                };
                match self.sign.r7() {
                    r7::Output::Success {
                        mut state,
                        mut out_bcast,
                    } => {
                        info!(
                            "malicious participant {} r7 corrupt ecdsa_sig_summand",
                            self.sign.my_participant_index
                        );
                        let one: FE = ECScalar::from(&BigInt::from(1));
                        // need to corrupt both state and out_bcast
                        // because they both contain a copy of ecdsa_sig_summand
                        let ecdsa_sig_summand = &mut out_bcast.ecdsa_sig_summand;
                        *ecdsa_sig_summand = *ecdsa_sig_summand + one;
                        let ecdsa_sig_summand_state = &mut state.my_ecdsa_sig_summand;
                        *ecdsa_sig_summand_state = *ecdsa_sig_summand_state + one;

                        self.sign.update_state_r7(state, out_bcast)
                    }
                    r7::Output::Fail { out_bcast } => {
                        warn!(
                            "malicious participant {} instructed to corrupt r7 ecdsa_sig_summand but r7 has already failed so reverting to honesty",
                            self.sign.my_participant_index
                        );
                        self.sign.update_state_r7fail(out_bcast)
                    }
                }
            }
        }
    }
    fn set_msg_in(&mut self, msg: &[u8]) -> ProtocolResult {
        self.sign.set_msg_in(msg)
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

#[cfg(test)]
mod tests;
