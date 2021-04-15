use super::{r2, r3, r4, ParamsError, Sign, SignOutput, Status};
use crate::protocol::{gg20::keygen::SecretKeyShare, MsgBytes, Protocol, ProtocolResult};
use crate::zkp::{mta, pedersen, range};
use curv::BigInt;
use tracing::{info, warn};

pub enum MaliciousType {
    // TODO R1BadCommit,
    R1BadProof { victim: usize },
    R1FalseAccusation { victim: usize },
    R2BadMta { victim: usize },
    R2BadMtaWc { victim: usize },
    R2FalseAccusationMta { victim: usize },
    R2FalseAccusationMtaWc { victim: usize },
    R3BadProof,
    R4BadReveal,
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
        match self.malicious_type {
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
                *proof = range::corrupt_proof(proof);

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
                        *proof = mta::corrupt_proof(proof);

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
                        *proof = mta::corrupt_proof_wc(proof);

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
                        *proof = pedersen::corrupt_proof(proof);

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
