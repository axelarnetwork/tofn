use super::{r2, ParamsError, Sign, SignOutput, Status};
use crate::protocol::{gg20::keygen::SecretKeyShare, MsgBytes, Protocol, ProtocolResult};
use crate::zkp::range::corrupt_proof;
pub enum MaliciousType {
    // corrupt proof at r1
    R1BadProof(usize),
    // falsely accuse a participant
    FalseAccusation(usize),
}

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
            MaliciousType::R1BadProof(victim) => {
                if !matches!(self.sign.status, Status::New) {
                    return self.sign.next_round();
                };
                let (state, bcast, mut p2ps) = self.sign.r1();
                // corrupt the proof to self.victim
                let proof = &mut p2ps.vec_ref_mut()[victim].as_mut().unwrap().range_proof;
                *proof = corrupt_proof(proof);

                self.sign.update_state_r1(state, bcast, p2ps)?;
                Ok(())
            }
            MaliciousType::FalseAccusation(victim) => {
                if !matches!(self.sign.status, Status::R1) {
                    return self.sign.next_round();
                };

                // falsely accuse `victim` of a bad proof in r1
                // no need to execute self.s.r2()
                println!(
                    "participant {} falsely accuse {}",
                    self.sign.my_participant_index, victim
                );
                self.sign.update_state_r2fail(r2::FailBcast {
                    culprits: vec![r2::Culprit {
                        participant_index: victim,
                    }],
                })
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
pub(crate) mod tests;
