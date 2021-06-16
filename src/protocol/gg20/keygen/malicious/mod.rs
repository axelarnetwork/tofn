use crate::protocol::gg20::keygen::{Keygen, Status};
use strum_macros::EnumIter;

use super::MsgType;
// all malicious behaviours
// names have the form <round><fault> where
// <round> indicates round where the first malicious tampering occurs, and
// <fault> is a description
// example: R1BadProof -> fault injected to the output of r1()
#[derive(Clone, Debug, EnumIter)]
pub enum Behaviour {
    Honest,
    Staller { msg_type: MsgType },
    UnauthenticatedSender { victim: usize, status: Status },
    DisruptingSender { msg_type: MsgType },
    R1BadCommit,
    R1BadZkSetupProof,
    R2BadShare { victim: usize },
    R2BadEncryption { victim: usize },
    R3FalseAccusation { victim: usize },
    R3BadXIWitness,
}

impl Keygen {
    pub fn set_behaviour(&mut self, behaviour: Behaviour) {
        self.behaviour = behaviour;
    }
}

#[cfg(test)]
mod tests;
