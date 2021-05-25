use crate::protocol::gg20::keygen::Status;
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
    DisruptingSender { victim: usize, msg_type: MsgType },
    R1BadCommit,
    R2BadShare { victim: usize },
    R2BadEncryption { victim: usize },
    R3FalseAccusation { victim: usize },
}

#[cfg(test)]
mod tests;
