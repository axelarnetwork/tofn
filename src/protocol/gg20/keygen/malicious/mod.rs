use strum_macros::EnumIter;
use crate::protocol::gg20::keygen::Status;
// all malicious behaviours
// names have the form <round><fault> where
// <round> indicates round where the first malicious tampering occurs, and
// <fault> is a description
// example: R1BadProof -> fault injected to the output of r1()
#[derive(Clone, Debug, EnumIter)]
pub enum Behaviour {
    Honest,
    UnauthenticatedSender { victim: usize, status: Status },
    R1BadCommit,
    R2BadShare { victim: usize },
    R2BadEncryption { victim: usize },
    R3FalseAccusation { victim: usize },
}

#[cfg(test)]
mod tests;
