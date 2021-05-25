use crate::protocol::gg20::keygen::{MsgType, Status};

// all crimes
// names have the form <round><crime> where
// <round> indicates round where the crime is detected, and
// <crime> is a description
// example: R3FailBadProof -> crime detected in r3_fail()
#[derive(Debug, Clone, PartialEq)]
pub enum Crime {
    StalledMessage { msg_type: MsgType },
    SpoofedMessage { victim: usize, status: Status },
    DisruptedMessage {},
    R3BadReveal,
    R4FailBadVss { victim: usize },
    R4FailBadEncryption { victim: usize },
    R4FailFalseAccusation { victim: usize },
}
