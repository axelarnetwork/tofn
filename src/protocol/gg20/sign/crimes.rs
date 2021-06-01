use crate::protocol::gg20::sign::{MsgType, Status};
// all crimes
// names have the form <round><crime> where
// <round> indicates round where the crime is detected, and
// <crime> is a description
// example: R3FailBadProof -> crime detected in r3_fail()
#[derive(Debug, Clone, PartialEq)]
pub enum Crime {
    SpoofedMessage { victim: usize, status: Status },
    StalledMessage { msg_type: MsgType },
    DisruptedMessage,
    R3FailBadRangeProof { victim: usize },
    R3FailFalseAccusation { victim: usize },
    R4BadPedersenProof,
    R4FailBadMta { victim: usize },
    R4FailBadMtaWc { victim: usize },
    R4FailFalseAccusationMta { victim: usize },
    R4FailFalseAccusationMtaWc { victim: usize },
    R5BadHashCommit,
    R7FailBadRangeProof { victim: usize },
    R7FailFalseAccusation { victim: usize },
    R7BadRangeProof,
    R7FailType5MissingData, // TODO missing unit test
    R7FailType5BadDeltaI,
    R7FailType5BadKI,
    R7FailType5BadGammaI,
    R7FailType5BadBeta { victim: usize },
    R7FailType5BadAlpha { victim: usize },
    R7FailType5FalseComplaint,
    R8BadSigSummand,
    R8FailType7MissingData,     // TODO missing unit test
    R8FailType7BadNonceSummand, // TODO missing unit test
    R8FailType7MtaWcKeyshareSummandLhs { victim: usize }, // TODO missing unit test
    R8FailType7BadZkp,
}
