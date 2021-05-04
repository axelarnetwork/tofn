// all crimes
// names have the form <round><crime> where
// <round> indicates round where the crime is detected, and
// <crime> is a description
// example: R3FailBadProof -> crime detected in r3_fail()
#[derive(Debug, Clone, PartialEq)]
pub enum Crime {
    R3FailBadRangeProof { victim: usize },
    R3FailFalseAccusation { victim: usize },
    R4BadPedersenProof,
    R4FailBadRangeProof { victim: usize },
    R4FailFalseAccusation { victim: usize },
    R5BadHashCommit,
    R7FailBadRangeProof { victim: usize },
    R7FailFalseAccusation { victim: usize },
    R7BadRangeProof,
    R7FailType5MissingData, // TODO missing unit test
    R7FailType5BadNonceXBlindSummand,
    R7FailType5BadNonceSummand,
    R7FailType5BadBlindSummand,
    R7FailType5MtaBlindSummandRhs { victim: usize },
    R7FailType5MtaBlindSummandLhs { victim: usize },
    R7FailType5FalseComplaint,
    R8BadSigSummand,
}
