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
    R8FailRandomizerMissingData, // TODO: rename. this happens when parties falsely pretend `type 5` success
    R8FailRandomizerBadNonceXBlindSummand,
    R8FailRandomizerBadNonceSummand,
    R8FailRandomizerBadBlindSummand,
    R8FailRandomizerMtaBlindSummandRhs { victim: usize },
    R8FailRandomizerMtaBlindSummandLhs { victim: usize },
    R8FailRandomizerFalseComplaint,
    R8BadSigSummand,
}
