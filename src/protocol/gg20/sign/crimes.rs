use crate::protocol::{CrimeType, Criminal};

// all possible crimes
// variant names are of the form <Status><Crime>
#[derive(Debug, Clone, PartialEq)]
pub(super) enum Crime {
    R3BadRangeProof { victim: usize },
    R3FalseAccusation { victim: usize },
    R4BadRangeProof { victim: usize },
    R4FalseAccusation { victim: usize },
    R5BadRangeProof { victim: usize },
    R5FalseAccusation { victim: usize },
    R6BadHashCommit { victim: usize },
    R6FalseAccusation { victim: usize },
    R7BadRangeProof { victim: usize },
    R7FalseAccusation { victim: usize },
    R8BadRangeProof { victim: usize },
    R8FalseAccusation { victim: usize },
    R8MissingData, // TODO: Add a unit test for this
    R8BadNonceXBlindSummand,
    R8BadNonceSummand,
    R8BadBlindSummand,
    R8MtaBlindSummandRhs { victim: usize },
    R8MtaBlindSummandLhs { victim: usize },
    R8FalseComplaint,
}

// helper function
pub(super) fn to_criminals(criminals: &[Vec<Crime>]) -> Vec<Criminal> {
    criminals
        .iter()
        .enumerate()
        .filter_map(|(i, v)| {
            if v.is_empty() {
                None
            } else {
                Some(Criminal {
                    index: i,
                    crime_type: CrimeType::Malicious,
                })
            }
        })
        .collect()
}
