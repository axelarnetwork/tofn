use crate::protocol::{CrimeType, Criminal};

// all possible crimes
// variant names are of the form <Status><Crime>
// #[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) enum Crime {
    R3BadRangeProof { victim: usize },
    R3FalseAccusation { victim: usize },
}

// helper function
pub(super) fn into_criminals(criminals: Vec<Vec<Crime>>) -> Vec<Criminal> {
    criminals
        .into_iter()
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
