// all crimes
// names have the form <round><crime> where
// <round> indicates round where the crime is detected, and
// <crime> is a description
// example: R3FailBadProof -> crime detected in r3_fail()
#[derive(Debug, Clone, PartialEq)]
pub enum Crime {
    R3BadReveal,
    R3BadVss { victim: usize },
    R4FailFalseAccusation { victim: usize },
}
