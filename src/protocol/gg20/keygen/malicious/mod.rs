use strum_macros::EnumIter;
// all malicious behaviours
// names have the form <round><fault> where
// <round> indicates round where the first malicious tampering occurs, and
// <fault> is a description
// example: R1BadProof -> fault injected to the output of r1()
#[derive(Clone, Debug, EnumIter)]
pub enum Behaviour {
    Honest,
    R1BadCommit,
    R2BadShare { victim: usize },
}

#[cfg(test)]
mod tests;
