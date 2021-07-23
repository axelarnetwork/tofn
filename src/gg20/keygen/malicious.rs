use tracing::info;

use crate::collections::TypedUsize;

use super::KeygenPartyIndex;

// all malicious behaviours
// names have the form <round><fault> where
// <round> indicates round where the first malicious tampering occurs, and
// <fault> is a description
// example: R1BadProof -> fault injected to the output of r1()
// #[derive(Clone, Debug, EnumIter)]
#[derive(Clone, Debug)]
pub enum Behaviour {
    Honest,
    R1BadCommit,
    R1BadEncryptionKeyProof,
    R1BadZkSetupProof,
    R2BadShare {
        victim: TypedUsize<KeygenPartyIndex>,
    },
    R2BadEncryption {
        victim: TypedUsize<KeygenPartyIndex>,
    },
    R3FalseAccusation {
        victim: TypedUsize<KeygenPartyIndex>,
    },
    R3BadXIWitness,
}

impl Behaviour {
    pub fn is_honest(&self) -> bool {
        matches!(self, Self::Honest)
    }
}

pub(crate) fn log_confess_info<K>(me: TypedUsize<K>, behaviour: &Behaviour, msg: &str) {
    if msg.is_empty() {
        info!("malicious peer {} do {:?}", me, behaviour);
    } else {
        info!("malicious peer {} do {:?} [{}]", me, behaviour, msg);
    }
}

// #[cfg(test)]
// mod tests;
