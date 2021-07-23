use tracing::info;

use crate::refactor::collections::TypedUsize;

use super::SignParticipantIndex;

// all malicious behaviours
// names have the form <round><fault> where
// <round> indicates round where the first malicious tampering occurs, and
// <fault> is a description
// example: R1BadProof -> fault injected to the output of r1
#[derive(Clone, Debug)]
pub enum Behaviour {
    Honest,
    R1BadProof {
        victim: TypedUsize<SignParticipantIndex>,
    },
    R1BadGammaI, // triggers r6::Output::FailType5
    R2FalseAccusation {
        victim: TypedUsize<SignParticipantIndex>,
    },
    R2BadMta {
        victim: TypedUsize<SignParticipantIndex>,
    },
    R2BadMtaWc {
        victim: TypedUsize<SignParticipantIndex>,
    },
    R3BadSigmaI, // triggers r7::Output::FailType7
    R3FalseAccusationMta {
        victim: TypedUsize<SignParticipantIndex>,
    },
    R3FalseAccusationMtaWc {
        victim: TypedUsize<SignParticipantIndex>,
    },
    R3BadProof,
    R3BadDeltaI, // triggers r6::Output::FailType5
    R3BadKI,     // triggers r6::Output::FailType5
    R3BadAlpha {
        victim: TypedUsize<SignParticipantIndex>,
    }, // triggers r6::Output::FailType5
    R3BadBeta {
        victim: TypedUsize<SignParticipantIndex>,
    }, // triggers r6::Output::FailType5
    R4BadReveal,
    R5BadProof {
        victim: TypedUsize<SignParticipantIndex>,
    },
    R6FalseAccusation {
        victim: TypedUsize<SignParticipantIndex>,
    },
    R6BadProof,
    R6FalseFailRandomizer,
    R7BadSI,
}

impl Behaviour {
    pub fn is_honest(&self) -> bool {
        matches!(self, Self::Honest)
    }
}

pub(crate) fn log_confess_info<K>(me: TypedUsize<K>, behaviour: &Behaviour, msg: &str) {
    if msg.is_empty() {
        info!("malicious peer {} does {:?}", me, behaviour);
    } else {
        info!("malicious peer {} does {:?} [{}]", me, behaviour, msg);
    }
}
