use tracing::info;

use crate::collections::TypedUsize;

use super::SignShareId;

// all malicious behaviours
// names have the form <round><fault> where
// <round> indicates round where the first malicious tampering occurs, and
// <fault> is a description
// example: R1BadProof -> fault injected to the output of r1
#[derive(Clone, Debug)]
pub enum Behaviour {
    Honest,
    R1BadProof { victim: TypedUsize<SignShareId> },
    R1BadGammaI, // triggers r6::Output::FailType5
    R2FalseAccusation { victim: TypedUsize<SignShareId> },
    R2BadMta { victim: TypedUsize<SignShareId> },
    R2BadMtaWc { victim: TypedUsize<SignShareId> },
    R3BadSigmaI, // triggers r7::Output::FailType7
    R3FalseAccusationMta { victim: TypedUsize<SignShareId> },
    R3FalseAccusationMtaWc { victim: TypedUsize<SignShareId> },
    R3BadProof,
    R3BadDeltaI,                                    // triggers r6::Output::FailType5
    R3BadKI,                                        // triggers r6::Output::FailType5
    R3BadAlpha { victim: TypedUsize<SignShareId> }, // triggers r6::Output::FailType5
    R3BadBeta { victim: TypedUsize<SignShareId> },  // triggers r6::Output::FailType5
    R4BadReveal,
    R5BadProof { victim: TypedUsize<SignShareId> },
    R6FalseAccusation { victim: TypedUsize<SignShareId> },
    R6BadProof,
    R6FalseFailRandomizer,
    R7BadSI,
}

impl Behaviour {
    pub fn is_honest(&self) -> bool {
        matches!(self, Self::Honest)
    }
}

pub(crate) fn log_confess_info<K>(sign_id: TypedUsize<K>, behaviour: &Behaviour, msg: &str) {
    if msg.is_empty() {
        info!("malicious peer {} does {:?}", sign_id, behaviour);
    } else {
        info!("malicious peer {} does {:?} [{}]", sign_id, behaviour, msg);
    }
}
