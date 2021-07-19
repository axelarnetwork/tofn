use tracing::info;

use crate::refactor::collections::{Behave, TypedUsize};

use super::SignParticipantIndex;

// all malicious behaviours
// names have the form <round><fault> where
// <round> indicates round where the first malicious tampering occurs, and
// <fault> is a description
// example: R1BadProof -> fault injected to the output of r1()
#[derive(Clone, Debug)]
pub enum Behaviour {
    Honest,
    // TODO R1BadCommit,
    UnauthenticatedSender {
        victim: TypedUsize<SignParticipantIndex>,
        status: Status,
    },
    Staller {
        msg_type: MsgType,
    },
    DisrupringSender {
        msg_type: MsgType,
    },
    R3BadSigmaI, // triggers r7::Output::FailType7
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

    // Timeout, // TODO how to test timeouts?
    CorruptMessage {
        msg_type: MsgType,
    },
    R1BadCommit,
    R1BadEncryptionKeyProof,
    R1BadZkSetupProof,
    R2BadShare {
        victim: TypedUsize<SignParticipantIndex>,
    },
    R2BadEncryption {
        victim: TypedUsize<SignParticipantIndex>,
    },
    R3FalseAccusation {
        victim: TypedUsize<SignParticipantIndex>,
    },
    R3BadXIWitness,
}

impl Behaviour {
    pub fn is_honest(&self) -> bool {
        matches!(self, Self::Honest)
    }
}

#[derive(Clone, Debug)]
pub enum MsgType {
    R1Bcast,
    R1P2p {
        to: TypedUsize<SignParticipantIndex>,
    },
    R2P2p {
        to: TypedUsize<SignParticipantIndex>,
    },
    R2FailBcast,
    R3Bcast,
    R3FailBcast,
    R4Bcast,
    R5Bcast,
    R5P2p {
        to: TypedUsize<SignParticipantIndex>,
    },
    R6Bcast,
    R6FailBcast,
    R6FailType5Bcast,
    R7Bcast,
    R7FailType7Bcast,
}

#[derive(Clone, Debug)]
pub enum Status {
    New,
    R1,
    R2,
    R2Fail,
    R3,
    R3Fail,
    R4,
    R5,
    R6,
    R6Fail,
    R6FailType5,
    R7,
    R7FailType7,
    Done,
    Fail,
}

pub(crate) fn log_confess_info<K>(me: TypedUsize<K>, behaviour: &Behaviour, msg: &str)
where
    K: Behave,
{
    if msg.is_empty() {
        info!("malicious peer {} does {:?}", me, behaviour);
    } else {
        info!("malicious peer {} does {:?} [{}]", me, behaviour, msg);
    }
}
