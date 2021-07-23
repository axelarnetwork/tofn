// use strum_macros::EnumIter;

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

// #[derive(Clone, Debug)]
// pub enum MsgType {
//     R1Bcast,
//     R2Bcast,
//     R2P2p { to: TypedUsize<KeygenPartyIndex> },
//     R3Bcast,
//     R3FailBcast,
// }

// `EnumIter` derivation for `Behaviour` requires `Default` impls
// https://docs.rs/strum/0.14.0/strum/?search=#strum-macros
// impl Default for MsgType {
//     fn default() -> Self {
//         MsgType::R1Bcast
//     }
// }
// impl Default for Index<KeygenPartyIndex> {
//     fn default() -> Self {
//         Self::from_usize(0)
//     }
// }

pub(crate) fn log_confess_info<K>(me: TypedUsize<K>, behaviour: &Behaviour, msg: &str) {
    if msg.is_empty() {
        info!("malicious peer {} do {:?}", me, behaviour);
    } else {
        info!("malicious peer {} do {:?} [{}]", me, behaviour, msg);
    }
}

// #[cfg(test)]
// mod tests;
