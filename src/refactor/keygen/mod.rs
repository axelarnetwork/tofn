use serde::de::DeserializeOwned;

use crate::protocol::gg20::SecretKeyShare;
use crate::refactor::protocol::{
    executer::{DeTimeout, ProtocolBuilder, RoundData, RoundExecuterTyped},
    Protocol, ProtocolRound,
};

use super::TofnResult;

pub struct KeygenPartyIndex;

pub type KeygenProtocol = Protocol<KeygenOutput, KeygenPartyIndex>;
pub type KeygenProtocolBuilder = ProtocolBuilder<KeygenOutput, KeygenPartyIndex>;
pub type KeygenOutput = Result<SecretKeyShare, Vec<Vec<Crime>>>;
pub type SecretRecoveryKey = [u8; 64];

pub const MAX_SHARE_COUNT: usize = 1000;

/// Alias `RoundExecuter` so that every round does not need `type FinalOutputTyped = KeygenOutput;`
/// TODO Is all this cruft worth it to save one line in each round? Trait aliasing is not supported, even if we switch the associated type `FinalOutput` to a generic type parameter `F`: https://github.com/rust-lang/rust/issues/41517
pub trait KeygenRoundExecuterTyped: Send + Sync {
    type Bcast: DeserializeOwned;
    type P2p: DeserializeOwned;

    fn execute_typed(
        self: Box<Self>,
        data: RoundData<Self::Bcast, Self::P2p>,
    ) -> KeygenProtocolBuilder;

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        unimplemented!("(KeygenRoundExecuterTyped) return `self` to enable runtime reflection: https://bennetthardwick.com/dont-use-boxed-trait-objects-for-struct-internals")
    }
}
impl<T: KeygenRoundExecuterTyped> RoundExecuterTyped for T {
    type FinalOutputTyped = KeygenOutput;
    type Index = KeygenPartyIndex;
    type Bcast = T::Bcast;
    type P2p = T::P2p;

    #[inline]
    fn execute_typed(
        self: Box<Self>,
        data: RoundData<Self::Bcast, Self::P2p>,
    ) -> ProtocolBuilder<Self::FinalOutputTyped, Self::Index> {
        self.execute_typed(data)
    }

    #[cfg(test)]
    #[inline]
    fn as_any(&self) -> &dyn std::any::Any {
        self.as_any()
    }
}

pub fn new_keygen(
    share_count: usize,
    threshold: usize,
    index: usize,
    secret_recovery_key: &SecretRecoveryKey,
    session_nonce: &[u8],
) -> TofnResult<KeygenProtocol> {
    // validate args
    if share_count <= threshold || share_count <= index || share_count > MAX_SHARE_COUNT {
        return Err(format!(
            "invalid (share_count,threshold,index): ({},{},{})",
            share_count, threshold, index
        ));
    }
    if session_nonce.is_empty() {
        return Err(format!(
            "invalid session_nonce length: {}",
            session_nonce.len()
        ));
    }

    // compute the RNG seed now so as to minimize copying of `secret_recovery_key`
    let rng_seed = rng::seed(secret_recovery_key, session_nonce);

    Ok(Protocol::NotDone(ProtocolRound::new(
        Box::new(r1::R1 {
            threshold,
            rng_seed,
        }),
        share_count,
        index,
        None,
        None,
    )))
}

// all crimes
// names have the form <round><crime> where
// <round> indicates round where the crime is detected, and
// <crime> is a description
// example: R3FailBadProof -> crime detected in r3_fail()
#[derive(Debug, Clone, PartialEq)]
pub enum Crime {
    MissingMessage,   // TODO add victim for missing p2p messages?
    CorruptedMessage, // TODO add victim for missing p2p messages?
    R2BadZkSetupProof,
    R2BadEncryptionKeyProof,
    R3BadReveal,
    R4FailBadVss { victim: usize },
    // R4FailBadEncryption { victim: usize },
    // R4FailFalseAccusation { victim: usize },
    R4BadDLProof,
}

/// TODO PoC only
impl DeTimeout for KeygenOutput {
    fn new_timeout() -> Self {
        Err(vec![vec![Crime::MissingMessage]])
    }
    fn new_deserialization_failure() -> Self {
        Err(vec![vec![Crime::CorruptedMessage]])
    }
}

mod r1;
mod r2;
mod r3;
mod r4;
mod rng;

#[cfg(test)]
pub(super) mod tests; // pub(super) so that sign module can see tests::execute_keygen
