use crate::protocol::gg20::SecretKeyShare;
use crate::refactor::protocol::{
    executer::{DeTimeout, ProtocolBuilder},
    Protocol, ProtocolRound,
};
use crate::vecmap::{Behave, Index};
use serde::{Deserialize, Serialize};

use super::TofnResult;

// need to derive all this crap for each new marker struct
// in order to avoid this problem: https://stackoverflow.com/a/31371094
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct KeygenPartyIndex;
impl Behave for KeygenPartyIndex {}

pub type KeygenProtocol = Protocol<KeygenOutput, KeygenPartyIndex>;
pub type KeygenProtocolBuilder = ProtocolBuilder<KeygenOutput, KeygenPartyIndex>;
pub type KeygenOutput = Result<SecretKeyShare, Vec<(Index<KeygenPartyIndex>, Fault)>>;
pub type SecretRecoveryKey = [u8; 64];

// Can't define a keygen-specific alias for `RoundExecuter` that sets
// `FinalOutputTyped = KeygenOutput` and `Index = KeygenPartyIndex`
// because https://github.com/rust-lang/rust/issues/41517

pub const MAX_SHARE_COUNT: usize = 1000;

pub fn new_keygen(
    share_count: usize,
    threshold: usize,
    index: Index<KeygenPartyIndex>,
    secret_recovery_key: &SecretRecoveryKey,
    session_nonce: &[u8],
) -> TofnResult<KeygenProtocol> {
    new_keygen_impl(
        share_count,
        threshold,
        index,
        secret_recovery_key,
        session_nonce,
        #[cfg(feature = "malicious")]
        Behaviour::Honest,
    )
}

fn new_keygen_impl(
    share_count: usize,
    threshold: usize,
    index: Index<KeygenPartyIndex>,
    secret_recovery_key: &SecretRecoveryKey,
    session_nonce: &[u8],
    #[cfg(feature = "malicious")] behaviour: Behaviour,
) -> TofnResult<KeygenProtocol> {
    // validate args
    if share_count <= threshold || share_count <= index.as_usize() || share_count > MAX_SHARE_COUNT
    {
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
            #[cfg(feature = "malicious")]
            behaviour,
        }),
        share_count,
        index,
        None,
        None,
    )))
}

#[cfg(feature = "malicious")]
pub fn new_keygen_with_behaviour(
    share_count: usize,
    threshold: usize,
    index: Index<KeygenPartyIndex>,
    secret_recovery_key: &SecretRecoveryKey,
    session_nonce: &[u8],
    behaviour: Behaviour,
) -> TofnResult<KeygenProtocol> {
    new_keygen_impl(
        share_count,
        threshold,
        index,
        secret_recovery_key,
        session_nonce,
        #[cfg(feature = "malicious")]
        behaviour,
    )
}

// all crimes
// names have the form <round><crime> where
// <round> indicates round where the crime is detected, and
// <crime> is a description
// example: R3FailBadProof -> crime detected in r3_fail()
#[derive(Debug, Clone, PartialEq)]
pub enum Fault {
    MissingMessage,   // TODO add victim for missing p2p messages?
    CorruptedMessage, // TODO add victim for missing p2p messages?
    R2BadZkSetupProof,
    R2BadEncryptionKeyProof,
    R3BadReveal,
    R4FailBadVss { victim: Index<KeygenPartyIndex> },
    R4SadBadEncryption { victim: Index<KeygenPartyIndex> },
    R4SadFalseAccusation { victim: Index<KeygenPartyIndex> },
    R4BadDLProof,
}

/// TODO PoC only
impl DeTimeout for KeygenOutput {
    fn new_timeout() -> Self {
        Err(vec![(Index::from_usize(0), Fault::MissingMessage)])
    }
    fn new_deserialization_failure() -> Self {
        Err(vec![(Index::from_usize(0), Fault::CorruptedMessage)])
    }
}

mod r1;
mod r2;
mod r3;
mod r4;
mod rng;

#[cfg(test)]
pub(super) mod tests; // pub(super) so that sign module can see tests::execute_keygen

#[cfg(feature = "malicious")]
pub mod malicious;
#[cfg(feature = "malicious")]
use malicious::Behaviour;
