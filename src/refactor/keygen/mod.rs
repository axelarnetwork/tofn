use crate::protocol::gg20::SecretKeyShare;
use crate::refactor::protocol::{
    executer::{DeTimeout, ProtocolBuilder},
    Protocol, ProtocolRound,
};

use super::TofnResult;

// need to derive all this crap for each new marker struct
// in order to avoid this problem: https://stackoverflow.com/a/31371094
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct KeygenPartyIndex;

pub type KeygenProtocol = Protocol<KeygenOutput, KeygenPartyIndex>;
pub type KeygenProtocolBuilder = ProtocolBuilder<KeygenOutput, KeygenPartyIndex>;
pub type KeygenOutput = Result<SecretKeyShare, Vec<Vec<Crime>>>;
pub type SecretRecoveryKey = [u8; 64];

// Can't define a keygen-specific alias for `RoundExecuter` that sets
// `FinalOutputTyped = KeygenOutput` and `Index = KeygenPartyIndex`
// because https://github.com/rust-lang/rust/issues/41517

pub const MAX_SHARE_COUNT: usize = 1000;

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

// TODO TEMPORARY: translate HoleVecMap into FillVec
pub mod temp {
    use crate::{
        fillvec::FillVec,
        refactor::{BytesVec, TofnResult},
        vecmap::HoleVecMap,
    };

    use super::KeygenPartyIndex;

    pub fn to_fillvec(
        hole_vecmap: HoleVecMap<KeygenPartyIndex, TofnResult<BytesVec>>,
        hole: usize,
    ) -> FillVec<BytesVec> {
        let mut res = FillVec::from_vec(
            hole_vecmap
                .into_iter()
                .map(|(_, r)| match r {
                    Ok(bytes) => Some(bytes),
                    Err(_) => None,
                })
                .collect(),
        );
        res.vec_ref_mut().insert(hole, None);
        res
    }
}
