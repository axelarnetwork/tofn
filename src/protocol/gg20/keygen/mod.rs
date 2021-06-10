use super::SecretKeyShare;
use crate::{fillvec::FillVec, protocol::MsgBytes};
use hmac::{Hmac, Mac, NewMac};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use strum_macros::EnumIter;

pub type KeygenOutput = Result<SecretKeyShare, Vec<Vec<crimes::Crime>>>;

#[derive(Clone, Debug, EnumIter, PartialEq)]
pub enum Status {
    New,
    R1,
    R2,
    R3,
    R3Fail,
    Done,
    Fail,
}

// Behaviour includes UnauthonticatedSender{victim, status} and we use
// strum to make Behaviour iterable. Strum needs for all included enums
// that contain complex data to provide a default method:
// https://docs.rs/strum/0.14.0/strum/?search=#strum-macros
impl Default for Status {
    fn default() -> Self {
        Status::New
    }
}

#[derive(Clone, Debug, EnumIter, PartialEq, Serialize, Deserialize)]
pub enum MsgType {
    R1Bcast,
    R2Bcast,
    R2P2p { to: usize },
    R3Bcast,
    R3FailBcast,
}

// TODO: see if we can skip that by some how duplicating MsgType inside tests
//       and add EnumIter and Default to that
// Behaviour includes Staller{victim, msg_type} and we use
// strum to make Behaviour iterable. Strum needs for all included enums
// that contain complex data to provide a default method:
// https://docs.rs/strum/0.14.0/strum/?search=#strum-macros
impl Default for MsgType {
    fn default() -> Self {
        MsgType::R1Bcast
    }
}

// TODO identical to keygen::MsgMeta except for MsgType---use generic
#[derive(Serialize, Deserialize)]
struct MsgMeta {
    msg_type: MsgType,
    from: usize,
    payload: MsgBytes,
}

#[cfg(feature = "malicious")]
pub mod malicious;

pub mod crimes;
mod protocol;
mod r1;
mod r2;
mod r3;
mod r4;
mod r4_fail;

pub struct Keygen {
    status: Status,

    // state data
    share_count: usize,
    threshold: usize,
    my_index: usize,
    rng_seed: <ChaCha20Rng as SeedableRng>::Seed,
    r1state: Option<r1::State>,
    r2state: Option<r2::State>,
    r3state: Option<r3::State>,

    // incoming messages
    in_r1bcasts: FillVec<r1::Bcast>,
    in_r2bcasts: FillVec<r2::Bcast>,
    in_all_r2p2ps: Vec<FillVec<r2::P2p>>,
    in_r3bcasts: FillVec<r3::Bcast>,
    in_r3bcasts_fail: FillVec<r3::BcastFail>,

    // outgoing/incoming messages
    // initialized to `None`, filled as the protocol progresses
    out_r1bcast: Option<MsgBytes>,
    out_r2bcast: Option<MsgBytes>,
    out_r2p2ps: Option<Vec<Option<MsgBytes>>>,
    out_r3bcast: Option<MsgBytes>,
    out_r3bcast_fail: Option<MsgBytes>,
    unauth_parties: FillVec<usize>,
    disrupting_parties: FillVec<bool>,
    final_output: Option<KeygenOutput>,

    #[cfg(feature = "malicious")]
    behaviour: malicious::Behaviour,
}

impl Keygen {
    pub fn new(
        share_count: usize,
        threshold: usize,
        my_index: usize,
        prf_secret_key: &[u8; 64],
        prf_input: &[u8],
    ) -> Result<Self, ParamsError> {
        // use prf_secret_key immediately to minimize memory writes
        let mut prf = Hmac::<Sha256>::new(prf_secret_key[..].into());
        prf.update(prf_input);
        let rng_seed = prf.finalize().into_bytes().into();

        validate_params(share_count, threshold, my_index)?;
        Ok(Self {
            status: Status::New,
            share_count,
            threshold,
            my_index,
            rng_seed, // do not use after round 1
            r1state: None,
            r2state: None,
            r3state: None,
            in_r1bcasts: FillVec::with_len(share_count),
            in_r2bcasts: FillVec::with_len(share_count),
            in_all_r2p2ps: vec![FillVec::with_len(share_count); share_count],
            in_r3bcasts: FillVec::with_len(share_count),
            in_r3bcasts_fail: FillVec::with_len(share_count),
            out_r1bcast: None,
            out_r2bcast: None,
            out_r2p2ps: None,
            out_r3bcast: None,
            out_r3bcast_fail: None,
            unauth_parties: FillVec::with_len(share_count),
            disrupting_parties: FillVec::with_len(share_count),
            final_output: None,

            #[cfg(feature = "malicious")]
            behaviour: malicious::Behaviour::Honest,
        })
    }
    pub fn found_disrupting(&self) -> bool {
        !self.disrupting_parties.is_empty()
    }
    pub fn clone_output(&self) -> Option<KeygenOutput> {
        self.final_output.clone()
    }
}

// validate_params helper with custom error type
// TODO enforce a maximum share_count?
pub fn validate_params(
    share_count: usize,
    threshold: usize,
    index: usize,
) -> Result<(), ParamsError> {
    if threshold >= share_count {
        return Err(ParamsError::InvalidThreshold(share_count, threshold));
    }
    if index >= share_count {
        return Err(ParamsError::InvalidThreshold(share_count, index));
    }
    Ok(())
}
#[derive(Debug)]
pub enum ParamsError {
    InvalidThreshold(usize, usize), // (share_count, threshold)
    InvalidIndex(usize, usize),     // (share_count, index)
}

impl std::error::Error for ParamsError {}
impl std::fmt::Display for ParamsError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ParamsError::InvalidThreshold(share_count, threshold) => write!(
                f,
                "invalid threshold {} for share_count {}",
                threshold, share_count
            ),
            ParamsError::InvalidIndex(share_count, index) => {
                write!(f, "invalid index {} for share_count {}", index, share_count)
            }
        }
    }
}

#[cfg(test)]
pub(super) mod tests_k256; // pub(super) so that sign module can see tests::execute_keygen
