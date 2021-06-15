use super::{vss_k256, GroupPublicInfo, SecretKeyShare, SharePublicInfo, ShareSecretInfo};
use crate::{fillvec::FillVec, paillier_k256, protocol::MsgBytes};
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
    rng_seed: <ChaCha20Rng as SeedableRng>::Seed, // do not use after round 1
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

/// type alias instead of struct so as to minimize memory writes
pub type SecretRecoveryKey = [u8; 64];

impl Keygen {
    pub fn new(
        share_count: usize,
        threshold: usize,
        my_index: usize,
        secret_recovery_key: &SecretRecoveryKey,
        session_nonce: &[u8],
    ) -> Result<Self, ParamsError> {
        if session_nonce.is_empty() {
            return Err(ParamsError::InvalidPrfInput(session_nonce.len()));
        }
        validate_params(share_count, threshold, my_index)?;

        Ok(Self {
            status: Status::New,
            share_count,
            threshold,
            my_index,
            rng_seed: rng_seed(secret_recovery_key, session_nonce),
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
    InvalidPrfInput(usize),         // (prf_input.len)
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
            ParamsError::InvalidPrfInput(prf_input_len) => {
                write!(f, "invalid prf_input length {}", prf_input_len)
            }
        }
    }
}

#[cfg(test)]
mod test_recovery;
#[cfg(test)]
pub(super) mod tests_k256; // pub(super) so that sign module can see tests::execute_keygen

fn rng_seed(
    secret_recovery_key: &SecretRecoveryKey,
    session_nonce: &[u8],
) -> <ChaCha20Rng as SeedableRng>::Seed {
    let mut prf = Hmac::<Sha256>::new(secret_recovery_key[..].into());
    prf.update(session_nonce);
    prf.finalize().into_bytes().into()
}

/// Subset of `SecretKeyShare` that goes on-chain.
/// (Secret data is encrypted so it's ok to post publicly.)
/// When combined with similar data from all parties,
/// this data + mnemonic can be used to recover a full `SecretKeyShare` struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyShareRecoveryInfo {
    index: usize,
    share: SharePublicInfo,
    x_i_ciphertext: paillier_k256::Ciphertext,
}

impl SecretKeyShare {
    pub fn recovery_info(&self) -> KeyShareRecoveryInfo {
        let index = self.share.index;
        let share = self.group.all_shares[index].clone();
        let x_i_ciphertext = share.ek.encrypt(&self.share.x_i.unwrap().into()).0;
        KeyShareRecoveryInfo {
            index,
            share,
            x_i_ciphertext,
        }
    }

    /// Recover a `SecretKeyShare`
    /// TODO more complete arg checking? eg. unique eks, etc
    pub fn recover(
        secret_recovery_key: &SecretRecoveryKey,
        session_nonce: &[u8],
        recovery_infos: &[KeyShareRecoveryInfo],
        threshold: usize,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // basic argument validation
        if session_nonce.is_empty() {
            return Err(From::from(format!(
                "invalid session_nonce length: {}",
                session_nonce.len()
            )));
        }
        let share_count = recovery_infos.len();
        if threshold >= share_count {
            return Err(From::from(format!(
                "invalid (share_count,threshold): ({},{})",
                share_count, threshold
            )));
        }

        // sort recovery_info and verify indices are 0..len-1
        let recovery_infos_sorted = {
            let mut recovery_infos_sorted = recovery_infos.to_vec();
            recovery_infos_sorted.sort_unstable_by_key(|r| r.index);
            for (i, info) in recovery_infos_sorted.iter().enumerate() {
                if info.index != i {
                    return Err(From::from(format!(
                        "invalid party index {} at sorted position {}",
                        info.index, i
                    )));
                }
            }
            recovery_infos_sorted
        };

        // recover my Paillier keys
        let (ek, dk) = paillier_k256::keygen_unsafe(&mut ChaCha20Rng::from_seed(rng_seed(
            secret_recovery_key,
            session_nonce,
        )));

        // find my index by searching for my Paillier key
        let index = if let Some(index) = recovery_infos_sorted.iter().position(|r| r.share.ek == ek)
        {
            index
        } else {
            return Err(From::from("unable to find my ek"));
        };

        // prepare output
        let x_i = dk
            .decrypt(&recovery_infos_sorted[index].x_i_ciphertext)
            .to_scalar()
            .into();
        let y = vss_k256::recover_secret_commit(
            &recovery_infos_sorted
                .iter()
                .map(|info| vss_k256::ShareCommit::from_point(info.share.X_i.clone(), info.index))
                .collect::<Vec<_>>(),
            threshold,
        )
        .into();
        let all_shares: Vec<SharePublicInfo> = recovery_infos_sorted
            .into_iter()
            .map(|info| SharePublicInfo {
                X_i: info.share.X_i,
                ek: info.share.ek,
                zkp: info.share.zkp,
            })
            .collect();

        Ok(Self {
            group: GroupPublicInfo {
                threshold,
                y,
                all_shares,
            },
            share: ShareSecretInfo { index, dk, x_i },
        })
    }
}
