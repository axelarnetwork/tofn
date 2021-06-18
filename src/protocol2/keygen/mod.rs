use crate::{
    fillvec::FillVec,
    protocol::gg20::{keygen::crimes, SecretKeyShare},
};

use super::RoundWaiter;

pub type KeygenOutput = Result<SecretKeyShare, Vec<Vec<crimes::Crime>>>;
pub type SecretRecoveryKey = [u8; 64];

pub const MAX_SHARE_COUNT: usize = 1000;

pub fn new_keygen(
    share_count: usize,
    threshold: usize,
    index: usize,
    secret_recovery_key: &SecretRecoveryKey,
    session_nonce: &[u8],
) -> Result<RoundWaiter<KeygenOutput>, String> {
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

    Ok(RoundWaiter {
        round: Box::new(r1::R1 {
            share_count,
            threshold,
            index,
            rng_seed,
        }),
        bcast_out: None,
        p2ps_out: None,
        all_in_msgs: FillVec::with_len(0), // expect no incoming messages before r1
    })
}

mod r1;
mod r2;
mod r3;
mod rng;

#[cfg(test)]
pub(super) mod tests; // pub(super) so that sign module can see tests::execute_keygen
