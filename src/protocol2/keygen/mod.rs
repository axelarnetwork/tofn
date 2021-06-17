use crate::protocol::gg20::{keygen::crimes, SecretKeyShare};

use super::RoundWaiter;

pub type KeygenOutput = Result<SecretKeyShare, Vec<Vec<crimes::Crime>>>;

pub type SecretRecoveryKey = [u8; 64];

pub fn new_keygen(
    share_count: usize,
    threshold: usize,
    my_index: usize,
    secret_recovery_key: &SecretRecoveryKey,
    session_nonce: &[u8],
) -> Result<RoundWaiter<KeygenOutput>, String> {
    // validate args
    if share_count <= threshold || share_count <= my_index {
        return Err(format!(
            "invalid (share_count,threshold,index): ({},{},{})",
            share_count, threshold, my_index
        ));
    }
    if session_nonce.is_empty() {
        return Err(format!(
            "invalid session_nonce length: {}",
            session_nonce.len()
        ));
    }

    Ok(r1::execute(
        share_count,
        threshold,
        my_index,
        secret_recovery_key,
        session_nonce,
    ))
}

mod r1;
mod r2;
