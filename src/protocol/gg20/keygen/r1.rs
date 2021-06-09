use super::{Keygen, Status};
use crate::{hash, k256_serde::to_bytes, paillier_k256, protocol::gg20::vss_k256};
use serde::{Deserialize, Serialize};

#[cfg(feature = "malicious")]
use {super::malicious::Behaviour, tracing::info};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Bcast {
    pub(super) y_i_commit_k256: hash::Output,
    pub(super) ek_k256: paillier_k256::EncryptionKey,
    pub(super) zkp_k256: paillier_k256::zk::ZkSetup,
    // TODO zk proofs for Paillier keys
}
#[derive(Debug)] // do not derive Clone, Serialize, Deserialize
pub(super) struct State {
    pub(super) dk_k256: paillier_k256::DecryptionKey,
    pub(super) my_u_i_vss_k256: vss_k256::Vss,
    pub(super) my_y_i_reveal_k256: hash::Randomness,
}

impl Keygen {
    pub(super) fn r1(&self) -> (State, Bcast) {
        assert!(matches!(self.status, Status::New));

        // k256
        let my_u_i_vss_k256 = vss_k256::Vss::new(self.threshold);
        let (my_y_i_commit_k256, my_y_i_reveal_k256) = hash::commit(to_bytes(
            &(k256::ProjectivePoint::generator() * my_u_i_vss_k256.get_secret()),
        ));

        #[cfg(feature = "malicious")]
        let my_y_i_commit_k256 = if matches!(self.behaviour, Behaviour::R1BadCommit) {
            info!(
                "(k256) malicious party {} do {:?}",
                self.my_index, self.behaviour
            );
            my_y_i_commit_k256.corrupt()
        } else {
            my_y_i_commit_k256
        };

        let (ek_k256, dk_k256) = paillier_k256::keygen_unsafe();
        let zkp_k256 = paillier_k256::zk::ZkSetup::new_unsafe();
        // TODO Paillier key proofs

        (
            State {
                dk_k256,
                my_u_i_vss_k256,
                my_y_i_reveal_k256,
            },
            Bcast {
                y_i_commit_k256: my_y_i_commit_k256,
                ek_k256,
                zkp_k256,
            },
        )
    }
}
