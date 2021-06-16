use super::{Keygen, Status};
use crate::{hash, k256_serde::to_bytes, paillier_k256, protocol::gg20::vss_k256};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};

#[cfg(feature = "malicious")]
use {super::malicious::Behaviour, tracing::info};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Bcast {
    pub(super) y_i_commit_k256: hash::Output,
    pub(super) ek_k256: paillier_k256::EncryptionKey,
    pub(super) ek_proof: paillier_k256::zk::EncryptionKeyProof,
    pub(super) zkp_k256: paillier_k256::zk::ZkSetup,
    pub(super) zkp_proof: paillier_k256::zk::ZkSetupProof,
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
        let u_i_vss = vss_k256::Vss::new(self.threshold);
        let (y_i_commit, y_i_reveal) = hash::commit(to_bytes(
            &(k256::ProjectivePoint::generator() * u_i_vss.get_secret()),
        ));

        #[cfg(feature = "malicious")]
        let y_i_commit = if matches!(self.behaviour, Behaviour::R1BadCommit) {
            info!("malicious party {} do {:?}", self.my_index, self.behaviour);
            y_i_commit.corrupt()
        } else {
            y_i_commit
        };

        // instantiate the rng here instead of in Keygen::new
        // because we need rng to be mutable
        // otherwise we'd need `r1(&mut self)`
        let mut rng = ChaCha20Rng::from_seed(self.rng_seed);

        let (ek, dk) = paillier_k256::keygen_unsafe(&mut rng);
        let ek_proof = dk.correctness_proof();
        let (zkp, zkp_proof) = paillier_k256::zk::ZkSetup::new_unsafe(&mut rng);

        #[cfg(feature = "malicious")]
        let zkp_proof = if matches!(self.behaviour, Behaviour::R1BadZkSetupProof) {
            info!("malicious party {} do {:?}", self.my_index, self.behaviour);
            paillier_k256::zk::malicious::corrupt(zkp_proof)
        } else {
            zkp_proof
        };

        (
            State {
                dk_k256: dk,
                my_u_i_vss_k256: u_i_vss,
                my_y_i_reveal_k256: y_i_reveal,
            },
            Bcast {
                y_i_commit_k256: y_i_commit,
                ek_k256: ek,
                ek_proof,
                zkp_k256: zkp,
                zkp_proof,
            },
        )
    }
}
