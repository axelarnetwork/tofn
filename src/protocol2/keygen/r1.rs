use crate::{
    hash, k256_serde, paillier_k256,
    protocol::gg20::vss_k256::Vss,
    protocol2::{RoundExecuter, RoundOutput},
};
use serde::{Deserialize, Serialize};
use tracing::error;

use crate::{fillvec::FillVec, protocol::gg20::keygen::KeygenOutput, protocol2::RoundWaiter};

use super::{r2, rng};

pub(super) struct R1 {
    pub(super) share_count: usize,
    pub(super) threshold: usize,
    pub(super) index: usize,
    pub(super) rng_seed: rng::Seed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Bcast {
    pub(super) y_i_commit: hash::Output,
    pub(super) ek: paillier_k256::EncryptionKey,
    pub(super) ek_proof: paillier_k256::zk::EncryptionKeyProof,
    pub(super) zkp: paillier_k256::zk::ZkSetup,
    pub(super) zkp_proof: paillier_k256::zk::ZkSetupProof,
}

impl RoundExecuter for R1 {
    type FinalOutput = KeygenOutput;

    fn execute(self: Box<Self>, _all_in_msgs: FillVec<Vec<u8>>) -> RoundOutput<Self::FinalOutput> {
        let u_i_vss = Vss::new(self.threshold);
        let (y_i_commit, y_i_reveal) = hash::commit(k256_serde::to_bytes(
            &(k256::ProjectivePoint::generator() * u_i_vss.get_secret()),
        ));

        // #[cfg(feature = "malicious")]
        // let y_i_commit = if matches!(self.behaviour, Behaviour::R1BadCommit) {
        //     info!("malicious party {} do {:?}", self.my_index, self.behaviour);
        //     y_i_commit.corrupt()
        // } else {
        //     y_i_commit
        // };

        let mut rng = rng::rng_from_seed(self.rng_seed);
        let (ek, dk) = paillier_k256::keygen_unsafe(&mut rng);
        let (zkp, zkp_proof) = paillier_k256::zk::ZkSetup::new_unsafe(&mut rng);
        let ek_proof = dk.correctness_proof();

        // #[cfg(feature = "malicious")]
        // let ek_proof = if matches!(self.behaviour, Behaviour::R1BadEncryptionKeyProof) {
        //     info!("malicious party {} do {:?}", self.my_index, self.behaviour);
        //     paillier_k256::zk::malicious::corrupt_ek_proof(ek_proof)
        // } else {
        //     ek_proof
        // };

        // #[cfg(feature = "malicious")]
        // let zkp_proof = if matches!(self.behaviour, Behaviour::R1BadZkSetupProof) {
        //     info!("malicious party {} do {:?}", self.my_index, self.behaviour);
        //     paillier_k256::zk::malicious::corrupt_zksetup_proof(zkp_proof)
        // } else {
        //     zkp_proof
        // };
        let msg = Bcast {
            y_i_commit,
            ek,
            ek_proof,
            zkp,
            zkp_proof,
        };
        let out_msg = bincode::serialize(&msg).ok();
        if out_msg.is_none() {
            error!("party {} serialization failure", self.index);
        }

        RoundOutput::NotDone(RoundWaiter {
            round: Box::new(r2::R2 {
                share_count: self.share_count,
                threshold: self.threshold,
                index: self.index,
                dk,
                u_i_vss,
                y_i_reveal,
                msg,
            }),
            out_msg,
            all_in_msgs: FillVec::with_len(self.share_count),
        })
    }
}
