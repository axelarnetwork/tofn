use super::{Keygen, Status};
use crate::{hash, k256_serde::to_bytes, protocol::gg20::vss_k256, zkp::paillier::ZkSetup};
use curv::{
    cryptographic_primitives::commitments::{hash_commitment::HashCommitment, traits::Commitment},
    elliptic::curves::traits::{ECPoint, ECScalar},
    BigInt, FE, GE,
};
use paillier::{DecryptionKey, EncryptionKey};
use paillier::{KeyGeneration, Paillier};
use serde::{Deserialize, Serialize};
use zk_paillier::zkproofs::NICorrectKeyProof;

#[cfg(feature = "malicious")]
use {super::malicious::Behaviour, tracing::info};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Bcast {
    pub(super) y_i_commit: BigInt,

    pub(super) y_i_commit_k256: hash::Output,

    // TODO Paillier
    pub(super) ek: EncryptionKey,
    pub(super) zkp: ZkSetup,
    pub(super) correct_key_proof: NICorrectKeyProof,
}
// can't derive Debug because NonZeroScalar doesn't derive Debug
#[derive(Debug)] // do not derive Clone, Serialize, Deserialize
pub(super) struct State {
    pub(super) my_u_i: FE,
    pub(super) my_y_i: GE,
    pub(super) my_y_i_reveal: BigInt,

    pub(super) my_u_i_vss_k256: vss_k256::Vss,
    pub(super) my_y_i_reveal_k256: hash::Randomness,

    // TODO Paillier
    pub(super) my_dk: DecryptionKey,
    pub(super) my_ek: EncryptionKey,
    pub(super) my_zkp: ZkSetup,
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
            info!("malicious party {} do {:?}", self.my_index, self.behaviour);
            my_y_i_commit_k256.corrupt()
        } else {
            my_y_i_commit_k256
        };

        // curv
        let my_u_i = FE::new_random();
        let my_y_i = GE::generator() * my_u_i;
        let (my_y_i_commit, my_y_i_reveal) =
            HashCommitment::create_commitment(&my_y_i.bytes_compressed_to_big_int());

        #[cfg(feature = "malicious")]
        let my_y_i_commit = if matches!(self.behaviour, Behaviour::R1BadCommit) {
            info!("malicious party {} do {:?}", self.my_index, self.behaviour);
            my_y_i_commit + BigInt::one()
        } else {
            my_y_i_commit
        };

        // TODO Paillier
        let (ek, my_dk) = Paillier::keypair().keys();
        let correct_key_proof = NICorrectKeyProof::proof(&my_dk);
        let zkp = ZkSetup::new_unsafe();

        (
            State {
                my_u_i,
                my_y_i,
                my_y_i_reveal,
                my_u_i_vss_k256,
                my_y_i_reveal_k256,
                my_dk,
                my_ek: ek.clone(),
                my_zkp: zkp.clone(),
            },
            Bcast {
                y_i_commit: my_y_i_commit,
                y_i_commit_k256: my_y_i_commit_k256,
                ek,
                zkp,
                correct_key_proof,
            },
        )
    }
}
