use curv::{
    cryptographic_primitives::commitments::{hash_commitment::HashCommitment, traits::Commitment},
    elliptic::curves::traits::{ECPoint, ECScalar},
    BigInt, FE, GE,
};
use paillier::{DecryptionKey, EncryptionKey};
use paillier::{KeyGeneration, Paillier};
use serde::{Deserialize, Serialize};
use tracing::info;
use zk_paillier::zkproofs::NICorrectKeyProof;

use super::{malicious::Behaviour, Keygen, Status};
use crate::zkp::paillier::ZkSetup;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bcast {
    pub y_i_commit: BigInt,

    // TODO Paillier
    pub ek: EncryptionKey,
    pub zkp: ZkSetup,
    pub correct_key_proof: NICorrectKeyProof,
}
#[derive(Debug)] // do not derive Clone, Serialize, Deserialize
pub(super) struct State {
    pub(super) my_u_i: FE,
    pub(super) my_y_i: GE,
    pub(super) my_y_i_reveal: BigInt,

    // TODO Paillier
    pub(super) my_dk: DecryptionKey,
    pub(super) my_ek: EncryptionKey,
    pub(super) my_zkp: ZkSetup,
}

impl Keygen {
    pub(super) fn r1(&self) -> (State, Bcast) {
        assert!(matches!(self.status, Status::New));
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
                my_dk,
                my_ek: ek.clone(),
                my_zkp: zkp.clone(),
            },
            Bcast {
                y_i_commit: my_y_i_commit,
                ek,
                zkp,
                correct_key_proof,
            },
        )
    }
}
