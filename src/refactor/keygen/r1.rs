use crate::{
    corrupt, hash, k256_serde, paillier_k256,
    protocol::gg20::vss_k256,
    refactor::{
        keygen::SecretKeyShare,
        sdk::{
            api::TofnResult,
            implementer_api::{serialize, ProtocolBuilder::*, ProtocolInfo, RoundBuilder},
            no_messages,
        },
    },
};
use serde::{Deserialize, Serialize};

use super::{r2, rng, KeygenPartyIndex, KeygenProtocolBuilder};

#[cfg(feature = "malicious")]
use super::malicious::Behaviour;

pub struct R1 {
    pub threshold: usize,
    pub rng_seed: rng::Seed,

    #[cfg(feature = "malicious")]
    pub behaviour: Behaviour,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bcast {
    pub y_i_commit: hash::Output,
    pub ek: paillier_k256::EncryptionKey,
    pub ek_proof: paillier_k256::zk::EncryptionKeyProof,
    pub zkp: paillier_k256::zk::ZkSetup,
    pub zkp_proof: paillier_k256::zk::ZkSetupProof,
}

impl no_messages::Executer for R1 {
    type FinalOutput = SecretKeyShare;
    type Index = KeygenPartyIndex;

    fn execute(
        self: Box<Self>,
        _info: &ProtocolInfo<Self::Index>,
    ) -> TofnResult<KeygenProtocolBuilder> {
        let u_i_vss = vss_k256::Vss::new(self.threshold);
        let (y_i_commit, y_i_reveal) = hash::commit(k256_serde::to_bytes(
            &(k256::ProjectivePoint::generator() * u_i_vss.get_secret()),
        ));

        corrupt!(
            y_i_commit,
            self.corrupt_commit(_info.share_id(), y_i_commit)
        );

        let mut rng = rng::rng_from_seed(self.rng_seed);
        let (ek, dk) = paillier_k256::keygen_unsafe(&mut rng);
        let (zkp, zkp_proof) = paillier_k256::zk::ZkSetup::new_unsafe(&mut rng);
        let ek_proof = dk.correctness_proof();

        corrupt!(ek_proof, self.corrupt_ek_proof(_info.share_id(), ek_proof));
        corrupt!(
            zkp_proof,
            self.corrupt_zkp_proof(_info.share_id(), zkp_proof)
        );

        let bcast_out = serialize(&Bcast {
            y_i_commit,
            ek,
            ek_proof,
            zkp,
            zkp_proof,
        })?;

        Ok(NotDone(RoundBuilder::BcastOnly {
            round: Box::new(r2::R2 {
                threshold: self.threshold,
                dk,
                u_i_vss,
                y_i_reveal,
                #[cfg(feature = "malicious")]
                behaviour: self.behaviour,
            }),
            bcast_out,
        }))
    }
}

#[cfg(feature = "malicious")]
mod malicious {
    use super::R1;
    use crate::{
        hash::Output,
        paillier_k256,
        paillier_k256::zk::{EncryptionKeyProof, ZkSetupProof},
        refactor::collections::TypedUsize,
        refactor::keygen::malicious::Behaviour,
        refactor::keygen::KeygenPartyIndex,
    };
    use tracing::info;

    impl R1 {
        pub fn corrupt_commit(
            &self,
            my_index: TypedUsize<KeygenPartyIndex>,
            commit: Output,
        ) -> Output {
            if let Behaviour::R1BadCommit = self.behaviour {
                info!("malicious party {} do {:?}", my_index, self.behaviour);
                commit.corrupt()
            } else {
                commit
            }
        }

        pub fn corrupt_ek_proof(
            &self,
            my_index: TypedUsize<KeygenPartyIndex>,
            ek_proof: EncryptionKeyProof,
        ) -> EncryptionKeyProof {
            if let Behaviour::R1BadEncryptionKeyProof = self.behaviour {
                info!("malicious party {} do {:?}", my_index, self.behaviour);
                paillier_k256::zk::malicious::corrupt_ek_proof(ek_proof)
            } else {
                ek_proof
            }
        }

        pub fn corrupt_zkp_proof(
            &self,
            my_index: TypedUsize<KeygenPartyIndex>,
            zkp_proof: ZkSetupProof,
        ) -> ZkSetupProof {
            if let Behaviour::R1BadZkSetupProof = self.behaviour {
                info!("malicious party {} do {:?}", my_index, self.behaviour);
                paillier_k256::zk::malicious::corrupt_zksetup_proof(zkp_proof)
            } else {
                zkp_proof
            }
        }
    }
}
