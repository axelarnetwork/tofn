use crate::{
    hash, k256_serde, paillier_k256,
    protocol::gg20::vss_k256,
    refactor::collections::TypedUsize,
    refactor::{
        keygen::SecretKeyShare,
        protocol::{
            api::TofnResult,
            implementer_api::{serialize, ProtocolBuilder::*, RoundBuilder},
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
        _party_count: usize,
        index: TypedUsize<Self::Index>,
    ) -> TofnResult<KeygenProtocolBuilder> {
        let u_i_vss = vss_k256::Vss::new(self.threshold);
        let (y_i_commit, y_i_reveal) = hash::commit(k256_serde::to_bytes(
            &(k256::ProjectivePoint::generator() * u_i_vss.get_secret()),
        ));

        let y_i_commit = self.corrupt_commit(index, y_i_commit);

        let mut rng = rng::rng_from_seed(self.rng_seed);
        let (ek, dk) = paillier_k256::keygen_unsafe(&mut rng);
        let (zkp, zkp_proof) = paillier_k256::zk::ZkSetup::new_unsafe(&mut rng);
        let ek_proof = dk.correctness_proof();

        let ek_proof = self.corrupt_ek_proof(index, ek_proof);
        let zkp_proof = self.corrupt_zkp_proof(index, zkp_proof);

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

pub mod malicious {
    // TODO need a better way to squelch build warnings with and without feature = "malicious"
    #![allow(unused_variables)]
    #![allow(unused_mut)]
    #![allow(unreachable_code)]
    use super::R1;
    use crate::{
        hash::Output,
        paillier_k256::zk::{EncryptionKeyProof, ZkSetupProof},
        refactor::collections::TypedUsize,
        refactor::keygen::KeygenPartyIndex,
    };

    #[cfg(feature = "malicious")]
    use tracing::info;

    #[cfg(feature = "malicious")]
    use crate::{paillier_k256, refactor::keygen::malicious::Behaviour};

    impl R1 {
        pub fn corrupt_commit(
            &self,
            my_index: TypedUsize<KeygenPartyIndex>,
            mut commit: Output,
        ) -> Output {
            #[cfg(feature = "malicious")]
            if let Behaviour::R1BadCommit = self.behaviour {
                info!("malicious party {} do {:?}", my_index, self.behaviour);
                return commit.corrupt();
            } else {
                return commit;
            }

            commit
        }

        pub fn corrupt_ek_proof(
            &self,
            my_index: TypedUsize<KeygenPartyIndex>,
            mut ek_proof: EncryptionKeyProof,
        ) -> EncryptionKeyProof {
            #[cfg(feature = "malicious")]
            if let Behaviour::R1BadEncryptionKeyProof = self.behaviour {
                info!("malicious party {} do {:?}", my_index, self.behaviour);
                return paillier_k256::zk::malicious::corrupt_ek_proof(ek_proof);
            } else {
                return ek_proof;
            }

            ek_proof
        }

        pub fn corrupt_zkp_proof(
            &self,
            my_index: TypedUsize<KeygenPartyIndex>,
            mut zkp_proof: ZkSetupProof,
        ) -> ZkSetupProof {
            #[cfg(feature = "malicious")]
            if let Behaviour::R1BadZkSetupProof = self.behaviour {
                info!("malicious party {} do {:?}", my_index, self.behaviour);
                return paillier_k256::zk::malicious::corrupt_zksetup_proof(zkp_proof);
            } else {
                return zkp_proof;
            }

            zkp_proof
        }
    }
}
