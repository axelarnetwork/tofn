use crate::{
    corrupt,
    gg20::{
        constants,
        crypto_tools::{hash, k256_serde, paillier, vss},
        keygen::SecretKeyShare,
    },
    sdk::{
        api::TofnResult,
        implementer_api::{no_messages, serialize, ProtocolBuilder::*, ProtocolInfo, RoundBuilder},
    },
};
use serde::{Deserialize, Serialize};

use super::{r2, rng, KeygenPartyShareCounts, KeygenProtocolBuilder, KeygenShareId};

#[cfg(feature = "malicious")]
use super::malicious::Behaviour;

pub struct R1 {
    pub threshold: usize,
    pub party_share_counts: KeygenPartyShareCounts,
    pub rng_seed: rng::Seed,
    pub use_safe_primes: bool,

    #[cfg(feature = "malicious")]
    pub behaviour: Behaviour,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bcast {
    pub y_i_commit: hash::Output,
    pub ek: paillier::EncryptionKey,
    pub ek_proof: paillier::zk::EncryptionKeyProof,
    pub zkp: paillier::zk::ZkSetup,
    pub zkp_proof: paillier::zk::ZkSetupProof,
}

impl no_messages::Executer for R1 {
    type FinalOutput = SecretKeyShare;
    type Index = KeygenShareId;

    fn execute(
        self: Box<Self>,
        _info: &ProtocolInfo<Self::Index>,
    ) -> TofnResult<KeygenProtocolBuilder> {
        let u_i_vss = vss::Vss::new(self.threshold);
        let (y_i_commit, y_i_reveal) = hash::commit(
            constants::Y_I_COMMIT_TAG,
            k256_serde::to_bytes(&(k256::ProjectivePoint::generator() * u_i_vss.get_secret())),
        );

        corrupt!(
            y_i_commit,
            self.corrupt_commit(_info.share_id(), y_i_commit)
        );

        let mut rng = rng::rng_from_seed(self.rng_seed.clone());
        let ((ek, dk), (zkp, zkp_proof)) = if self.use_safe_primes {
            (
                paillier::keygen(&mut rng),
                paillier::zk::ZkSetup::new(&mut rng),
            )
        } else {
            (
                paillier::keygen_unsafe(&mut rng),
                paillier::zk::ZkSetup::new_unsafe(&mut rng),
            )
        };
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
                party_share_counts: self.party_share_counts,
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
        collections::TypedUsize,
        gg20::{
            crypto_tools::{
                hash::Output,
                paillier,
                paillier::zk::{EncryptionKeyProof, ZkSetupProof},
            },
            keygen::{malicious::Behaviour, KeygenShareId},
        },
    };
    use tracing::info;

    impl R1 {
        pub fn corrupt_commit(
            &self,
            my_index: TypedUsize<KeygenShareId>,
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
            my_index: TypedUsize<KeygenShareId>,
            ek_proof: EncryptionKeyProof,
        ) -> EncryptionKeyProof {
            if let Behaviour::R1BadEncryptionKeyProof = self.behaviour {
                info!("malicious party {} do {:?}", my_index, self.behaviour);
                paillier::zk::malicious::corrupt_ek_proof(ek_proof)
            } else {
                ek_proof
            }
        }

        pub fn corrupt_zkp_proof(
            &self,
            my_index: TypedUsize<KeygenShareId>,
            zkp_proof: ZkSetupProof,
        ) -> ZkSetupProof {
            if let Behaviour::R1BadZkSetupProof = self.behaviour {
                info!("malicious party {} do {:?}", my_index, self.behaviour);
                paillier::zk::malicious::corrupt_zksetup_proof(zkp_proof)
            } else {
                zkp_proof
            }
        }
    }
}
