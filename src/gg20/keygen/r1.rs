use crate::{
    collections::TypedUsize,
    corrupt,
    gg20::{
        constants,
        crypto_tools::{
            hash, k256_serde,
            paillier::{
                self,
                zk::{ZkSetup, ZkSetupProof},
                DecryptionKey, EncryptionKey,
            },
            vss,
        },
        keygen::SecretKeyShare,
    },
    sdk::{
        api::TofnResult,
        implementer_api::{
            no_messages, serialize, ProtocolBuilder::*, ProtocolInfo, RoundBuilder,
            XProtocolBuilder, XRoundBuilder,
        },
    },
};
use serde::{Deserialize, Serialize};

use super::{
    r2, KeygenPartyShareCounts, KeygenProtocolBuilder, KeygenShareId, XKeygenProtocolBuilder,
};

#[cfg(feature = "malicious")]
use super::malicious::Behaviour;

pub struct R1 {
    pub(crate) threshold: usize,
    pub(crate) party_share_counts: KeygenPartyShareCounts,
    pub(crate) ek: EncryptionKey,
    pub(crate) dk: DecryptionKey,
    pub(crate) zkp: ZkSetup,
    pub(crate) zkp_proof: ZkSetupProof,

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

// TODO the first round is ugly after the round-type refactor
impl R1 {
    /// no incoming messages for round 1
    /// returns (r2, bcast_out)
    pub fn start(self, share_id: TypedUsize<KeygenShareId>) -> TofnResult<XKeygenProtocolBuilder> {
        let u_i_vss = vss::Vss::new(self.threshold);
        let (y_i_commit, y_i_reveal) = hash::commit(
            constants::Y_I_COMMIT_TAG,
            share_id,
            k256_serde::to_bytes(&(k256::ProjectivePoint::generator() * u_i_vss.get_secret())),
        );

        corrupt!(y_i_commit, self.corrupt_commit(share_id, y_i_commit));

        let ek_proof = self.dk.correctness_proof();
        let zkp_proof = self.zkp_proof.clone();

        corrupt!(ek_proof, self.corrupt_ek_proof(share_id, ek_proof));
        corrupt!(zkp_proof, self.corrupt_zkp_proof(share_id, zkp_proof));

        let bcast_out = Some(serialize(&Bcast {
            y_i_commit,
            ek: self.ek,
            ek_proof,
            zkp: self.zkp,
            zkp_proof,
        })?);

        Ok(XProtocolBuilder::NotDone(XRoundBuilder::new(
            Box::new(r2::R2 {
                threshold: self.threshold,
                party_share_counts: self.party_share_counts,
                dk: self.dk,
                u_i_vss,
                y_i_reveal,
                #[cfg(feature = "malicious")]
                behaviour: self.behaviour,
            }),
            bcast_out,
            None,
        )))
    }
}

// impl no_messages::Executer for R1 {
//     type FinalOutput = SecretKeyShare;
//     type Index = KeygenShareId;

//     fn execute(
//         self: Box<Self>,
//         info: &ProtocolInfo<Self::Index>,
//     ) -> TofnResult<KeygenProtocolBuilder> {
//         let keygen_id = info.share_id();

//         let u_i_vss = vss::Vss::new(self.threshold);
//         let (y_i_commit, y_i_reveal) = hash::commit(
//             constants::Y_I_COMMIT_TAG,
//             keygen_id,
//             k256_serde::to_bytes(&(k256::ProjectivePoint::generator() * u_i_vss.get_secret())),
//         );

//         corrupt!(y_i_commit, self.corrupt_commit(keygen_id, y_i_commit));

//         let ek_proof = self.dk.correctness_proof();
//         let zkp_proof = self.zkp_proof.clone();

//         corrupt!(ek_proof, self.corrupt_ek_proof(keygen_id, ek_proof));
//         corrupt!(zkp_proof, self.corrupt_zkp_proof(keygen_id, zkp_proof));

//         let bcast_out = serialize(&Bcast {
//             y_i_commit,
//             ek: self.ek,
//             ek_proof,
//             zkp: self.zkp,
//             zkp_proof,
//         })?;

//         Ok(NotDone(RoundBuilder::BcastOnly {
//             round: Box::new(r2::R2 {
//                 threshold: self.threshold,
//                 party_share_counts: self.party_share_counts,
//                 dk: self.dk,
//                 u_i_vss,
//                 y_i_reveal,
//                 #[cfg(feature = "malicious")]
//                 behaviour: self.behaviour,
//             }),
//             bcast_out,
//         }))
//     }
// }

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
            keygen_id: TypedUsize<KeygenShareId>,
            commit: Output,
        ) -> Output {
            if let Behaviour::R1BadCommit = self.behaviour {
                info!("malicious peer {} does {:?}", keygen_id, self.behaviour);
                commit.corrupt()
            } else {
                commit
            }
        }

        pub fn corrupt_ek_proof(
            &self,
            keygen_id: TypedUsize<KeygenShareId>,
            ek_proof: EncryptionKeyProof,
        ) -> EncryptionKeyProof {
            if let Behaviour::R1BadEncryptionKeyProof = self.behaviour {
                info!("malicious peer {} does {:?}", keygen_id, self.behaviour);
                paillier::zk::malicious::corrupt_ek_proof(ek_proof)
            } else {
                ek_proof
            }
        }

        pub fn corrupt_zkp_proof(
            &self,
            keygen_id: TypedUsize<KeygenShareId>,
            zkp_proof: ZkSetupProof,
        ) -> ZkSetupProof {
            if let Behaviour::R1BadZkSetupProof = self.behaviour {
                info!("malicious peer {} does {:?}", keygen_id, self.behaviour);
                paillier::zk::malicious::corrupt_zksetup_proof(zkp_proof)
            } else {
                zkp_proof
            }
        }
    }
}
