use crate::{
    hash, k256_serde, paillier_k256,
    protocol::gg20::{vss_k256, SecretKeyShare},
    refactor::{
        api::BytesVec,
        protocol_round::{
            bcast_and_p2p::executer::{serialize, RoundExecuterRaw},
            ProtocolBuilder::{self, *},
            RoundBuilder,
        },
    },
    vecmap::{FillP2ps, FillVecMap, Index},
};
use serde::{Deserialize, Serialize};
use tracing::info;

use super::{r2, rng, KeygenPartyIndex};

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

impl RoundExecuterRaw for R1 {
    type FinalOutput = SecretKeyShare;
    type Index = KeygenPartyIndex;

    fn execute_raw(
        self: Box<Self>,
        _party_count: usize,
        index: Index<Self::Index>,
        _bcasts_in: FillVecMap<Self::Index, BytesVec>,
        _p2ps_in: FillP2ps<Self::Index, BytesVec>,
    ) -> ProtocolBuilder<Self::FinalOutput, Self::Index> {
        let u_i_vss = vss_k256::Vss::new(self.threshold);
        let (y_i_commit, y_i_reveal) = hash::commit(k256_serde::to_bytes(
            &(k256::ProjectivePoint::generator() * u_i_vss.get_secret()),
        ));

        #[cfg(feature = "malicious")]
        let y_i_commit = if matches!(self.behaviour, Behaviour::R1BadCommit) {
            info!("malicious party {} do {:?}", index, self.behaviour);
            y_i_commit.corrupt()
        } else {
            y_i_commit
        };

        let mut rng = rng::rng_from_seed(self.rng_seed);
        let (ek, dk) = paillier_k256::keygen_unsafe(&mut rng);
        let (zkp, zkp_proof) = paillier_k256::zk::ZkSetup::new_unsafe(&mut rng);
        let ek_proof = dk.correctness_proof();

        #[cfg(feature = "malicious")]
        let ek_proof = if matches!(self.behaviour, Behaviour::R1BadEncryptionKeyProof) {
            info!("malicious party {} do {:?}", index, self.behaviour);
            paillier_k256::zk::malicious::corrupt_ek_proof(ek_proof)
        } else {
            ek_proof
        };

        #[cfg(feature = "malicious")]
        let zkp_proof = if matches!(self.behaviour, Behaviour::R1BadZkSetupProof) {
            info!("malicious party {} do {:?}", index, self.behaviour);
            paillier_k256::zk::malicious::corrupt_zksetup_proof(zkp_proof)
        } else {
            zkp_proof
        };

        let bcast_out = Some(serialize(&Bcast {
            y_i_commit,
            ek,
            ek_proof,
            zkp,
            zkp_proof,
        }));

        NotDone(RoundBuilder {
            round: Box::new(r2::R2 {
                threshold: self.threshold,
                dk,
                u_i_vss,
                y_i_reveal,
                #[cfg(feature = "malicious")]
                behaviour: self.behaviour,
            }),
            bcast_out,
            p2ps_out: None,
        })
    }
}
