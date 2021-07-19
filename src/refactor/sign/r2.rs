use crate::{
    hash, mta,
    paillier_k256::{self, Ciphertext},
    refactor::{
        collections::{FillHoleVecMap, FillVecMap, P2ps, TypedUsize, VecMap},
        keygen::{KeygenPartyIndex, SecretKeyShare},
        protocol::{
            api::{BytesVec, Fault::ProtocolFault, TofnResult},
            bcast_and_p2p,
            implementer_api::{serialize, ProtocolBuilder, RoundBuilder},
        },
    },
};
use k256::{ProjectivePoint, Scalar};
use serde::{Deserialize, Serialize};
use tracing::warn;

use super::{r1, r3, Peers, SignParticipantIndex, SignProtocolBuilder};

#[cfg(feature = "malicious")]
use super::malicious::Behaviour;

#[allow(non_snake_case)]
pub struct R2 {
    pub secret_key_share: SecretKeyShare,
    pub msg_to_sign: Scalar,
    pub peers: Peers,
    pub keygen_id: TypedUsize<KeygenPartyIndex>,
    pub gamma_i: Scalar,
    pub Gamma_i: ProjectivePoint,
    pub Gamma_i_reveal: hash::Randomness,
    pub w_i: Scalar,
    pub k_i: Scalar,
    pub k_i_randomness: paillier_k256::Randomness,

    #[cfg(feature = "malicious")]
    pub behaviour: Behaviour,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct Bcast {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct P2p {
    pub alpha_ciphertext: Ciphertext,
    pub alpha_proof: paillier_k256::zk::mta::Proof,
    pub mu_ciphertext: Ciphertext,
    pub mu_proof: paillier_k256::zk::mta::ProofWc,
}

impl bcast_and_p2p::Executer for R2 {
    type FinalOutput = BytesVec;
    type Index = SignParticipantIndex;
    type Bcast = r1::Bcast;
    type P2p = r1::P2p;

    fn execute(
        self: Box<Self>,
        participants_count: usize,
        sign_id: TypedUsize<Self::Index>,
        bcasts_in: VecMap<Self::Index, Self::Bcast>,
        p2ps_in: P2ps<Self::Index, Self::P2p>,
    ) -> TofnResult<SignProtocolBuilder> {
        let mut faulters = FillVecMap::with_size(participants_count);

        let mut beta_secrets = FillHoleVecMap::with_size(participants_count, sign_id)?;
        let mut nu_secrets = FillHoleVecMap::with_size(participants_count, sign_id)?;

        // step 2 for MtA protocols:
        // 1. k_i (other) * gamma_j (me)
        // 2. k_i (other) * w_j (me)
        for (sign_peer_id, &keygen_peer_id) in &self.peers {
            // k256: verify zk proof for first message of MtA
            let peer_ek = &self
                .secret_key_share
                .group
                .all_shares
                .get(keygen_peer_id)?
                .ek;
            let peer_k_i_ciphertext = &bcasts_in.get(sign_id)?.k_i_ciphertext;

            let peer_stmt = &paillier_k256::zk::range::Statement {
                ciphertext: peer_k_i_ciphertext,
                ek: peer_ek,
            };

            let peer_proof = &p2ps_in.get(sign_peer_id, sign_id)?.range_proof;

            let zkp = &self
                .secret_key_share
                .group
                .all_shares
                .get(self.keygen_id)?
                .zkp;

            if let Err(err) = zkp.verify_range_proof(peer_stmt, peer_proof) {
                warn!(
                    "peer {} says: range proof from peer {} failed to verify because [{}]",
                    sign_id, sign_peer_id, err
                );

                faulters.set(sign_peer_id, ProtocolFault)?;
            }
        }

        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        let mut p2ps_out = FillHoleVecMap::with_size(participants_count, sign_id)?;

        for (sign_peer_id, &keygen_peer_id) in &self.peers {
            // k256: MtA step 2 for k_i * gamma_j
            let peer_ek = &self
                .secret_key_share
                .group
                .all_shares
                .get(keygen_peer_id)?
                .ek;
            let peer_k_i_ciphertext = &bcasts_in.get(sign_id)?.k_i_ciphertext;
            let peer_zkp = &self
                .secret_key_share
                .group
                .all_shares
                .get(keygen_peer_id)?
                .zkp;

            let (alpha_ciphertext, alpha_proof, beta_secret) =
                mta::mta_response_with_proof(peer_zkp, peer_ek, peer_k_i_ciphertext, &self.gamma_i);

            beta_secrets.set(sign_peer_id, beta_secret)?;

            let (mu_ciphertext, mu_proof, nu_secret) =
                mta::mta_response_with_proof_wc(peer_zkp, peer_ek, peer_k_i_ciphertext, &self.w_i);

            nu_secrets.set(sign_peer_id, nu_secret)?;

            let p2p = serialize(&P2p {
                alpha_ciphertext,
                alpha_proof,
                mu_ciphertext,
                mu_proof,
            })?;

            p2ps_out.set(sign_peer_id, p2p)?;
        }

        let beta_secrets = beta_secrets.unwrap_all()?;
        let nu_secrets = nu_secrets.unwrap_all()?;
        let p2ps_out = p2ps_out.unwrap_all()?;

        let bcast_out = serialize(&Bcast {})?;

        Ok(ProtocolBuilder::NotDone(RoundBuilder::BcastAndP2p {
            round: Box::new(r3::R3 {
                secret_key_share: self.secret_key_share,
                msg_to_sign: self.msg_to_sign,
                peers: self.peers,
                keygen_id: self.keygen_id,
                gamma_i: self.gamma_i,
                Gamma_i: self.Gamma_i,
                Gamma_i_reveal: self.Gamma_i_reveal,
                w_i: self.w_i,
                k_i: self.k_i,
                k_i_randomness: self.k_i_randomness,
                beta_secrets,
                nu_secrets,
                r1bcasts: bcasts_in,

                #[cfg(feature = "malicious")]
                behaviour: self.behaviour,
            }),
            bcast_out,
            p2ps_out,
        }))
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
