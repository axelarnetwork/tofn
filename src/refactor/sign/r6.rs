use crate::{
    hash::Randomness,
    k256_serde,
    mta::Secret,
    paillier_k256::{self, zk},
    refactor::{
        collections::{FillVecMap, HoleVecMap, P2ps, TypedUsize, VecMap},
        keygen::{KeygenPartyIndex, SecretKeyShare},
        protocol::{
            api::{BytesVec, Fault::ProtocolFault, TofnResult},
            bcast_and_p2p,
            implementer_api::{serialize, ProtocolBuilder, RoundBuilder},
        },
    },
    zkp::pedersen_k256,
};
use k256::{ProjectivePoint, Scalar};
use serde::{Deserialize, Serialize};
use tracing::warn;

use super::{r1, r5, r7, Peers, SignParticipantIndex, SignProtocolBuilder};

#[cfg(feature = "malicious")]
use super::malicious::Behaviour;

#[allow(non_snake_case)]
pub struct R6 {
    pub secret_key_share: SecretKeyShare,
    pub msg_to_sign: Scalar,
    pub peers: Peers,
    pub keygen_id: TypedUsize<KeygenPartyIndex>,
    pub gamma_i: Scalar,
    pub Gamma_i: ProjectivePoint,
    pub Gamma_i_reveal: Randomness,
    pub w_i: Scalar,
    pub k_i: Scalar,
    pub k_i_randomness: paillier_k256::Randomness,
    pub sigma_i: Scalar,
    pub l_i: Scalar,
    pub T_i: ProjectivePoint,
    pub(crate) beta_secrets: HoleVecMap<SignParticipantIndex, Secret>,
    pub(crate) nu_secrets: HoleVecMap<SignParticipantIndex, Secret>,
    pub r1bcasts: VecMap<SignParticipantIndex, r1::Bcast>,
    pub delta_inv: Scalar,
    pub R: ProjectivePoint,

    #[cfg(feature = "malicious")]
    pub behaviour: Behaviour,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct Bcast {
    pub S_i: k256_serde::ProjectivePoint,
    pub S_i_proof_wc: pedersen_k256::ProofWc,
}

impl bcast_and_p2p::Executer for R6 {
    type FinalOutput = BytesVec;
    type Index = SignParticipantIndex;
    type Bcast = r5::Bcast;
    type P2p = r5::P2p;

    #[allow(non_snake_case)]
    fn execute(
        self: Box<Self>,
        participants_count: usize,
        sign_id: TypedUsize<Self::Index>,
        bcasts_in: VecMap<Self::Index, Self::Bcast>,
        p2ps_in: P2ps<Self::Index, Self::P2p>,
    ) -> TofnResult<SignProtocolBuilder> {
        let mut faulters = FillVecMap::with_size(participants_count);

        // verify proofs
        for (sign_peer_id, bcast) in &bcasts_in {
            let zkp = &self
                .secret_key_share
                .group
                .all_shares
                .get(self.keygen_id)?
                .zkp;
            let peer_k_i_ciphertext = &self.r1bcasts.get(sign_peer_id)?.k_i_ciphertext;
            let ek = &self
                .secret_key_share
                .group
                .all_shares
                .get(self.keygen_id)?
                .ek;
            let p2p_in = p2ps_in.get(sign_peer_id, sign_id)?;

            let peer_stmt = &zk::range::StatementWc {
                stmt: zk::range::Statement {
                    ciphertext: peer_k_i_ciphertext,
                    ek,
                },
                msg_g: bcast.R_i.unwrap(),
                g: &self.R,
            };

            if let Err(err) = zkp.verify_range_proof_wc(&peer_stmt, &p2p_in.k_i_range_proof_wc) {
                warn!(
                    "peer {} says: range proof wc failed to verify for peer {} because [{}]",
                    sign_id, sign_peer_id, err
                );

                faulters.set(sign_peer_id, ProtocolFault)?;
            }
        }

        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        // check for failure of type 5 from section 4.2 of https://eprint.iacr.org/2020/540.pdf
        let R_i_sum: ProjectivePoint = bcasts_in
            .iter()
            .fold(ProjectivePoint::identity(), |acc, (_, bcast)| {
                acc + bcast.R_i.unwrap()
            });

        if R_i_sum != ProjectivePoint::generator() {
            warn!("peer {} says: 'type 5' fault detected", sign_id);

            // TODO: Move to sad path
            return Err(());
        }

        let S_i = self.R * self.sigma_i;
        let S_i_proof_wc = pedersen_k256::prove_wc(
            &pedersen_k256::StatementWc {
                stmt: pedersen_k256::Statement { commit: &self.T_i },
                msg_g: &S_i,
                g: &self.R,
            },
            &pedersen_k256::Witness {
                msg: &self.sigma_i,
                randomness: &self.l_i,
            },
        );

        let bcast_out = serialize(&Bcast {
            S_i: S_i.into(),
            S_i_proof_wc,
        })?;

        Ok(ProtocolBuilder::NotDone(RoundBuilder::BcastOnly {
            round: Box::new(r7::R7 {
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
                sigma_i: self.sigma_i,
                l_i: self.l_i,
                T_i: self.T_i,
                _beta_secrets: self.beta_secrets,
                _nu_secrets: self.nu_secrets,
                r1bcasts: self.r1bcasts,
                delta_inv: self.delta_inv,
                R: self.R,
                r5bcasts: bcasts_in,

                #[cfg(feature = "malicious")]
                behaviour: self.behaviour,
            }),
            bcast_out,
        }))
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
