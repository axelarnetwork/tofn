use crate::{
    hash::Randomness,
    k256_serde,
    mta::Secret,
    paillier_k256,
    refactor::{
        collections::{FillVecMap, HoleVecMap, TypedUsize, VecMap},
        keygen::{KeygenPartyIndex, SecretKeyShare},
        protocol::{
            api::{BytesVec, Fault::ProtocolFault, TofnResult},
            bcast_only,
            implementer_api::{serialize, ProtocolBuilder, RoundBuilder},
        },
    },
    zkp::pedersen_k256,
};
use ecdsa::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, Scalar};
use serde::{Deserialize, Serialize};
use tracing::{error, warn};

use super::{r1, r5, r6, r8, Peers, SignParticipantIndex, SignProtocolBuilder};

#[cfg(feature = "malicious")]
use super::malicious::Behaviour;

#[allow(non_snake_case)]
pub struct R7 {
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
    // TODO: Remove these as needed
    pub(crate) _beta_secrets: HoleVecMap<SignParticipantIndex, Secret>,
    pub(crate) _nu_secrets: HoleVecMap<SignParticipantIndex, Secret>,
    pub r1bcasts: VecMap<SignParticipantIndex, r1::Bcast>,
    pub delta_inv: Scalar,
    pub R: ProjectivePoint,
    pub r5bcasts: VecMap<SignParticipantIndex, r5::Bcast>,

    #[cfg(feature = "malicious")]
    pub behaviour: Behaviour,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct Bcast {
    pub s_i: k256_serde::Scalar,
}

impl bcast_only::Executer for R7 {
    type FinalOutput = BytesVec;
    type Index = SignParticipantIndex;
    type Bcast = r6::Bcast;

    #[allow(non_snake_case)]
    fn execute(
        self: Box<Self>,
        participants_count: usize,
        sign_id: TypedUsize<Self::Index>,
        bcasts_in: VecMap<Self::Index, Self::Bcast>,
    ) -> TofnResult<SignProtocolBuilder> {
        let mut faulters = FillVecMap::with_size(participants_count);

        // verify proofs
        for (sign_peer_id, bcast) in &bcasts_in {
            let peer_stmt = &pedersen_k256::StatementWc {
                stmt: pedersen_k256::Statement { commit: &self.T_i },
                msg_g: bcast.S_i.unwrap(),
                g: &self.R,
            };

            if let Err(err) = pedersen_k256::verify_wc(&peer_stmt, &bcast.S_i_proof_wc) {
                warn!(
                    "peer {} says: pedersen proof wc failed to verify for peer {} because [{}]",
                    sign_id, sign_peer_id, err
                );

                faulters.set(sign_peer_id, ProtocolFault)?;
            }
        }

        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        // check for failure of type 7 from section 4.2 of https://eprint.iacr.org/2020/540.pdf
        let S_i_sum: ProjectivePoint = bcasts_in
            .iter()
            .fold(ProjectivePoint::identity(), |acc, (_, bcast)| {
                acc + bcast.S_i.unwrap()
            });

        if &S_i_sum != self.secret_key_share.group.y.unwrap() {
            warn!("peer {} says: 'type 7' fault detected", sign_id);

            // TODO: Move to sad path
            return Err(());
        }

        // compute r, s_i
        // reference for r: https://docs.rs/k256/0.8.1/src/k256/ecdsa/sign.rs.html#223-225
        let r = k256::Scalar::from_bytes_reduced(
            self.R
                .to_affine()
                .to_encoded_point(true)
                .x()
                .ok_or_else(|| {
                    error!("Invalid R point");
                })?,
        );

        let s_i = self.msg_to_sign * self.k_i + r * self.sigma_i;

        let bcast_out = serialize(&Bcast { s_i: s_i.into() })?;

        Ok(ProtocolBuilder::NotDone(RoundBuilder::BcastOnly {
            round: Box::new(r8::R8 {
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
                r1bcasts: self.r1bcasts,
                delta_inv: self.delta_inv,
                R: self.R,
                r,
                r5bcasts: self.r5bcasts,
                r6bcasts: bcasts_in,

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
