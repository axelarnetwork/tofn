use crate::{
    hash::Randomness,
    k256_serde,
    mta::Secret,
    paillier_k256,
    refactor::{
        collections::{FillVecMap, HoleVecMap, P2ps, TypedUsize, VecMap},
        keygen::{KeygenPartyIndex, SecretKeyShare},
        sdk::{
            api::{BytesVec, Fault::ProtocolFault, TofnFatal, TofnResult},
            implementer_api::{bcast_only, serialize, ProtocolBuilder, ProtocolInfo, RoundBuilder},
        },
        sign::{r4, r7, SignParticipantIndex},
    },
    zkp::pedersen_k256,
};
use ecdsa::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, Scalar};
use serde::{Deserialize, Serialize};
use tracing::{error, warn};

use super::super::{r1, r2, r3, r5, r6, r8, Peers, SignProtocolBuilder};

#[cfg(feature = "malicious")]
use super::super::malicious::Behaviour;

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
    pub(crate) beta_secrets: HoleVecMap<SignParticipantIndex, Secret>,
    pub(crate) nu_secrets: HoleVecMap<SignParticipantIndex, Secret>,
    pub r1bcasts: VecMap<SignParticipantIndex, r1::Bcast>,
    pub r2p2ps: P2ps<SignParticipantIndex, r2::P2p>,
    pub r3bcasts: VecMap<SignParticipantIndex, r3::Bcast>,
    pub r4bcasts: VecMap<SignParticipantIndex, r4::Bcast>,
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
        info: &ProtocolInfo<Self::Index>,
        bcasts_in: VecMap<Self::Index, Self::Bcast>,
    ) -> TofnResult<SignProtocolBuilder> {
        let sign_id = info.share_id();
        let participants_count = info.share_count();

        for (sign_peer_id, bcast) in &bcasts_in {
            if matches!(bcast, r6::Bcast::Sad(_)) {
                warn!(
                    "peer {} says: received a complaint from peer {}; running the 'type 5' failure protocol",
                    sign_id, sign_peer_id,
                );

                return Box::new(r7::sad::R7 {
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
                    r2p2ps: self.r2p2ps,
                    r3bcasts: self.r3bcasts,
                    r4bcasts: self.r4bcasts,
                    delta_inv: self.delta_inv,
                    R: self.R,
                    r5bcasts: self.r5bcasts,

                    #[cfg(feature = "malicious")]
                    behaviour: self.behaviour,
                })
                .execute(info, bcasts_in);
            }
        }

        let mut faulters = FillVecMap::with_size(participants_count);
        let bcasts: VecMap<SignParticipantIndex, &r6::BcastHappy> = VecMap::from_vec(
            bcasts_in
                .iter()
                .filter_map(|(_, bcast)| match bcast {
                    r6::Bcast::Happy(b) => Some(b),
                    _ => None,
                })
                .collect::<Vec<_>>(),
        );

        if bcasts.len() != self.peers.len() {
            error!("invalid happy bcast length received");
            return Err(TofnFatal);
        }

        // verify proofs
        for (sign_peer_id, bcast) in &bcasts {
            let peer_stmt = &pedersen_k256::StatementWc {
                stmt: pedersen_k256::Statement {
                    commit: &self.r3bcasts.get(sign_peer_id)?.T_i.unwrap(),
                },
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
        let S_i_sum = bcasts
            .iter()
            .fold(ProjectivePoint::identity(), |acc, (_, bcast)| {
                acc + bcast.S_i.unwrap()
            });

        if &S_i_sum != self.secret_key_share.group().y().unwrap() {
            warn!("peer {} says: 'type 7' fault detected", sign_id);

            // TODO: Move to sad path
            return Err(TofnFatal);
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
                    TofnFatal
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
