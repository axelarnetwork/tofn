use crate::{
    hash::Randomness,
    mta, paillier,
    refactor::{
        collections::{FillVecMap, P2ps, TypedUsize, VecMap},
        keygen::{KeygenPartyIndex, SecretKeyShare},
        sdk::{
            api::{BytesVec, Fault::ProtocolFault, TofnFatal, TofnResult},
            implementer_api::{bcast_only, ProtocolBuilder, ProtocolInfo},
        },
        sign::{r2, r4, Participants},
    },
};
use k256::{ProjectivePoint, Scalar};
use tracing::{error, warn};

use super::super::{r1, r3, r5, r6, Peers, SignParticipantIndex, SignProtocolBuilder};

#[cfg(feature = "malicious")]
use super::super::malicious::Behaviour;

#[allow(non_snake_case)]
pub struct R7 {
    pub secret_key_share: SecretKeyShare,
    pub msg_to_sign: Scalar,
    pub peers: Peers,
    pub participants: Participants,
    pub keygen_id: TypedUsize<KeygenPartyIndex>,
    pub gamma_i: Scalar,
    pub Gamma_i: ProjectivePoint,
    pub Gamma_i_reveal: Randomness,
    pub w_i: Scalar,
    pub k_i: Scalar,
    pub k_i_randomness: paillier::Randomness,
    pub sigma_i: Scalar,
    pub l_i: Scalar,
    pub T_i: ProjectivePoint,
    pub r1bcasts: VecMap<SignParticipantIndex, r1::Bcast>,
    pub r2p2ps: P2ps<SignParticipantIndex, r2::P2pHappy>,
    pub r3bcasts: VecMap<SignParticipantIndex, r3::happy::BcastHappy>,
    pub r4bcasts: VecMap<SignParticipantIndex, r4::happy::Bcast>,
    pub delta_inv: Scalar,
    pub R: ProjectivePoint,
    pub r5bcasts: VecMap<SignParticipantIndex, r5::Bcast>,

    #[cfg(feature = "malicious")]
    pub behaviour: Behaviour,
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

        let mut faulters = FillVecMap::with_size(participants_count);
        let mut bcasts = FillVecMap::with_size(participants_count);

        // our check for 'type 5` error failed, so any peer broadcasting a success is a faulter
        for (sign_peer_id, bcast) in bcasts_in.into_iter() {
            match bcast {
                r6::Bcast::SadType5(bcast) => {
                    bcasts.set(sign_peer_id, bcast)?;
                }
                r6::Bcast::Sad(_) => {
                    // TODO: What do we prioritize first?
                    todo!()
                }
                r6::Bcast::Happy(_) => {
                    warn!(
                        "peer {} says: peer {} did not broadcast a 'type 5' failure",
                        sign_id, sign_peer_id
                    );
                    faulters.set(sign_peer_id, ProtocolFault)?;
                }
            }
        }

        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        let bcasts_in = bcasts.unwrap_all()?;

        // verify that each participant's data is consistent with earlier messages:
        for (sign_peer_id, bcast) in &bcasts_in {
            let mta_plaintexts = &bcast.mta_plaintexts;

            if mta_plaintexts.len() != self.peers.len() {
                warn!(
                    "peer {} says: peer {} did not send all the MtA plaintexts",
                    sign_id, sign_peer_id
                );
                faulters.set(sign_peer_id, ProtocolFault)?;
                continue;
            }

            // verify correct computation of delta_i
            let delta_i = mta_plaintexts.iter().fold(
                bcast.k_i.unwrap() * bcast.gamma_i.unwrap(),
                |acc, (_, mta_plaintext)| {
                    acc + mta_plaintext.alpha_plaintext.to_scalar()
                        + mta_plaintext.beta_secret.beta.unwrap()
                },
            );

            if &delta_i != self.r3bcasts.get(sign_peer_id)?.delta_i.unwrap() {
                warn!(
                    "peer {} says: delta_i for peer {} does not match",
                    sign_id, sign_peer_id
                );
                faulters.set(sign_peer_id, ProtocolFault)?;
                continue;
            }

            // verify R7 peer data is consistent with earlier messages:
            // 1. k_i
            // 2. gamma_i
            // 3. beta_ij
            // 4. alpha_ij
            let keygen_peer_id = *self.participants.get(sign_peer_id)?;

            let peer_ek = &self
                .secret_key_share
                .group()
                .all_shares()
                .get(keygen_peer_id)?
                .ek();

            // k_i
            let k_i_ciphertext = peer_ek
                .encrypt_with_randomness(&(bcast.k_i.unwrap()).into(), &bcast.k_i_randomness);
            if k_i_ciphertext != self.r1bcasts.get(sign_peer_id)?.k_i_ciphertext {
                warn!(
                    "peer {} says: invalid k_i detected from peer {}",
                    sign_id, sign_peer_id
                );
                faulters.set(sign_peer_id, ProtocolFault)?;
                continue;
            }

            // gamma_i
            let Gamma_i = ProjectivePoint::generator() * bcast.gamma_i.unwrap();
            if &Gamma_i != self.r4bcasts.get(sign_peer_id)?.Gamma_i.unwrap() {
                warn!(
                    "peer {} says: invalid Gamma_i detected from peer {}",
                    sign_id, sign_peer_id
                );
                faulters.set(sign_peer_id, ProtocolFault)?;
                continue;
            }

            // beta_ij, alpha_ij
            for (sign_party_id, mta_plaintext) in mta_plaintexts {
                let keygen_party_id = *self.participants.get(sign_party_id)?;

                // beta_ij
                let party_ek = &self
                    .secret_key_share
                    .group()
                    .all_shares()
                    .get(keygen_party_id)?
                    .ek();
                let party_k_i_ciphertext = &self.r1bcasts.get(sign_party_id)?.k_i_ciphertext;
                let party_alpha_ciphertext = &self
                    .r2p2ps
                    .get(sign_peer_id, sign_party_id)?
                    .alpha_ciphertext;

                if !mta::verify_mta_response(
                    party_ek,
                    party_k_i_ciphertext,
                    bcast.gamma_i.unwrap(),
                    party_alpha_ciphertext,
                    &mta_plaintext.beta_secret,
                ) {
                    // TODO: Who's responsible for the failure here?
                    warn!(
                        "peer {} says: invalid beta from peer {} to victim peer {}",
                        sign_id, sign_peer_id, sign_party_id
                    );
                    faulters.set(sign_peer_id, ProtocolFault)?;
                    continue;
                }

                // alpha_ij
                let peer_alpha_ciphertext = peer_ek.encrypt_with_randomness(
                    &mta_plaintext.alpha_plaintext,
                    &mta_plaintext.alpha_randomness,
                );
                if peer_alpha_ciphertext
                    != self
                        .r2p2ps
                        .get(sign_party_id, sign_peer_id)?
                        .alpha_ciphertext
                {
                    // TODO: Who's responsible for the failure here?
                    warn!(
                        "peer {} says: invalid alpha from peer {} to victim peer {}",
                        sign_id, sign_peer_id, sign_party_id
                    );
                    faulters.set(sign_peer_id, ProtocolFault)?;
                    continue;
                }
            }
        }

        if faulters.is_empty() {
            error!(
                "peer {} says: No faulters found in 'type 5' failure protocol",
                sign_id
            );
            return Err(TofnFatal);
        }

        Ok(ProtocolBuilder::Done(Err(faulters)))
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
