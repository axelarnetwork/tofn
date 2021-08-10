use crate::{
    collections::{FillVecMap, P2ps, VecMap},
    gg20::{
        crypto_tools::mta,
        keygen::SecretKeyShare,
        sign::{r2, r4, r7, Participants},
    },
    sdk::{
        api::{BytesVec, Fault::ProtocolFault, TofnFatal, TofnResult},
        implementer_api::{bcast_only, ProtocolBuilder, ProtocolInfo},
    },
};
use k256::ProjectivePoint;
use tracing::{error, warn};

use super::super::{r1, r3, r5, r6, Peers, SignProtocolBuilder, SignShareId};

#[cfg(feature = "malicious")]
use super::super::malicious::Behaviour;

#[allow(non_snake_case)]
pub(crate) struct R7Type5 {
    pub(crate) secret_key_share: SecretKeyShare,
    pub(crate) peers: Peers,
    pub(crate) participants: Participants,
    pub(crate) r1bcasts: VecMap<SignShareId, r1::Bcast>,
    pub(crate) r2p2ps: P2ps<SignShareId, r2::P2pHappy>,
    pub(crate) r3bcasts: VecMap<SignShareId, r3::BcastHappy>,
    pub(crate) r4bcasts: VecMap<SignShareId, r4::Bcast>,
    pub(crate) R: ProjectivePoint,
    pub(crate) r5bcasts: VecMap<SignShareId, r5::Bcast>,
    pub(crate) r5p2ps: P2ps<SignShareId, r5::P2p>,

    #[cfg(feature = "malicious")]
    pub behaviour: Behaviour,
}

impl bcast_only::Executer for R7Type5 {
    type FinalOutput = BytesVec;
    type Index = SignShareId;
    type Bcast = r6::Bcast;

    #[allow(non_snake_case)]
    fn execute(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        bcasts_in: VecMap<Self::Index, Self::Bcast>,
    ) -> TofnResult<SignProtocolBuilder> {
        let sign_id = info.share_id();
        let participants_count = info.share_count();

        // check for complaints
        // If someone broadcasts a Sad complaint, switch to verifying that accusation.
        // While there might also be a Type 5 fault, we prioritize accusations.
        if bcasts_in
            .iter()
            .any(|(_, bcast)| matches!(bcast, r6::Bcast::Sad(_)))
        {
            warn!(
                "peer {} says: received an R6 complaint from others while in Type5 path",
                sign_id,
            );

            return Box::new(r7::sad::R7Sad {
                secret_key_share: self.secret_key_share,
                participants: self.participants,
                r1bcasts: self.r1bcasts,
                R: self.R,
                r5bcasts: self.r5bcasts,
                r5p2ps: self.r5p2ps,

                #[cfg(feature = "malicious")]
                behaviour: self.behaviour,
            })
            .execute(info, bcasts_in);
        }

        let mut faulters = FillVecMap::with_size(participants_count);
        let mut bcasts_sad = FillVecMap::with_size(participants_count);

        // our check for 'type 5` error failed, so any peer broadcasting a success is a faulter
        for (sign_peer_id, bcast) in bcasts_in.into_iter() {
            match bcast {
                r6::Bcast::SadType5(bcast) => {
                    bcasts_sad.set(sign_peer_id, bcast)?;
                }
                r6::Bcast::Sad(_) => return Err(TofnFatal), // This should never happen
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

        let bcasts_in = bcasts_sad.to_vecmap()?;

        // verify that each participant's data is consistent with earlier messages:
        for (sign_peer_id, bcast) in &bcasts_in {
            let peer_mta_plaintexts = &bcast.mta_plaintexts;

            if peer_mta_plaintexts.len() != self.peers.len() {
                warn!(
                    "peer {} says: peer {} sent {} MtA plaintexts, expected {}",
                    sign_id,
                    sign_peer_id,
                    peer_mta_plaintexts.len(),
                    self.peers.len()
                );

                faulters.set(sign_peer_id, ProtocolFault)?;
                continue;
            }

            if peer_mta_plaintexts.get_hole() != sign_peer_id {
                warn!(
                    "peer {} says: peer {} sent MtA plaintexts with an unexpected hole {}",
                    sign_id,
                    sign_peer_id,
                    peer_mta_plaintexts.get_hole()
                );

                faulters.set(sign_peer_id, ProtocolFault)?;
                continue;
            }

            // verify correct computation of delta_i
            let delta_i = peer_mta_plaintexts.iter().fold(
                bcast.k_i.as_ref() * bcast.gamma_i.as_ref(),
                |acc, (_, mta_plaintext)| {
                    acc + mta_plaintext.alpha_plaintext.to_scalar()
                        + mta_plaintext.beta_secret.beta.as_ref()
                },
            );

            if &delta_i != self.r3bcasts.get(sign_peer_id)?.delta_i.as_ref() {
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
                .encrypt_with_randomness(&(bcast.k_i.as_ref()).into(), &bcast.k_i_randomness);
            if k_i_ciphertext != self.r1bcasts.get(sign_peer_id)?.k_i_ciphertext {
                warn!(
                    "peer {} says: invalid k_i detected from peer {}",
                    sign_id, sign_peer_id
                );
                faulters.set(sign_peer_id, ProtocolFault)?;
                continue;
            }

            // gamma_i
            let Gamma_i = ProjectivePoint::generator() * bcast.gamma_i.as_ref();
            if &Gamma_i != self.r4bcasts.get(sign_peer_id)?.Gamma_i.as_ref() {
                warn!(
                    "peer {} says: invalid Gamma_i detected from peer {}",
                    sign_id, sign_peer_id
                );
                faulters.set(sign_peer_id, ProtocolFault)?;
                continue;
            }

            // beta_ij, alpha_ij
            for (sign_peer2_id, peer_mta_plaintext) in peer_mta_plaintexts {
                let keygen_peer2_id = *self.participants.get(sign_peer2_id)?;

                // beta_ij
                let peer2_ek = &self
                    .secret_key_share
                    .group()
                    .all_shares()
                    .get(keygen_peer2_id)?
                    .ek();
                let peer2_k_i_ciphertext = &self.r1bcasts.get(sign_peer2_id)?.k_i_ciphertext;
                let peer2_alpha_ciphertext = &self
                    .r2p2ps
                    .get(sign_peer_id, sign_peer2_id)?
                    .alpha_ciphertext;

                if !mta::verify_mta_response(
                    peer2_ek,
                    peer2_k_i_ciphertext,
                    bcast.gamma_i.as_ref(),
                    peer2_alpha_ciphertext,
                    &peer_mta_plaintext.beta_secret,
                ) {
                    warn!(
                        "peer {} says: invalid beta from peer {} to victim peer {}",
                        sign_id, sign_peer_id, sign_peer2_id
                    );

                    faulters.set(sign_peer_id, ProtocolFault)?;
                    continue;
                }

                // alpha_ij
                let peer_alpha_ciphertext = peer_ek.encrypt_with_randomness(
                    &peer_mta_plaintext.alpha_plaintext,
                    &peer_mta_plaintext.alpha_randomness,
                );
                if peer_alpha_ciphertext
                    != self
                        .r2p2ps
                        .get(sign_peer2_id, sign_peer_id)?
                        .alpha_ciphertext
                {
                    warn!(
                        "peer {} says: invalid alpha from peer {} to victim peer {}",
                        sign_id, sign_peer_id, sign_peer2_id
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
