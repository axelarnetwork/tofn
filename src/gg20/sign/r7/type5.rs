use crate::{
    collections::{FillVecMap, FullP2ps, P2ps, VecMap},
    gg20::{
        crypto_tools::mta,
        keygen::SecretKeyShare,
        sign::{r2, r4, r7, KeygenShareIds},
    },
    sdk::{
        api::{BytesVec, Fault::ProtocolFault, TofnFatal, TofnResult},
        implementer_api::{Executer, ProtocolBuilder, ProtocolInfo},
    },
};
use k256::ProjectivePoint;
use tracing::{error, warn};

use super::super::{r1, r3, r5, r6, Peers, SignShareId};

#[allow(non_snake_case)]
pub(in super::super) struct R7Type5 {
    pub(in super::super) secret_key_share: SecretKeyShare,
    pub(in super::super) peer_keygen_ids: Peers,
    pub(in super::super) all_keygen_ids: KeygenShareIds,
    pub(in super::super) r1bcasts: VecMap<SignShareId, r1::Bcast>,
    pub(in super::super) r2p2ps: FullP2ps<SignShareId, r2::P2pHappy>,
    pub(in super::super) r3bcasts: VecMap<SignShareId, r3::BcastHappy>,
    pub(in super::super) r4bcasts: VecMap<SignShareId, r4::Bcast>,
    pub(in super::super) R: ProjectivePoint,
    pub(in super::super) r5bcasts: VecMap<SignShareId, r5::Bcast>,
    pub(in super::super) r5p2ps: FullP2ps<SignShareId, r5::P2p>,
}

impl Executer for R7Type5 {
    type FinalOutput = BytesVec;
    type Index = SignShareId;
    type Bcast = r6::Bcast;
    type P2p = ();

    #[allow(non_snake_case)]
    fn execute(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        bcasts_in: FillVecMap<Self::Index, Self::Bcast>,
        p2ps_in: P2ps<Self::Index, Self::P2p>,
    ) -> TofnResult<ProtocolBuilder<Self::FinalOutput, Self::Index>> {
        let my_sign_id = info.my_id();
        let mut faulters = info.new_fillvecmap();

        // anyone who did not send a bcast is a faulter
        for (peer_sign_id, bcast) in bcasts_in.iter() {
            if bcast.is_none() {
                warn!(
                    "peer {} says: missing bcast from peer {}",
                    my_sign_id, peer_sign_id
                );
                faulters.set(peer_sign_id, ProtocolFault)?;
            }
        }
        // anyone who sent p2ps is a faulter
        for (peer_sign_id, p2ps) in p2ps_in.iter() {
            if p2ps.is_some() {
                warn!(
                    "peer {} says: unexpected p2ps from peer {}",
                    my_sign_id, peer_sign_id
                );
                faulters.set(peer_sign_id, ProtocolFault)?;
            }
        }
        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        // check for complaints
        // If someone broadcasts a Sad complaint, switch to verifying that accusation.
        // While there might also be a Type 5 fault, we prioritize accusations.
        if bcasts_in
            .iter()
            .any(|(_, bcast_option)| matches!(bcast_option, Some(r6::Bcast::Sad(_))))
        {
            warn!(
                "peer {} says: received an R6 complaint from others while in Type5 path",
                my_sign_id,
            );

            return Box::new(r7::sad::R7Sad {
                secret_key_share: self.secret_key_share,
                all_keygen_ids: self.all_keygen_ids,
                r1bcasts: self.r1bcasts,
                R: self.R,
                r5bcasts: self.r5bcasts,
                r5p2ps: self.r5p2ps,
            })
            .execute(info, bcasts_in, p2ps_in);
        }

        // everyone sent their bcast/p2ps---unwrap all bcasts/p2ps
        let bcasts_in = bcasts_in.to_vecmap()?;

        let mut bcasts_sad = info.new_fillvecmap();

        // our check for 'type 5` error failed, so any peer broadcasting a success is a faulter
        for (peer_sign_id, bcast) in bcasts_in.into_iter() {
            match bcast {
                r6::Bcast::SadType5(bcast) => {
                    bcasts_sad.set(peer_sign_id, bcast)?;
                }
                r6::Bcast::Sad(_) => return Err(TofnFatal), // This should never happen
                r6::Bcast::Happy(_) => {
                    warn!(
                        "peer {} says: peer {} did not broadcast a 'type 5' failure",
                        my_sign_id, peer_sign_id
                    );
                    faulters.set(peer_sign_id, ProtocolFault)?;
                }
            }
        }

        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        let bcasts_in = bcasts_sad.to_vecmap()?;

        // verify that each participant's data is consistent with earlier messages:
        for (peer_sign_id, bcast) in &bcasts_in {
            let peer_mta_plaintexts = &bcast.mta_plaintexts;

            if peer_mta_plaintexts.len() != self.peer_keygen_ids.len() {
                warn!(
                    "peer {} says: peer {} sent {} MtA plaintexts, expected {}",
                    my_sign_id,
                    peer_sign_id,
                    peer_mta_plaintexts.len(),
                    self.peer_keygen_ids.len()
                );

                faulters.set(peer_sign_id, ProtocolFault)?;
                continue;
            }

            if peer_mta_plaintexts.get_hole() != peer_sign_id {
                warn!(
                    "peer {} says: peer {} sent MtA plaintexts with an unexpected hole {}",
                    my_sign_id,
                    peer_sign_id,
                    peer_mta_plaintexts.get_hole()
                );

                faulters.set(peer_sign_id, ProtocolFault)?;
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

            if &delta_i != self.r3bcasts.get(peer_sign_id)?.delta_i.as_ref() {
                warn!(
                    "peer {} says: delta_i for peer {} does not match",
                    my_sign_id, peer_sign_id
                );
                faulters.set(peer_sign_id, ProtocolFault)?;
                continue;
            }

            // verify R7 peer data is consistent with earlier messages:
            // 1. k_i
            // 2. gamma_i
            // 3. beta_ij
            // 4. alpha_ij
            let peer_keygen_id = *self.all_keygen_ids.get(peer_sign_id)?;

            let peer_ek = &self
                .secret_key_share
                .group()
                .all_shares()
                .get(peer_keygen_id)?
                .ek();

            // k_i
            let k_i_ciphertext = peer_ek
                .encrypt_with_randomness(&(bcast.k_i.as_ref()).into(), &bcast.k_i_randomness);
            if k_i_ciphertext != self.r1bcasts.get(peer_sign_id)?.k_i_ciphertext {
                warn!(
                    "peer {} says: invalid k_i detected from peer {}",
                    my_sign_id, peer_sign_id
                );
                faulters.set(peer_sign_id, ProtocolFault)?;
                continue;
            }

            // gamma_i
            let Gamma_i = ProjectivePoint::generator() * bcast.gamma_i.as_ref();
            if &Gamma_i != self.r4bcasts.get(peer_sign_id)?.Gamma_i.as_ref() {
                warn!(
                    "peer {} says: invalid Gamma_i detected from peer {}",
                    my_sign_id, peer_sign_id
                );
                faulters.set(peer_sign_id, ProtocolFault)?;
                continue;
            }

            // beta_ij, alpha_ij
            for (sign_peer2_id, peer_mta_plaintext) in peer_mta_plaintexts {
                let keygen_peer2_id = *self.all_keygen_ids.get(sign_peer2_id)?;

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
                    .get(peer_sign_id, sign_peer2_id)?
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
                        my_sign_id, peer_sign_id, sign_peer2_id
                    );

                    faulters.set(peer_sign_id, ProtocolFault)?;
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
                        .get(sign_peer2_id, peer_sign_id)?
                        .alpha_ciphertext
                {
                    warn!(
                        "peer {} says: invalid alpha from peer {} to victim peer {}",
                        my_sign_id, peer_sign_id, sign_peer2_id
                    );

                    faulters.set(peer_sign_id, ProtocolFault)?;
                    continue;
                }
            }
        }

        if faulters.is_empty() {
            error!(
                "peer {} says: No faulters found in 'type 5' failure protocol",
                my_sign_id
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
