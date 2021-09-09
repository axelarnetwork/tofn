use crate::{
    collections::{zip2, FillVecMap, FullP2ps, P2ps, VecMap},
    gg20::{
        crypto_tools::mta,
        keygen::SecretKeyShare,
        sign::{
            r2, r4,
            r7::{
                self,
                common::{check_message_types, R7Path},
            },
            KeygenShareIds,
        },
    },
    sdk::{
        api::{BytesVec, Fault::ProtocolFault, TofnFatal, TofnResult},
        implementer_api::{Executer, ProtocolBuilder, ProtocolInfo},
    },
};
use k256::ProjectivePoint;
use tracing::{error, warn};

use super::super::{r1, r3, r5, r6, SignShareId};

#[allow(non_snake_case)]
pub(in super::super) struct R7Type5 {
    pub(in super::super) secret_key_share: SecretKeyShare,
    pub(in super::super) all_keygen_ids: KeygenShareIds,
    pub(in super::super) r1bcasts: VecMap<SignShareId, r1::Bcast>,
    pub(in super::super) r2p2ps: FullP2ps<SignShareId, r2::P2pHappy>,
    pub(in super::super) r3bcasts: VecMap<SignShareId, r3::BcastHappy>,
    pub(in super::super) r4bcasts: VecMap<SignShareId, r4::BcastHappy>,
    pub(in super::super) R: ProjectivePoint,
    pub(in super::super) r5bcasts: VecMap<SignShareId, r5::Bcast>,
    pub(in super::super) r5p2ps: FullP2ps<SignShareId, r5::P2p>,
}

impl Executer for R7Type5 {
    type FinalOutput = BytesVec;
    type Index = SignShareId;
    type Bcast = r6::Bcast;
    type P2p = r6::P2p;

    #[allow(non_snake_case)]
    fn execute(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        bcasts_in: FillVecMap<Self::Index, Self::Bcast>,
        p2ps_in: P2ps<Self::Index, Self::P2p>,
    ) -> TofnResult<ProtocolBuilder<Self::FinalOutput, Self::Index>> {
        let my_sign_id = info.my_id();
        let mut faulters = info.new_fillvecmap();

        let paths = check_message_types(info, &bcasts_in, &p2ps_in, &mut faulters)?;
        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        // if anyone complained then move to sad path
        if paths.iter().any(|(_, path)| matches!(path, R7Path::Sad)) {
            warn!(
                "peer {} says: received an R6 complaint from others---switch path type-5 -> sad",
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

        // our check for type 5 failed, so anyone who claimed success is a faulter
        for (peer_sign_id, path) in paths.iter() {
            if matches!(path, R7Path::Happy) {
                warn!(
                    "peer {} says: peer {} falsely claimed type 5 success",
                    my_sign_id, peer_sign_id
                );
                faulters.set(peer_sign_id, ProtocolFault)?;
            }
        }
        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        // type-5 sad path: everyone is in R7Path::SadType5--unwrap bcast and p2p into expected types
        // TODO combine to_vecmap() and to_fullp2ps() into new map2_result methods?
        let bcasts_in = bcasts_in.to_vecmap()?;
        let bcasts_in = bcasts_in.map2_result(|(_, bcast)| {
            if let r6::Bcast::SadType5(t) = bcast {
                Ok(t)
            } else {
                Err(TofnFatal)
            }
        })?;
        let p2ps_in = p2ps_in.to_fullp2ps()?;
        let p2ps_in = p2ps_in.map2_result(|(_, p2p)| {
            if let r6::P2p::SadType5(t) = p2p {
                Ok(t.mta_plaintext)
            } else {
                Err(TofnFatal)
            }
        })?;

        for (peer_sign_id, bcast_type5, peer_mta_plaintexts) in zip2(bcasts_in, p2ps_in) {
            // verify correct computation of delta_i
            let delta_i = peer_mta_plaintexts.iter().fold(
                bcast_type5.k_i.as_ref() * bcast_type5.gamma_i.as_ref(),
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
            let k_i_ciphertext = peer_ek.encrypt_with_randomness(
                &(bcast_type5.k_i.as_ref()).into(),
                &bcast_type5.k_i_randomness,
            );
            if k_i_ciphertext != self.r1bcasts.get(peer_sign_id)?.k_i_ciphertext {
                warn!(
                    "peer {} says: invalid k_i detected from peer {}",
                    my_sign_id, peer_sign_id
                );
                faulters.set(peer_sign_id, ProtocolFault)?;
                continue;
            }

            // gamma_i
            let Gamma_i = ProjectivePoint::generator() * bcast_type5.gamma_i.as_ref();
            if &Gamma_i != self.r4bcasts.get(peer_sign_id)?.Gamma_i.as_ref() {
                warn!(
                    "peer {} says: invalid Gamma_i detected from peer {}",
                    my_sign_id, peer_sign_id
                );
                faulters.set(peer_sign_id, ProtocolFault)?;
                continue;
            }

            // beta_ij, alpha_ij
            for (receiver_sign_id, peer_mta_plaintext) in peer_mta_plaintexts {
                let receiver_keygen_id = *self.all_keygen_ids.get(receiver_sign_id)?;

                // beta_ij
                let receiver_ek = self
                    .secret_key_share
                    .group()
                    .all_shares()
                    .get(receiver_keygen_id)?
                    .ek();
                let receiver_k_i_ciphertext = &self.r1bcasts.get(receiver_sign_id)?.k_i_ciphertext;
                let receiver_alpha_ciphertext = &self
                    .r2p2ps
                    .get(peer_sign_id, receiver_sign_id)?
                    .alpha_ciphertext;

                if !mta::verify_mta_response(
                    receiver_ek,
                    receiver_k_i_ciphertext,
                    bcast_type5.gamma_i.as_ref(),
                    receiver_alpha_ciphertext,
                    &peer_mta_plaintext.beta_secret,
                ) {
                    warn!(
                        "peer {} says: invalid beta from peer {} to victim peer {}",
                        my_sign_id, peer_sign_id, receiver_sign_id
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
                        .get(receiver_sign_id, peer_sign_id)?
                        .alpha_ciphertext
                {
                    warn!(
                        "peer {} says: invalid alpha from peer {} to victim peer {}",
                        my_sign_id, peer_sign_id, receiver_sign_id
                    );

                    faulters.set(peer_sign_id, ProtocolFault)?;
                    continue;
                }
            }
        }

        // sanity check
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
