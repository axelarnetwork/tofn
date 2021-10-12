use crate::{
    collections::{zip2, FillVecMap, FullP2ps, P2ps, TypedUsize, VecMap},
    crypto_tools::{k256_serde, vss, zkp::chaum_pedersen},
    gg20::{
        keygen::{KeygenShareId, SecretKeyShare},
        sign::{r2, r8::common::R8Path, KeygenShareIds},
    },
    sdk::{
        api::{BytesVec, Fault::ProtocolFault, TofnFatal, TofnResult},
        implementer_api::{Executer, ProtocolBuilder, ProtocolInfo},
    },
};
use k256::{ProjectivePoint, Scalar};
use serde::{Deserialize, Serialize};
use tracing::{error, warn};

use super::{
    super::{r1, r6, r7, Peers, SignShareId},
    common::check_message_types,
};

#[allow(non_snake_case)]
pub(in super::super) struct R8Type7 {
    pub(in super::super) secret_key_share: SecretKeyShare,
    pub(in super::super) peers: Peers,
    pub(in super::super) participants: KeygenShareIds,
    pub(in super::super) keygen_id: TypedUsize<KeygenShareId>,
    pub(in super::super) r1bcasts: VecMap<SignShareId, r1::Bcast>,
    pub(in super::super) r2p2ps: FullP2ps<SignShareId, r2::P2pHappy>,
    pub(in super::super) R: ProjectivePoint,
    pub(in super::super) r6bcasts: VecMap<SignShareId, r6::BcastHappy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub(in super::super) struct Bcast {
    pub(in super::super) s_i: k256_serde::Scalar,
}

impl Executer for R8Type7 {
    type FinalOutput = BytesVec;
    type Index = SignShareId;
    type Bcast = r7::Bcast;
    type P2p = r7::P2p;

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

        // our check for type 7 failed, so anyone who claimed success is a faulter
        for (peer_sign_id, path) in paths.iter() {
            if matches!(path, R8Path::Happy) {
                warn!(
                    "peer {} says: peer {} falsely claimed type 7 success",
                    my_sign_id, peer_sign_id
                );
                faulters.set(peer_sign_id, ProtocolFault)?;
            }
        }
        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        // type-7 sad path: everyone is in R8Path::Type7--unwrap bcast and p2p into expected types
        // TODO combine to_vecmap() and to_fullp2ps() into new map2_result methods?
        let bcasts_in = bcasts_in.to_vecmap()?;
        let bcasts_in = bcasts_in.map2_result(|(_, bcast)| {
            if let r7::Bcast::SadType7(t) = bcast {
                Ok(t)
            } else {
                Err(TofnFatal)
            }
        })?;
        let p2ps_in = p2ps_in.to_fullp2ps()?;

        // execute blame protocol from section 4.3 of https://eprint.iacr.org/2020/540.pdf
        // verify that each participant's data is consistent with earlier messages:
        // 1. ecdsa_nonce_summand (k_i)
        // 2. mta_wc_blind_summands.lhs (mu_ij)
        //
        // TODO this code for k_i faults is identical to that of r7_fail_type5
        // TODO maybe you can test this path by choosing fake k_i', w_i' such that k_i'*w_i' == k_i*w_i
        for (peer_sign_id, bcast, peer_p2ps) in zip2(&bcasts_in, &p2ps_in) {
            // verify R8 peer data is consistent with earlier messages:
            // 1. k_i
            let peer_keygen_id = *self.participants.get(peer_sign_id)?;

            let peer_ek = &self
                .secret_key_share
                .group()
                .all_shares()
                .get(peer_keygen_id)?
                .ek();

            // validate k_i_randomness
            if !peer_ek.validate_randomness(&bcast.k_i_randomness) {
                warn!(
                    "peer {} says: invalid k_i_randomness from peer {}",
                    my_sign_id, peer_sign_id
                );
                faulters.set(peer_sign_id, ProtocolFault)?;
                continue;
            }

            // validate mu_plaintext and mu_randomness
            for (receiver_sign_id, mta_plaintext) in peer_p2ps.iter() {
                if !peer_ek.validate_plaintext(&mta_plaintext.mu_plaintext) {
                    warn!(
                        "peer {} says: invalid mu_plaintext from peer {} to peer {}",
                        my_sign_id, peer_sign_id, receiver_sign_id
                    );
                    faulters.set(peer_sign_id, ProtocolFault)?;
                    continue;
                }

                if !peer_ek.validate_randomness(&mta_plaintext.mu_randomness) {
                    warn!(
                        "peer {} says: invalid mu_randomness from peer {} to peer {}",
                        my_sign_id, peer_sign_id, receiver_sign_id
                    );
                    faulters.set(peer_sign_id, ProtocolFault)?;
                    continue;
                }
            }

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

            // mu_ij
            for (receiver_sign_id, peer_mta_wc_plaintext) in peer_p2ps {
                let peer_mu_ciphertext = peer_ek.encrypt_with_randomness(
                    &peer_mta_wc_plaintext.mu_plaintext,
                    &peer_mta_wc_plaintext.mu_randomness,
                );
                if peer_mu_ciphertext
                    != self
                        .r2p2ps
                        .get(receiver_sign_id, peer_sign_id)?
                        .mu_ciphertext
                {
                    warn!(
                        "peer {} says: invalid mu from peer {} to victim peer {}",
                        my_sign_id, peer_sign_id, receiver_sign_id
                    );

                    faulters.set(peer_sign_id, ProtocolFault)?;
                    continue;
                }
            }
        }

        // compute ecdsa nonce k = sum_i k_i
        let k = bcasts_in
            .iter()
            .fold(Scalar::zero(), |acc, (_, bcast)| acc + bcast.k_i.as_ref());

        // verify zkps as per page 19 of https://eprint.iacr.org/2020/540.pdf doc version 20200511:155431
        for (peer_sign_id, bcast, peer_p2ps) in zip2(&bcasts_in, &p2ps_in) {
            // compute sigma_i * G as per the equation at the bottom of page 18 of
            // https://eprint.iacr.org/2020/540.pdf doc version 20200511:155431

            // BEWARE: there is a typo in the equation second from the bottom of page 18 of
            // https://eprint.iacr.org/2020/540.pdf doc version 20200511:155431
            // the subscripts of nu should be reversed: nu_ji -> nu_ij
            // So, mu_ij * G = (w_j * k_i) * G + (-nu_ij) * G
            // Substituting for nu_ji, the formula for sigma_i simplifies to the following:
            //   sigma_i = w_i * k + sum_{j!=i} (mu_ij - mu_ji)
            // thus we may compute sigma_i * G as follows:
            //   k * W_i + sum_{j!=i} (mu_ij - mu_ji) * G

            // compute sum_{j!=i} (mu_ij - mu_ji)
            let peer_mu_sum =
                peer_p2ps
                    .iter()
                    .try_fold(Scalar::zero(), |acc, (j, mta_wc_plaintext)| {
                        let mu_ij = mta_wc_plaintext.mu_plaintext.to_scalar();
                        let mu_ji = p2ps_in.get(j, peer_sign_id)?.mu_plaintext.to_scalar();

                        Ok(acc + (mu_ij - mu_ji))
                    })?;

            // compute W_i
            let peer_lambda_i_S = &vss::lagrange_coefficient(
                peer_sign_id.as_usize(),
                &self
                    .peers
                    .clone()
                    .plug_hole(self.keygen_id)
                    .iter()
                    .map(|(_, peer_keygen_id)| peer_keygen_id.as_usize())
                    .collect::<Vec<_>>(),
            )?;

            let peer_keygen_id = *self.participants.get(peer_sign_id)?;

            let peer_W_i = self
                .secret_key_share
                .group()
                .all_shares()
                .get(peer_keygen_id)?
                .X_i()
                .as_ref()
                * peer_lambda_i_S;

            // compute sigma_i * G
            let peer_g_sigma_i = peer_W_i * k + ProjectivePoint::generator() * peer_mu_sum;

            // verify zkp
            let peer_stmt = &chaum_pedersen::Statement {
                prover_id: peer_sign_id,
                base1: &k256::ProjectivePoint::generator(),
                base2: &self.R,
                target1: &peer_g_sigma_i, // sigma_i * G
                target2: self.r6bcasts.get(peer_sign_id)?.S_i.as_ref(), // sigma_i * R == S_i
            };

            if !chaum_pedersen::verify(peer_stmt, &bcast.proof) {
                warn!(
                    "peer {} says: chaum_pedersen proof from peer {} failed to verify",
                    my_sign_id, peer_sign_id,
                );
                faulters.set(peer_sign_id, ProtocolFault)?;
                continue;
            }
        }

        if faulters.is_empty() {
            error!(
                "peer {} says: No faulters found in 'type 7' failure protocol",
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
