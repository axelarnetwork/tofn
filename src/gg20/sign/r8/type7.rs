use crate::{
    collections::{FillVecMap, FullP2ps, P2ps, TypedUsize, VecMap},
    gg20::{
        crypto_tools::{k256_serde, vss, zkp::chaum_pedersen},
        keygen::{KeygenShareId, SecretKeyShare},
        sign::{r2, KeygenShareIds},
    },
    sdk::{
        api::{BytesVec, Fault::ProtocolFault, TofnFatal, TofnResult},
        implementer_api::{Executer, ProtocolBuilder, ProtocolInfo},
    },
};
use k256::{ProjectivePoint, Scalar};
use serde::{Deserialize, Serialize};
use tracing::{error, warn};

use super::super::{r1, r6, r7, Peers, SignShareId};

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
        for (share_id, bcast) in bcasts_in.iter() {
            if bcast.is_none() {
                warn!(
                    "peer {} says: missing bcast from peer {} in round 8 type-7 sad path",
                    my_sign_id, share_id
                );
                faulters.set(share_id, ProtocolFault)?;
            }
        }
        // anyone who sent p2ps is a faulter
        for (share_id, p2ps) in p2ps_in.iter() {
            if p2ps.is_some() {
                warn!(
                    "peer {} says: unexpected p2ps from peer {} in round 8 type-7 sad path",
                    my_sign_id, share_id
                );
                faulters.set(share_id, ProtocolFault)?;
            }
        }
        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        // everyone sent their bcast/p2ps---unwrap all bcasts/p2ps
        let bcasts_in = bcasts_in.to_vecmap()?;

        // execute blame protocol from section 4.3 of https://eprint.iacr.org/2020/540.pdf
        let mut faulters = info.new_fillvecmap();
        let mut bcasts_sad = info.new_fillvecmap();

        // any peer who did not detect 'type 7' is a faulter
        for (peer_sign_id, bcast) in bcasts_in.into_iter() {
            match bcast {
                r7::Bcast::SadType7(bcast_sad) => {
                    bcasts_sad.set(peer_sign_id, bcast_sad)?;
                }
                r7::Bcast::Happy(_) => {
                    warn!(
                        "peer {} detect failure to detect 'type 7' fault by peer {}",
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
        // 1. ecdsa_nonce_summand (k_i)
        // 2. mta_wc_blind_summands.lhs (mu_ij)
        //
        // TODO this code for k_i faults is identical to that of r7_fail_type5
        // TODO maybe you can test this path by choosing fake k_i', w_i' such that k_i'*w_i' == k_i*w_i
        for (peer_sign_id, bcast) in bcasts_in.iter() {
            let peer_mta_wc_plaintexts = &bcast.mta_wc_plaintexts;

            if peer_mta_wc_plaintexts.len() != self.peers.len() {
                warn!(
                    "peer {} says: peer {} sent {} MtAwc plaintexts, expected {}",
                    my_sign_id,
                    peer_sign_id,
                    peer_mta_wc_plaintexts.len(),
                    self.peers.len()
                );

                faulters.set(peer_sign_id, ProtocolFault)?;
                continue;
            }

            if peer_mta_wc_plaintexts.get_hole() != peer_sign_id {
                warn!(
                    "peer {} says: peer {} sent MtAwc plaintexts with an unexpected hole {}",
                    my_sign_id,
                    peer_sign_id,
                    peer_mta_wc_plaintexts.get_hole()
                );

                faulters.set(peer_sign_id, ProtocolFault)?;
                continue;
            }

            // verify R8 peer data is consistent with earlier messages:
            // 1. k_i
            let peer_keygen_id = *self.participants.get(peer_sign_id)?;

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

            // mu_ij
            for (receiver_sign_id, peer_mta_wc_plaintext) in peer_mta_wc_plaintexts {
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
        for (peer_sign_id, bcast) in &bcasts_in {
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
            let peer_mu_sum = bcast.mta_wc_plaintexts.iter().try_fold(
                Scalar::zero(),
                |acc, (j, mta_wc_plaintext)| {
                    let mu_ij = mta_wc_plaintext.mu_plaintext.to_scalar();
                    let mu_ji = bcasts_in
                        .get(j)?
                        .mta_wc_plaintexts
                        .get(peer_sign_id)?
                        .mu_plaintext
                        .to_scalar();

                    Ok(acc + (mu_ij - mu_ji))
                },
            )?;

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
