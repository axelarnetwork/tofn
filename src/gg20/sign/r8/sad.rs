use crate::{
    collections::{FillVecMap, P2ps, TypedUsize, VecMap},
    gg20::{
        crypto_tools::{hash::Randomness, k256_serde, paillier, vss, zkp::chaum_pedersen_k256},
        keygen::{KeygenShareId, SecretKeyShare},
        sign::{r2, r3, r4, Participants},
    },
    sdk::{
        api::{BytesVec, Fault::ProtocolFault, TofnFatal, TofnResult},
        implementer_api::{bcast_only, ProtocolBuilder, ProtocolInfo},
    },
};
use k256::{ProjectivePoint, Scalar};
use serde::{Deserialize, Serialize};
use tracing::{error, warn};

use super::super::{r1, r5, r6, r7, Peers, SignProtocolBuilder, SignShareId};

#[cfg(feature = "malicious")]
use super::super::malicious::Behaviour;

#[allow(non_snake_case)]
pub struct R8 {
    pub secret_key_share: SecretKeyShare,
    pub msg_to_sign: Scalar,
    pub peers: Peers,
    pub participants: Participants,
    pub keygen_id: TypedUsize<KeygenShareId>,
    pub gamma_i: Scalar,
    pub Gamma_i: ProjectivePoint,
    pub Gamma_i_reveal: Randomness,
    pub w_i: Scalar,
    pub k_i: Scalar,
    pub k_i_randomness: paillier::Randomness,
    pub sigma_i: Scalar,
    pub l_i: Scalar,
    pub T_i: ProjectivePoint,
    pub r1bcasts: VecMap<SignShareId, r1::Bcast>,
    pub r2p2ps: P2ps<SignShareId, r2::P2pHappy>,
    pub r3bcasts: VecMap<SignShareId, r3::happy::BcastHappy>,
    pub r4bcasts: VecMap<SignShareId, r4::happy::Bcast>,
    pub delta_inv: Scalar,
    pub R: ProjectivePoint,
    pub r5bcasts: VecMap<SignShareId, r5::Bcast>,
    pub r6bcasts: VecMap<SignShareId, r6::BcastHappy>,

    #[cfg(feature = "malicious")]
    pub behaviour: Behaviour,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct Bcast {
    pub s_i: k256_serde::Scalar,
}

impl bcast_only::Executer for R8 {
    type FinalOutput = BytesVec;
    type Index = SignShareId;
    type Bcast = r7::Bcast;

    #[allow(non_snake_case)]
    fn execute(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        bcasts_in: VecMap<Self::Index, Self::Bcast>,
    ) -> TofnResult<SignProtocolBuilder> {
        let sign_id = info.share_id();
        let participants_count = info.share_count();

        // execute blame protocol from section 4.3 of https://eprint.iacr.org/2020/540.pdf
        let mut faulters = FillVecMap::with_size(participants_count);
        let mut bcasts_sad = FillVecMap::with_size(participants_count);

        // any peer who did not detect 'type 7' is a faulter
        for (sign_peer_id, bcast) in bcasts_in.into_iter() {
            match bcast {
                r7::Bcast::Sad(bcast_sad) => {
                    bcasts_sad.set(sign_peer_id, bcast_sad)?;
                }
                r7::Bcast::Happy(_) => {
                    warn!(
                        "peer {} detect failure to detect 'type 7' fault by peer {}",
                        sign_id, sign_peer_id
                    );
                    faulters.set(sign_peer_id, ProtocolFault)?;
                }
            }
        }
        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        let bcasts_in = bcasts_sad.unwrap_all()?;

        // verify that each participant's data is consistent with earlier messages:
        // 1. ecdsa_nonce_summand (k_i)
        // 2. mta_wc_blind_summands.lhs (mu_ij)
        //
        // TODO this code for k_i faults is identical to that of r7_fail_type5
        // TODO maybe you can test this path by choosing fake k_i', w_i' such that k_i'*w_i' == k_i*w_i
        for (sign_peer_id, bcast) in bcasts_in.iter() {
            let mta_wc_plaintexts = &bcast.mta_wc_plaintexts;

            if mta_wc_plaintexts.len() != self.peers.len() {
                warn!(
                    "peer {} says: peer {} sent {} MtA plaintexts, expected {}",
                    sign_id,
                    sign_peer_id,
                    mta_wc_plaintexts.len(),
                    self.peers.len()
                );
                faulters.set(sign_peer_id, ProtocolFault)?;
                continue;
            }

            // verify R8 peer data is consistent with earlier messages:
            // 1. k_i
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

            // mu_ij
            for (sign_party_id, mta_wc_plaintext) in mta_wc_plaintexts {
                let peer_mu_ciphertext = peer_ek.encrypt_with_randomness(
                    &mta_wc_plaintext.mu_plaintext,
                    &mta_wc_plaintext.mu_randomness,
                );
                if peer_mu_ciphertext != self.r2p2ps.get(sign_party_id, sign_peer_id)?.mu_ciphertext
                {
                    // TODO: Who's responsible for the failure here?
                    warn!(
                        "peer {} says: invalid mu from peer {} to victim peer {}",
                        sign_id, sign_peer_id, sign_party_id
                    );
                    faulters.set(sign_peer_id, ProtocolFault)?;
                    continue;
                }
            }
        }

        // compute ecdsa nonce k = sum_i k_i
        let k = bcasts_in
            .iter()
            .fold(Scalar::zero(), |acc, (_, bcast)| acc + bcast.k_i.unwrap());

        // verify zkps as per page 19 of https://eprint.iacr.org/2020/540.pdf doc version 20200511:155431
        for (sign_peer_id, bcast) in &bcasts_in {
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
                        .get(sign_peer_id)?
                        .mu_plaintext
                        .to_scalar();

                    Ok(acc + (mu_ij - mu_ji))
                },
            )?;

            // compute W_i
            let peer_lambda_i_S = &vss::lagrange_coefficient(
                sign_peer_id.as_usize(),
                &self
                    .peers
                    .clone()
                    .plug_hole(self.keygen_id)
                    .iter()
                    .map(|(_, keygen_peer_id)| keygen_peer_id.as_usize())
                    .collect::<Vec<_>>(),
            );

            let keygen_peer_id = *self.participants.get(sign_peer_id)?;

            let peer_W_i = self
                .secret_key_share
                .group()
                .all_shares()
                .get(keygen_peer_id)?
                .X_i()
                .unwrap()
                * peer_lambda_i_S;

            // compute sigma_i * G
            let peer_g_sigma_i = peer_W_i * k + ProjectivePoint::generator() * peer_mu_sum;

            // verify zkp
            let peer_stmt = &chaum_pedersen_k256::Statement {
                base1: &k256::ProjectivePoint::generator(),
                base2: &self.R,
                target1: &peer_g_sigma_i, // sigma_i * G
                target2: &self.r6bcasts.get(sign_peer_id)?.S_i.unwrap(), // sigma_i * R == S_i
            };

            if let Err(err) = chaum_pedersen_k256::verify(peer_stmt, &bcast.proof) {
                warn!(
                    "peer {} says: chaum_pedersen proof from peer {} failed to verify because [{}]",
                    sign_id, sign_peer_id, err
                );
                faulters.set(sign_peer_id, ProtocolFault)?;
                continue;
            }
        }

        if faulters.is_empty() {
            error!(
                "peer {} says: No faulters found in 'type 7' failure protocol",
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
