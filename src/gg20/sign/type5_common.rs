use k256::ProjectivePoint;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::{
    collections::{zip2, FillVecMap, FullP2ps, TypedUsize, VecMap},
    crypto_tools::{constants, hash, k256_serde, mta, paillier},
    gg20::keygen::{KeygenShareId, SharePublicInfo},
    sdk::api::{
        Fault::{self, ProtocolFault},
        TofnResult,
    },
};

use super::{r1, r2, r3, r4, SignShareId};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BcastSadType5 {
    pub(super) k_i: k256_serde::Scalar,
    pub(super) k_i_randomness: paillier::Randomness,
    pub(super) gamma_i: k256_serde::Scalar,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2pSadType5 {
    pub(super) mta_plaintext: MtaPlaintext,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtaPlaintext {
    // need alpha_plaintext instead of alpha
    // because alpha_plaintext may differ from alpha
    // why? because the ciphertext was formed from homomorphic Paillier operations, not just encrypting alpha
    pub(super) alpha_plaintext: paillier::Plaintext,
    pub(super) alpha_randomness: paillier::Randomness,
    pub(super) beta_secret: mta::Secret,
}

/// 'Type 5' sad path checks as described in section 4.2 of https://eprint.iacr.org/2020/540.pdf
/// Verify peer data is consistent with earlier messages:
/// * k_i
/// * gamma_i, Gamma_i
/// * beta_ij
/// * alpha_ij
/// Used in rounds 5 and 7
/// Anyone who fails these checks is set in `faulters`
#[allow(non_snake_case)]
#[allow(clippy::too_many_arguments)]
pub fn type5_checks(
    faulters: &mut FillVecMap<SignShareId, Fault>,
    my_sign_id: TypedUsize<SignShareId>,
    bcasts_in: VecMap<SignShareId, (r4::BcastHappy, BcastSadType5)>,
    p2ps_in: FullP2ps<SignShareId, MtaPlaintext>,
    all_r1_bcasts: VecMap<SignShareId, r1::Bcast>,
    all_r2_p2ps: FullP2ps<SignShareId, r2::P2pHappy>,
    all_r3_bcasts: VecMap<SignShareId, r3::BcastHappy>,
    all_keygen_ids: VecMap<SignShareId, TypedUsize<KeygenShareId>>,
    all_share_public_infos: &VecMap<KeygenShareId, SharePublicInfo>,
) -> TofnResult<()> {
    for (peer_sign_id, (bcast_happy, bcast_type5), peer_mta_plaintexts) in zip2(bcasts_in, p2ps_in)
    {
        let peer_keygen_id = *all_keygen_ids.get(peer_sign_id)?;
        let peer_ek = all_share_public_infos.get(peer_keygen_id)?.ek();

        // validate k_i_randomness
        if !peer_ek.validate_randomness(&bcast_type5.k_i_randomness) {
            warn!(
                "peer {} says: invalid k_i_randomness from peer {}",
                my_sign_id, peer_sign_id
            );
            faulters.set(peer_sign_id, ProtocolFault)?;
            continue;
        }

        // validate alpha_plaintext and alpha_randomness
        for (receiver_sign_id, mta_plaintext) in peer_mta_plaintexts.iter() {
            if !peer_ek.validate_plaintext(&mta_plaintext.alpha_plaintext) {
                warn!(
                    "peer {} says: invalid alpha_plaintext from peer {} to peer {}",
                    my_sign_id, peer_sign_id, receiver_sign_id
                );
                faulters.set(peer_sign_id, ProtocolFault)?;
                continue;
            }

            if !peer_ek.validate_randomness(&mta_plaintext.alpha_randomness) {
                warn!(
                    "peer {} says: invalid alpha_randomness from peer {} to peer {}",
                    my_sign_id, peer_sign_id, receiver_sign_id
                );
                faulters.set(peer_sign_id, ProtocolFault)?;
                continue;
            }
        }

        // verify correct computation of delta_i
        let delta_i = peer_mta_plaintexts.iter().fold(
            bcast_type5.k_i.as_ref() * bcast_type5.gamma_i.as_ref(),
            |acc, (_, mta_plaintext)| {
                acc + mta_plaintext.alpha_plaintext.to_scalar()
                    + mta_plaintext.beta_secret.beta.as_ref()
            },
        );

        if &delta_i != all_r3_bcasts.get(peer_sign_id)?.delta_i.as_ref() {
            warn!(
                "peer {} says: delta_i for peer {} does not match",
                my_sign_id, peer_sign_id
            );
            faulters.set(peer_sign_id, ProtocolFault)?;
            continue;
        }

        // k_i
        let k_i_ciphertext = peer_ek.encrypt_with_randomness(
            &(bcast_type5.k_i.as_ref()).into(),
            &bcast_type5.k_i_randomness,
        );
        if k_i_ciphertext != all_r1_bcasts.get(peer_sign_id)?.k_i_ciphertext {
            warn!(
                "peer {} says: invalid k_i detected from peer {}",
                my_sign_id, peer_sign_id
            );
            faulters.set(peer_sign_id, ProtocolFault)?;
            continue;
        }

        // gamma_i
        let Gamma_i = ProjectivePoint::generator() * bcast_type5.gamma_i.as_ref();
        if &Gamma_i != bcast_happy.Gamma_i.as_ref() {
            warn!(
                "peer {} says: inconsistent (gamma_i, Gamma_i) from peer {}",
                my_sign_id, peer_sign_id
            );
            faulters.set(peer_sign_id, ProtocolFault)?;
            continue;
        }

        // Gamma_i
        // This check is also done round 5 happy path.
        // If we're in round 5 sad type-5 path then we need to do it here, too.
        // If we're in round 7 sad type-5 path then this check is redundant, but do it anyway.
        let Gamma_i_commit = hash::commit_with_randomness(
            constants::GAMMA_I_COMMIT_TAG,
            peer_sign_id,
            bcast_happy.Gamma_i.to_bytes(),
            &bcast_happy.Gamma_i_reveal,
        );
        if Gamma_i_commit != all_r1_bcasts.get(peer_sign_id)?.Gamma_i_commit {
            warn!(
                "peer {} says: inconsistent (Gamma_i, Gamma_i_commit) from peer {}",
                my_sign_id, peer_sign_id
            );
            faulters.set(peer_sign_id, ProtocolFault)?;
            continue;
        }

        // beta_ij, alpha_ij
        for (receiver_sign_id, peer_mta_plaintext) in peer_mta_plaintexts {
            let receiver_keygen_id = *all_keygen_ids.get(receiver_sign_id)?;

            // beta_ij
            let receiver_ek = all_share_public_infos.get(receiver_keygen_id)?.ek();
            let receiver_k_i_ciphertext = &all_r1_bcasts.get(receiver_sign_id)?.k_i_ciphertext;
            let receiver_alpha_ciphertext = &all_r2_p2ps
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
                != all_r2_p2ps
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

    Ok(())
}
