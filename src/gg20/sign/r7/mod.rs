use serde::{Deserialize, Serialize};
use tracing::{error, warn};

use crate::{
    collections::{zip2, FillVecMap, HoleVecMap, P2ps, VecMap},
    gg20::crypto_tools::{k256_serde, paillier, zkp::chaum_pedersen},
    sdk::{
        api::{
            Fault::{self, ProtocolFault},
            TofnFatal, TofnResult,
        },
        implementer_api::ProtocolInfo,
    },
};

use super::{r6, SignShareId};

mod happy;
pub(super) use happy::R7Happy;
mod sad;
pub(super) use sad::R7Sad;
mod type5;
pub(super) use type5::R7Type5;

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) enum Bcast {
    Happy(BcastHappy),
    SadType7(BcastSadType7),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub(super) struct BcastHappy {
    pub s_i: k256_serde::Scalar,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct BcastSadType7 {
    pub(super) k_i: k256_serde::Scalar,
    pub(super) k_i_randomness: paillier::Randomness,
    pub(super) proof: chaum_pedersen::Proof,
    pub(super) mta_wc_plaintexts: HoleVecMap<SignShareId, MtaWcPlaintext>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct MtaWcPlaintext {
    // mu_plaintext instead of mu
    // because mu_plaintext may differ from mu
    // why? because the ciphertext was formed from homomorphic Paillier operations, not just encrypting mu
    pub(super) mu_plaintext: paillier::Plaintext,
    pub(super) mu_randomness: paillier::Randomness,
}

// sanity checking for message types used in all r7 paths
// legal message type combos:
// * happy: bcast only
// * sad: p2p only
// * type 5: bcast and p2p
// anyone who does not meet these conditions is set in `faulters`.
// if there are no faulters then return a VecMap of each peer's path
fn check_message_types(
    info: &ProtocolInfo<SignShareId>,
    bcasts_in: &FillVecMap<SignShareId, r6::Bcast>,
    p2ps_in: &P2ps<SignShareId, r6::P2p>,
    faulters: &mut FillVecMap<SignShareId, Fault>,
) -> TofnResult<VecMap<SignShareId, R7Path>> {
    let my_sign_id = info.my_id();
    let mut paths = Vec::with_capacity(info.total_share_count());

    for (peer_sign_id, bcast_option, p2ps_option) in zip2(bcasts_in, p2ps_in) {
        match (bcast_option, p2ps_option) {
            (None, None) => {
                error!(
                    "peer {} says: unreachable: peer {} sent neither bcast nor p2ps",
                    my_sign_id, peer_sign_id
                );
                return Err(TofnFatal);
            }
            (None, Some(p2ps)) => {
                if p2ps.iter().any(|(_, p2p)| !matches!(p2p, r6::P2p::Sad(_))) {
                    warn!(
                        "peer {} says: peer {} sent a non-sad-path p2p without a bcast",
                        my_sign_id, peer_sign_id,
                    );
                    faulters.set(peer_sign_id, ProtocolFault)?;
                }
                paths.push(R7Path::Sad);
            }
            (Some(bcast), None) => {
                if !matches!(bcast, r6::Bcast::Happy(_)) {
                    warn!(
                        "peer {} says: peer {} sent a non-happy-path bcast without p2ps",
                        my_sign_id, peer_sign_id,
                    );
                    faulters.set(peer_sign_id, ProtocolFault)?;
                }
                paths.push(R7Path::Happy);
            }
            (Some(bcast), Some(p2ps)) => {
                if !matches!(bcast, r6::Bcast::SadType5(_))
                    || p2ps
                        .iter()
                        .any(|(_, p2p)| !matches!(p2p, r6::P2p::SadType5(_)))
                {
                    warn!(
                        "peer {} says: peer {} sent both bcast and p2ps but not all are sad-path-type5",
                        my_sign_id, peer_sign_id,
                    );
                    faulters.set(peer_sign_id, ProtocolFault)?;
                }
                paths.push(R7Path::SadType5);
            }
        }
    }
    debug_assert_eq!(paths.len(), info.total_share_count());
    Ok(VecMap::from_vec(paths))
}

enum R7Path {
    Happy,
    Sad,
    SadType5,
}
