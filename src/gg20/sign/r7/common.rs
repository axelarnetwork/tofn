use tracing::{error, warn};

use crate::{
    collections::{zip2, FillVecMap, P2ps, VecMap},
    gg20::sign::{r6, SignShareId},
    sdk::{
        api::{
            Fault::{self, ProtocolFault},
            TofnFatal, TofnResult,
        },
        implementer_api::ProtocolInfo,
    },
};

// sanity checking for message types used in all r7 paths
// legal message type combos:
// * happy: bcast only
// * sad: p2p only
// * type 5: bcast and p2p
// anyone who does not meet these conditions is set in `faulters`.
// if there are no faulters then return a VecMap of each peer's path
pub fn check_message_types(
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
                if p2ps.iter().all(|(_, p2p)| match p2p {
                    r6::P2p::Sad(p2p_sad) => !p2p_sad.zkp_complaint,
                    r6::P2p::SadType5(_) => true,
                }) {
                    warn!(
                        "peer {} says: peer {} sent zero complaints in sad path",
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

pub enum R7Path {
    Happy,
    Sad,
    SadType5,
}
