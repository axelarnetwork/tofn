use tracing::warn;

use crate::{
    collections::{FillVecMap, P2ps, VecMap},
    gg20::sign::{r2, SignShareId},
    sdk::{
        api::{
            Fault::{self, ProtocolFault},
            TofnResult,
        },
        implementer_api::ProtocolInfo,
    },
};

// sanity checking for message types used in all r3 paths
// legal message type combos:
// * happy: p2p only
// * sad: p2p only
// anyone who does not meet these conditions is set in `faulters`.
// if there are no faulters then return a VecMap of each peer's path
pub fn check_message_types(
    info: &ProtocolInfo<SignShareId>,
    bcasts_in: &FillVecMap<SignShareId, ()>,
    p2ps_in: &P2ps<SignShareId, r2::P2p>,
    faulters: &mut FillVecMap<SignShareId, Fault>,
) -> TofnResult<VecMap<SignShareId, R3Path>> {
    let my_sign_id = info.my_id();
    let mut paths = Vec::with_capacity(info.total_share_count());

    // anyone who sent a bcast is a faulter
    for (peer_sign_id, bcast) in bcasts_in.iter() {
        if bcast.is_some() {
            warn!(
                "peer {} says: unexpected bcast from peer {} in round 3",
                my_sign_id, peer_sign_id
            );
            faulters.set(peer_sign_id, ProtocolFault)?;
        }
    }
    // anyone who did not send p2ps is a faulter
    // anyone who sent conflicting p2ps is a faulter
    // anyone who sent zero sad path complaints is a faulter
    for (peer_sign_id, p2ps_option) in p2ps_in.iter() {
        if let Some(p2ps) = p2ps_option {
            if p2ps.iter().all(|(_, p2p)| matches!(p2p, r2::P2p::Happy(_))) {
                paths.push(R3Path::Happy);
            } else if p2ps.iter().all(|(_, p2p)| matches!(p2p, r2::P2p::Sad(_))) {
                if p2ps.iter().all(|(_, p2p)| match p2p {
                    r2::P2p::Happy(_) => true,
                    r2::P2p::Sad(p2p_sad) => !p2p_sad.zkp_complaint,
                }) {
                    warn!(
                        "peer {} says: peer {} sent zero complaints in round 3 sad path",
                        my_sign_id, peer_sign_id,
                    );
                    faulters.set(peer_sign_id, ProtocolFault)?;
                }
                paths.push(R3Path::Sad);
            } else {
                warn!(
                    "peer {} says: conflicting happy/sad p2ps from peer {} in round 3",
                    my_sign_id, peer_sign_id
                );
                faulters.set(peer_sign_id, ProtocolFault)?;
            }
        } else {
            warn!(
                "peer {} says: missing p2ps from peer {} in round 3",
                my_sign_id, peer_sign_id
            );
            faulters.set(peer_sign_id, ProtocolFault)?;
        }
    }
    debug_assert!(!faulters.is_empty() || paths.len() == info.total_share_count()); // sanity check
    Ok(VecMap::from_vec(paths))
}

pub enum R3Path {
    Happy,
    Sad,
}
