use tracing::warn;

use crate::{
    collections::{zip2, FillVecMap, P2ps, VecMap},
    gg20::sign::{r4, type5_common::P2pSadType5, SignShareId},
    sdk::{
        api::{
            Fault::{self, ProtocolFault},
            TofnResult,
        },
        implementer_api::ProtocolInfo,
    },
};

// validity checking for message types used in all r5 paths
// legal message type combos:
// * happy: bcast only
// * sad: bcast and p2p
// anyone who does not meet these conditions is set in `faulters`.
// if there are no faulters then return a VecMap of each peer's path
pub fn check_message_types(
    info: &ProtocolInfo<SignShareId>,
    bcasts_in: &FillVecMap<SignShareId, r4::Bcast>,
    p2ps_in: &P2ps<SignShareId, P2pSadType5>,
    faulters: &mut FillVecMap<SignShareId, Fault>,
) -> TofnResult<VecMap<SignShareId, R5Path>> {
    let my_sign_id = info.my_id();
    let mut paths = Vec::with_capacity(info.total_share_count());

    // anyone who did not send bcast is a faulter
    // deduce path from bcast
    // anyone who sent p2ps in happy path is a faulter
    // anyone who did not send p2ps in type 5 path is a faulter
    for (peer_sign_id, bcast_option, p2ps_option) in zip2(bcasts_in, p2ps_in) {
        if let Some(bcast) = bcast_option {
            match bcast {
                r4::Bcast::Happy(_) => {
                    if p2ps_option.is_some() {
                        warn!(
                            "peer {} says: unexpected p2ps from peer {} in round 5 happy path",
                            my_sign_id, peer_sign_id,
                        );
                        faulters.set(peer_sign_id, ProtocolFault)?;
                    }
                    paths.push(R5Path::Happy);
                }
                r4::Bcast::SadType5 { .. } => {
                    if p2ps_option.is_none() {
                        warn!(
                            "peer {} says: missing p2ps from peer {} in round 5 type-5 sad path",
                            my_sign_id, peer_sign_id,
                        );
                        faulters.set(peer_sign_id, ProtocolFault)?;
                    }
                    paths.push(R5Path::SadType5);
                }
            }
        } else {
            warn!(
                "peer {} says: missing bcast from peer {} in round 5",
                my_sign_id, peer_sign_id
            );
            faulters.set(peer_sign_id, ProtocolFault)?;
        }
    }

    debug_assert!(!faulters.is_empty() || paths.len() == info.total_share_count()); // sanity check
    Ok(VecMap::from_vec(paths))
}

pub enum R5Path {
    Happy,
    SadType5,
}
