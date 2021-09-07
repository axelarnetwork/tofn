use tracing::warn;

use crate::{
    collections::{zip2, FillVecMap, P2ps, VecMap},
    gg20::sign::{r7, SignShareId},
    sdk::{
        api::{
            Fault::{self, ProtocolFault},
            TofnResult,
        },
        implementer_api::ProtocolInfo,
    },
};

// validity check for message types used in all r8 paths
// legal message type combos:
// * happy: bcast only
// * type 7: bcast and p2p
// anyone who does not meet these conditions is set in `faulters`.
// if there are no faulters then return a VecMap of each peer's path
pub fn check_message_types(
    info: &ProtocolInfo<SignShareId>,
    bcasts_in: &FillVecMap<SignShareId, r7::Bcast>,
    p2ps_in: &P2ps<SignShareId, r7::P2p>,
    faulters: &mut FillVecMap<SignShareId, Fault>,
) -> TofnResult<VecMap<SignShareId, R8Path>> {
    let my_sign_id = info.my_id();
    let mut paths = Vec::with_capacity(info.total_share_count());

    // anyone who did not send bcast is a faulter
    // deduce path from bcast
    // anyone who sent p2ps in happy path is a faulter
    // anyone who did not send p2ps in type 7 path is a faulter
    for (peer_sign_id, bcast_option, p2ps_option) in zip2(bcasts_in, p2ps_in) {
        if let Some(bcast) = bcast_option {
            match bcast {
                r7::Bcast::Happy(_) => {
                    if p2ps_option.is_some() {
                        warn!(
                            "peer {} says: unexpected p2ps from peer {} in round 8 happy path",
                            my_sign_id, peer_sign_id,
                        );
                        faulters.set(peer_sign_id, ProtocolFault)?;
                    }
                    paths.push(R8Path::Happy);
                }
                r7::Bcast::SadType7(_) => {
                    if p2ps_option.is_none() {
                        warn!(
                            "peer {} says: mising p2ps from peer {} in round 8 type-7 sad path",
                            my_sign_id, peer_sign_id,
                        );
                        faulters.set(peer_sign_id, ProtocolFault)?;
                    }
                    paths.push(R8Path::Type7);
                }
            }
        } else {
            warn!(
                "peer {} says: missing bcast from peer {} in round 8",
                my_sign_id, peer_sign_id
            );
            faulters.set(peer_sign_id, ProtocolFault)?;
        }
    }

    debug_assert!(!faulters.is_empty() || paths.len() == info.total_share_count()); // sanity check
    Ok(VecMap::from_vec(paths))
}

pub enum R8Path {
    Happy,
    Type7,
}
