use crate::{
    collections::{FillVecMap, FullP2ps, P2ps, VecMap},
    gg20::{
        keygen::SecretKeyShare,
        sign::{
            r2, r4,
            r5::common::R5Path,
            type5_common::{self, type5_checks},
            KeygenShareIds,
        },
    },
    sdk::{
        api::{BytesVec, Fault::ProtocolFault, TofnFatal, TofnResult},
        implementer_api::{Executer, ProtocolBuilder, ProtocolInfo},
    },
};
use tracing::{error, warn};

use super::{
    super::{r1, r3, SignShareId},
    common::check_message_types,
};

#[allow(non_snake_case)]
pub(in super::super) struct R5Type5 {
    pub(in super::super) secret_key_share: SecretKeyShare,
    pub(in super::super) all_keygen_ids: KeygenShareIds,
    pub(in super::super) r1bcasts: VecMap<SignShareId, r1::Bcast>,
    pub(in super::super) r2p2ps: FullP2ps<SignShareId, r2::P2pHappy>,
    pub(in super::super) r3bcasts: VecMap<SignShareId, r3::BcastHappy>,
}

impl Executer for R5Type5 {
    type FinalOutput = BytesVec;
    type Index = SignShareId;
    type Bcast = r4::Bcast;
    type P2p = type5_common::P2pSadType5;

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

        // our check for type 5 failed, so anyone who claimed success is a faulter
        for (peer_sign_id, path) in paths.iter() {
            if matches!(path, R5Path::Happy) {
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

        // type-5 sad path: everyone is in R5Path::SadType5--unwrap bcast and p2p into expected types
        // TODO combine to_vecmap() and map2_result() into a new map2_to_vecmap_result method for FillVecMap?
        let bcasts_in = bcasts_in.to_vecmap()?;
        let bcasts_in = bcasts_in.map2_result(|(_, bcast)| {
            if let r4::Bcast::SadType5(h, s) = bcast {
                Ok((h, s))
            } else {
                Err(TofnFatal)
            }
        })?;
        let p2ps_in = p2ps_in.map_to_fullp2ps(|p2p| p2p.mta_plaintext)?;

        type5_checks(
            &mut faulters,
            my_sign_id,
            bcasts_in,
            p2ps_in,
            self.r1bcasts,
            self.r2p2ps,
            self.r3bcasts,
            self.all_keygen_ids,
            self.secret_key_share.group().all_shares(),
        )?;

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
