use crate::{
    collections::{zip2, FillVecMap, FullP2ps, P2ps, VecMap},
    gg20::{
        keygen::SecretKeyShare,
        sign::{
            r2, r4,
            r7::{
                self,
                common::{check_message_types, R7Path},
            },
            type5_common::type5_checks,
            KeygenShareIds,
        },
    },
    sdk::{
        api::{BytesVec, Fault::ProtocolFault, TofnFatal, TofnResult},
        implementer_api::{Executer, ProtocolBuilder, ProtocolInfo},
    },
};
use k256::ProjectivePoint;
use tracing::{error, warn};

use super::super::{r1, r3, r5, r6, SignShareId};

#[allow(non_snake_case)]
pub(in super::super) struct R7Type5 {
    pub(in super::super) secret_key_share: SecretKeyShare,
    pub(in super::super) all_keygen_ids: KeygenShareIds,
    pub(in super::super) r1bcasts: VecMap<SignShareId, r1::Bcast>,
    pub(in super::super) r2p2ps: FullP2ps<SignShareId, r2::P2pHappy>,
    pub(in super::super) r3bcasts: VecMap<SignShareId, r3::BcastHappy>,
    pub(in super::super) r4bcasts: VecMap<SignShareId, r4::BcastHappy>,
    pub(in super::super) R: ProjectivePoint,
    pub(in super::super) r5bcasts: VecMap<SignShareId, r5::Bcast>,
    pub(in super::super) r5p2ps: FullP2ps<SignShareId, r5::P2p>,
}

impl Executer for R7Type5 {
    type FinalOutput = BytesVec;
    type Index = SignShareId;
    type Bcast = r6::Bcast;
    type P2p = r6::P2p;

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

        // if anyone complained then move to sad path
        if paths.iter().any(|(_, path)| matches!(path, R7Path::Sad)) {
            warn!(
                "peer {} says: received an R6 complaint from others---switch path type-5 -> sad",
                my_sign_id,
            );
            return Box::new(r7::sad::R7Sad {
                secret_key_share: self.secret_key_share,
                all_keygen_ids: self.all_keygen_ids,
                r1bcasts: self.r1bcasts,
                R: self.R,
                r5bcasts: self.r5bcasts,
                r5p2ps: self.r5p2ps,
            })
            .execute(info, bcasts_in, p2ps_in);
        }

        // our check for type 5 failed, so anyone who claimed success is a faulter
        for (peer_sign_id, path) in paths.iter() {
            if matches!(path, R7Path::Happy) {
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

        // everyone is now in type-5 sad path: prepare bcasts_in, p2ps_in

        // prepare bcasts_in for the call to type5_checks()
        let bcasts_in = zip2(bcasts_in, self.r4bcasts)
            .map(|(_, bcast_option, happy)| {
                if let Some(Self::Bcast::SadType5(type5)) = bcast_option {
                    Ok((happy, type5))
                } else {
                    Err(TofnFatal)
                }
            })
            .collect::<TofnResult<_>>()?;

        // unwrap p2ps_in into expected type
        let p2ps_in = p2ps_in.to_fullp2ps()?;
        let p2ps_in = p2ps_in.map2_result(|(_, p2p)| {
            if let r6::P2p::SadType5(t) = p2p {
                Ok(t.mta_plaintext)
            } else {
                Err(TofnFatal)
            }
        })?;

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
