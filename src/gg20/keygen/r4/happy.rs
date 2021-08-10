use tracing::warn;

use crate::{
    collections::{FillVecMap, P2ps, VecMap},
    gg20::{
        crypto_tools::{paillier, zkp::schnorr},
        keygen::{
            r1, r2, r3, r4::sad::R4Sad, GroupPublicInfo, KeygenPartyShareCounts,
            KeygenProtocolBuilder, KeygenShareId, SecretKeyShare, SharePublicInfo, ShareSecretInfo,
        },
    },
    sdk::{
        api::{Fault::ProtocolFault, TofnFatal, TofnResult},
        implementer_api::{bcast_only, log_fault_warn, ProtocolBuilder, ProtocolInfo},
    },
};

#[cfg(feature = "malicious")]
use crate::gg20::keygen::malicious::Behaviour;

#[allow(non_snake_case)]
pub struct R4Happy {
    pub(crate) threshold: usize,
    pub(crate) party_share_counts: KeygenPartyShareCounts,
    pub(crate) dk: paillier::DecryptionKey,
    pub(crate) r1bcasts: VecMap<KeygenShareId, r1::Bcast>,
    pub(crate) r2bcasts: VecMap<KeygenShareId, r2::Bcast>,
    pub(crate) r2p2ps: P2ps<KeygenShareId, r2::P2p>,
    pub(crate) y: k256::ProjectivePoint,
    pub(crate) x_i: k256::Scalar,
    pub(crate) all_X_i: VecMap<KeygenShareId, k256::ProjectivePoint>,

    #[cfg(feature = "malicious")]
    pub behaviour: Behaviour,
}

impl bcast_only::Executer for R4Happy {
    type FinalOutput = SecretKeyShare;
    type Index = KeygenShareId;
    type Bcast = r3::Bcast;

    #[allow(non_snake_case)]
    fn execute(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        bcasts_in: VecMap<Self::Index, Self::Bcast>,
    ) -> TofnResult<KeygenProtocolBuilder> {
        let keygen_id = info.share_id();

        // move to sad path if necessary
        if bcasts_in
            .iter()
            .any(|(_, bcast)| matches!(bcast, r3::Bcast::Sad(_)))
        {
            warn!(
                "peer {} says: received R4 complaints from others",
                keygen_id
            );
            return Box::new(R4Sad {
                r1bcasts: self.r1bcasts,
                r2bcasts: self.r2bcasts,
                r2p2ps: self.r2p2ps,
            })
            .execute(info, bcasts_in);
        }

        // decode BcastHappy msgs
        let bcasts_in = bcasts_in.map2_result(|(_, bcast)| match bcast {
            r3::Bcast::Happy(h) => Ok(h),
            r3::Bcast::Sad(_) => Err(TofnFatal),
        })?;

        // verify proofs
        let mut faulters = FillVecMap::with_size(info.share_count());
        for (keygen_peer_id, bcast) in bcasts_in.iter() {
            if schnorr::verify(
                &schnorr::Statement {
                    base: &k256::ProjectivePoint::generator(),
                    target: self.all_X_i.get(keygen_peer_id)?,
                },
                &bcast.x_i_proof,
            )
            .is_err()
            {
                log_fault_warn(keygen_id, keygen_peer_id, "bad DL proof");

                faulters.set(keygen_peer_id, ProtocolFault)?;
            }
        }

        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        // prepare data for final output
        let all_shares = self
            .r1bcasts
            .iter()
            .map(|(keygen_peer_id, r1bcast)| {
                Ok(SharePublicInfo::new(
                    self.all_X_i.get(keygen_peer_id)?.into(),
                    r1bcast.ek.clone(),
                    r1bcast.zkp.clone(),
                ))
            })
            .collect::<TofnResult<VecMap<_, _>>>()?;

        Ok(ProtocolBuilder::Done(Ok(SecretKeyShare::new(
            GroupPublicInfo::new(
                self.party_share_counts,
                self.threshold,
                self.y.into(),
                all_shares,
            ),
            ShareSecretInfo::new(keygen_id, self.dk, self.x_i.into()),
        ))))
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
