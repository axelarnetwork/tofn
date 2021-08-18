use tracing::warn;

use crate::{
    collections::{FillVecMap, FullP2ps, P2ps, VecMap},
    gg20::{
        crypto_tools::{paillier, zkp::schnorr},
        keygen::{
            r1, r2, r3, r4::sad::R4Sad, GroupPublicInfo, KeygenPartyShareCounts, KeygenShareId,
            SecretKeyShare, SharePublicInfo, ShareSecretInfo,
        },
    },
    sdk::{
        api::{Fault::ProtocolFault, TofnFatal, TofnResult},
        implementer_api::{log_fault_warn, Executer, ProtocolBuilder, ProtocolInfo},
    },
};

#[allow(non_snake_case)]
pub(in super::super) struct R4Happy {
    pub(in super::super) threshold: usize,
    pub(in super::super) party_share_counts: KeygenPartyShareCounts,
    pub(in super::super) dk: paillier::DecryptionKey,
    pub(in super::super) r1bcasts: VecMap<KeygenShareId, r1::Bcast>,
    pub(in super::super) r2bcasts: VecMap<KeygenShareId, r2::Bcast>,
    pub(in super::super) r2p2ps: FullP2ps<KeygenShareId, r2::P2p>,
    pub(in super::super) y: k256::ProjectivePoint,
    pub(in super::super) x_i: k256::Scalar,
    pub(in super::super) all_X_i: VecMap<KeygenShareId, k256::ProjectivePoint>,
}

impl Executer for R4Happy {
    type FinalOutput = SecretKeyShare;
    type Index = KeygenShareId;
    type Bcast = r3::Bcast;
    type P2p = ();

    fn execute(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        bcasts_in: FillVecMap<Self::Index, Self::Bcast>,
        p2ps_in: P2ps<Self::Index, Self::P2p>,
    ) -> TofnResult<ProtocolBuilder<Self::FinalOutput, Self::Index>> {
        let keygen_id = info.share_id();
        let mut faulters = FillVecMap::with_size(info.share_count());

        // TODO boilerplate
        // anyone who did not send a bcast is a faulter
        for (keygen_peer_id, bcast) in bcasts_in.iter() {
            if bcast.is_none() {
                warn!(
                    "peer {} says: missing bcast from peer {}",
                    keygen_id, keygen_peer_id
                );
                faulters.set(keygen_peer_id, ProtocolFault)?;
            }
        }
        // anyone who sent p2ps is a faulter
        for (keygen_peer_id, p2ps) in p2ps_in.iter() {
            if p2ps.is_some() {
                warn!(
                    "peer {} says: unexpected p2ps from peer {}",
                    keygen_id, keygen_peer_id
                );
                faulters.set(keygen_peer_id, ProtocolFault)?;
            }
        }
        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        // move to sad path if necessary
        if bcasts_in
            .iter()
            .any(|(_, bcast_option)| matches!(bcast_option, Some(r3::Bcast::Sad(_))))
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
            .execute(info, bcasts_in, p2ps_in);
        }

        // TODO combine the next two lines in a new FillVecMap::map2_result method?
        // everyone sent a bcast---unwrap all bcasts
        let bcasts_in = bcasts_in.to_vecmap()?;

        // we are now in happy path, so there should only be BcastHappy msgs
        let bcasts_in = bcasts_in.map2_result(|(_, bcast)| match bcast {
            r3::Bcast::Happy(h) => Ok(h),
            r3::Bcast::Sad(_) => Err(TofnFatal),
        })?;

        // verify proofs
        for (keygen_peer_id, bcast) in bcasts_in.iter() {
            if !schnorr::verify(
                &schnorr::Statement {
                    prover_id: keygen_peer_id,
                    base: &k256::ProjectivePoint::generator(),
                    target: self.all_X_i.get(keygen_peer_id)?,
                },
                &bcast.x_i_proof,
            ) {
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
