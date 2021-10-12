use tracing::warn;

use crate::{
    collections::{zip2, FillVecMap, FullP2ps, P2ps, VecMap},
    crypto_tools::{paillier, zkp::schnorr},
    gg20::keygen::{
        r1, r2, r3, r4::sad::R4Sad, GroupPublicInfo, KeygenPartyShareCounts, KeygenShareId,
        SecretKeyShare, SharePublicInfo, ShareSecretInfo,
    },
    sdk::{
        api::{Fault::ProtocolFault, TofnResult},
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
    type Bcast = r3::BcastHappy;
    type P2p = r3::P2pSad;

    fn execute(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        bcasts_in: FillVecMap<Self::Index, Self::Bcast>,
        p2ps_in: P2ps<Self::Index, Self::P2p>,
    ) -> TofnResult<ProtocolBuilder<Self::FinalOutput, Self::Index>> {
        let my_keygen_id = info.my_id();
        let mut faulters = FillVecMap::with_size(info.total_share_count());

        // TODO boilerplate
        // anyone who sent both bcast and p2p is a faulter
        for (peer_keygen_id, bcast_option, p2ps_option) in zip2(&bcasts_in, &p2ps_in) {
            if bcast_option.is_some() && p2ps_option.is_some() {
                warn!(
                    "peer {} says: unexpected p2ps and bcast from peer {} in round 4 happy path",
                    my_keygen_id, peer_keygen_id
                );
                faulters.set(peer_keygen_id, ProtocolFault)?;
            }
        }
        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        // if anyone complained then move to sad path
        if p2ps_in.iter().any(|(_, p2ps_option)| p2ps_option.is_some()) {
            warn!(
                "peer {} says: received R4 complaints from others--move to sad path",
                my_keygen_id,
            );
            return Box::new(R4Sad {
                r1bcasts: self.r1bcasts,
                r2bcasts: self.r2bcasts,
                r2p2ps: self.r2p2ps,
            })
            .execute(info, bcasts_in, p2ps_in);
        }

        // happy path: everyone sent bcast---unwrap all bcasts
        let bcasts_in = bcasts_in.to_vecmap()?;

        // verify proofs
        for (peer_keygen_id, bcast) in bcasts_in.iter() {
            if !schnorr::verify(
                &schnorr::Statement {
                    prover_id: peer_keygen_id,
                    base: &k256::ProjectivePoint::generator(),
                    target: self.all_X_i.get(peer_keygen_id)?,
                },
                &bcast.x_i_proof,
            ) {
                log_fault_warn(my_keygen_id, peer_keygen_id, "bad DL proof");
                faulters.set(peer_keygen_id, ProtocolFault)?;
            }
        }
        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        // prepare data for final output
        let all_shares = self
            .r1bcasts
            .iter()
            .map(|(peer_keygen_id, r1bcast)| {
                Ok(SharePublicInfo::new(
                    self.all_X_i.get(peer_keygen_id)?.into(),
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
            ShareSecretInfo::new(my_keygen_id, self.dk, self.x_i.into()),
        ))))
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
