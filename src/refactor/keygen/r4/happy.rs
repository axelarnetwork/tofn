use tracing::warn;

use crate::{
    crypto_tools::{paillier, zkp::schnorr_k256},
    refactor::collections::{FillVecMap, P2ps, VecMap},
    refactor::{
        keygen::{
            r1, r2, r3, r4::sad::R4Sad, GroupPublicInfo, KeygenPartyIndex, KeygenPartyShareCounts,
            KeygenProtocolBuilder, SecretKeyShare, SharePublicInfo, ShareSecretInfo,
        },
        sdk::{
            api::{Fault::ProtocolFault, TofnResult},
            implementer_api::{bcast_only, log_fault_warn, ProtocolBuilder, ProtocolInfo},
        },
    },
};

#[cfg(feature = "malicious")]
use crate::refactor::keygen::malicious::Behaviour;

#[allow(non_snake_case)]
pub struct R4 {
    pub threshold: usize,
    pub party_share_counts: KeygenPartyShareCounts,
    pub dk: paillier::DecryptionKey,
    pub r1bcasts: VecMap<KeygenPartyIndex, r1::Bcast>,
    pub r2bcasts: VecMap<KeygenPartyIndex, r2::Bcast>,
    pub r2p2ps: P2ps<KeygenPartyIndex, r2::P2p>,
    pub y: k256::ProjectivePoint,
    pub x_i: k256::Scalar,
    pub all_X_i: VecMap<KeygenPartyIndex, k256::ProjectivePoint>,

    #[cfg(feature = "malicious")]
    pub behaviour: Behaviour,
}

impl bcast_only::Executer for R4 {
    type FinalOutput = SecretKeyShare;
    type Index = KeygenPartyIndex;
    type Bcast = r3::Bcast;

    #[allow(non_snake_case)]
    fn execute(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        bcasts_in: VecMap<Self::Index, Self::Bcast>,
    ) -> TofnResult<KeygenProtocolBuilder> {
        // move to sad path if necessary
        if bcasts_in
            .iter()
            .any(|(_, bcast)| matches!(bcast, r3::Bcast::Sad(_)))
        {
            warn!(
                "party {} r4 received complaints from others; move to sad path",
                info.share_id()
            );
            return Box::new(R4Sad {
                r1bcasts: self.r1bcasts,
                r2bcasts: self.r2bcasts,
                r2p2ps: self.r2p2ps,
            })
            .execute(info, bcasts_in);
        }

        // unwrap BcastHappy msgs
        let bcasts_in: VecMap<Self::Index, r3::BcastHappy> = bcasts_in
            .into_iter()
            .map(|(_, bcast)| match bcast {
                r3::Bcast::Happy(h) => h,
                r3::Bcast::Sad(_) => unreachable!(),
            })
            .collect();

        // verify proofs
        let mut faulters = FillVecMap::with_size(info.share_count());
        for (from, bcast) in bcasts_in.iter() {
            if schnorr_k256::verify(
                &schnorr_k256::Statement {
                    base: &k256::ProjectivePoint::generator(),
                    target: self.all_X_i.get(from)?,
                },
                &bcast.x_i_proof,
            )
            .is_err()
            {
                log_fault_warn(info.share_id(), from, "bad DL proof");
                faulters.set(from, ProtocolFault)?;
            }
        }
        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        // prepare data for final output
        let all_shares = self
            .r1bcasts
            .iter()
            .map(|(i, r1bcast)| {
                Ok(SharePublicInfo::new(
                    self.all_X_i.get(i)?.into(),
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
            ShareSecretInfo::new(info.share_id(), self.dk, self.x_i.into()),
        ))))
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
