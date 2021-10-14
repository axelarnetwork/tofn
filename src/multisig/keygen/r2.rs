use tracing::warn;

use crate::{
    collections::{FillVecMap, P2ps},
    sdk::{
        api::{Fault::ProtocolFault, TofnResult},
        implementer_api::{Executer, ProtocolBuilder, ProtocolInfo},
    },
};

use super::{
    r1,
    secret_key_share::{GroupPublicInfo, SecretKeyShare, ShareSecretInfo},
    KeygenPartyShareCounts, KeygenShareId,
};

pub(super) struct R2 {
    pub(super) threshold: usize,
    pub(super) party_share_counts: KeygenPartyShareCounts,
    pub(super) signing_key: k256::Scalar,
}

impl Executer for R2 {
    type FinalOutput = SecretKeyShare;
    type Index = KeygenShareId;
    type Bcast = r1::Bcast;
    type P2p = ();

    fn execute(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        bcasts_in: FillVecMap<Self::Index, Self::Bcast>,
        p2ps_in: P2ps<Self::Index, Self::P2p>,
    ) -> TofnResult<ProtocolBuilder<Self::FinalOutput, Self::Index>> {
        let my_keygen_id = info.my_id();
        let mut faulters = FillVecMap::with_size(info.total_share_count());

        // anyone who did not send a bcast is a faulter
        for (peer_keygen_id, bcast) in bcasts_in.iter() {
            if bcast.is_none() {
                warn!(
                    "peer {} says: missing bcast from peer {} in round 2",
                    my_keygen_id, peer_keygen_id
                );
                faulters.set(peer_keygen_id, ProtocolFault)?;
            }
        }
        // anyone who sent p2ps is a faulter
        for (peer_keygen_id, p2ps) in p2ps_in.iter() {
            if p2ps.is_some() {
                warn!(
                    "peer {} says: unexpected p2ps from peer {} in round 2",
                    my_keygen_id, peer_keygen_id
                );
                faulters.set(peer_keygen_id, ProtocolFault)?;
            }
        }
        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        // everyone sent a bcast---unwrap all bcasts
        let all_verifying_keys = bcasts_in.map_to_vecmap(|bcast| bcast.verifying_key)?;

        Ok(ProtocolBuilder::Done(Ok(SecretKeyShare::new(
            GroupPublicInfo::new(self.party_share_counts, self.threshold, all_verifying_keys),
            ShareSecretInfo::new(my_keygen_id, self.signing_key.into()),
        ))))
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
