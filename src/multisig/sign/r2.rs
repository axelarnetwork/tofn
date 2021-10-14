use crate::{
    collections::{FillVecMap, P2ps, VecMap},
    crypto_tools::k256_serde,
    multisig::keygen::SecretKeyShare,
    sdk::{
        api::{Fault::ProtocolFault, TofnResult},
        implementer_api::{Executer, ProtocolBuilder, ProtocolInfo},
    },
};
use ecdsa::hazmat::VerifyPrimitive;
use tracing::warn;

use super::{r1, KeygenShareIds, SignShareId};

// #[allow(non_snake_case)]
pub(super) struct R2 {
    pub(super) secret_key_share: SecretKeyShare,
    pub(super) msg_to_sign: k256::Scalar,
    pub(super) all_keygen_ids: KeygenShareIds,
}

impl Executer for R2 {
    type FinalOutput = VecMap<SignShareId, k256_serde::Signature>;
    type Index = SignShareId;
    type Bcast = r1::Bcast;
    type P2p = ();

    fn execute(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        bcasts_in: FillVecMap<Self::Index, Self::Bcast>,
        p2ps_in: P2ps<Self::Index, Self::P2p>,
    ) -> TofnResult<ProtocolBuilder<Self::FinalOutput, Self::Index>> {
        let my_sign_id = info.my_id();
        let mut faulters = info.new_fillvecmap();

        // TODO support robustness
        // anyone who did not send a bcast is a faulter
        for (peer_sign_id, bcast) in bcasts_in.iter() {
            if bcast.is_none() {
                warn!(
                    "peer {} says: missing bcast from peer {} in round 2",
                    my_sign_id, peer_sign_id
                );
                faulters.set(peer_sign_id, ProtocolFault)?;
            }
        }
        // anyone who sent p2ps is a faulter
        for (peer_sign_id, p2ps) in p2ps_in.iter() {
            if p2ps.is_some() {
                warn!(
                    "peer {} says: unexpected p2ps from peer {} in round 2",
                    my_sign_id, peer_sign_id
                );
                faulters.set(peer_sign_id, ProtocolFault)?;
            }
        }
        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        // everyone sent a bcast---unwrap all bcasts
        let all_signatures = bcasts_in.map_to_vecmap(|bcast| bcast.signature)?;

        // verify signatures
        for (peer_sign_id, signature) in all_signatures.iter() {
            let peer_keygen_id = *self.all_keygen_ids.get(peer_sign_id)?;
            let verifying_key = self
                .secret_key_share
                .group()
                .all_verifying_keys()
                .get(peer_keygen_id)?
                .as_ref()
                .to_affine();

            if verifying_key
                .verify_prehashed(&self.msg_to_sign, signature.as_ref())
                .is_err()
            {
                warn!(
                    "peer {} says: fail sig verify from peer {} in round 2",
                    my_sign_id, peer_sign_id
                );
                faulters.set(peer_sign_id, ProtocolFault)?;
            }
        }
        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        Ok(ProtocolBuilder::Done(Ok(all_signatures)))
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
