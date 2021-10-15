use crate::{
    collections::{zip2, FillVecMap, P2ps},
    multisig::keygen::SecretKeyShare,
    sdk::{
        api::{Fault::ProtocolFault, TofnFatal, TofnResult},
        implementer_api::{Executer, ProtocolBuilder, ProtocolInfo},
    },
};
use ecdsa::hazmat::VerifyPrimitive;
use tracing::{error, warn};

use super::{r1, KeygenShareIds, SignProtocolOutput, SignShareId, SignatureShare};

pub(super) struct R2 {
    pub(super) secret_key_share: SecretKeyShare,
    pub(super) msg_to_sign: k256::Scalar,
    pub(super) all_keygen_ids: KeygenShareIds,
}

impl Executer for R2 {
    type FinalOutput = SignProtocolOutput;
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
        let threshold = self.secret_key_share.group().threshold();
        let mut faulters = info.new_fillvecmap();
        let mut valid_signatures = Vec::with_capacity(threshold + 1);

        for (peer_sign_id, bcast_option, p2ps_option) in zip2(bcasts_in, p2ps_in) {
            // anyone who did not send a bcast is a faulter
            let signature = match bcast_option {
                Some(bcast) => bcast.signature,
                None => {
                    warn!(
                        "peer {} says: missing bcast from peer {} in round 2",
                        my_sign_id, peer_sign_id
                    );
                    faulters.set(peer_sign_id, ProtocolFault)?;
                    continue;
                }
            };

            // anyone who sent p2ps is a faulter
            if p2ps_option.is_some() {
                warn!(
                    "peer {} says: unexpected p2ps from peer {} in round 2",
                    my_sign_id, peer_sign_id
                );
                faulters.set(peer_sign_id, ProtocolFault)?;
                continue;
            }

            // verify signature
            let peer_keygen_id = *self.all_keygen_ids.get(peer_sign_id)?;
            let verifying_key = self
                .secret_key_share
                .group()
                .all_pubkeys()
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
                continue;
            }

            // store valid signature
            let (party_id, subshare_id) = self
                .secret_key_share
                .group()
                .party_share_counts()
                .share_to_party_subshare_ids(peer_keygen_id)?;

            valid_signatures.push(SignatureShare {
                signature_bytes: signature.to_bytes(),
                party_id,
                subshare_id,
            });

            // have we got enough valid sigs yet?
            if valid_signatures.len() > threshold {
                return Ok(ProtocolBuilder::Done(Ok(valid_signatures)));
            }
        }

        // not enough valid signatures => sad outcome
        warn!(
            "peer {} says: insufficient valid signatures {} to exceed threshold {}",
            my_sign_id,
            valid_signatures.len(),
            threshold
        );

        // sanity check
        if faulters.is_empty() {
            error!(
                "peer {} says: insufficient valid signatures but no faulters",
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
