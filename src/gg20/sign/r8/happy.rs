use crate::{
    collections::{FillVecMap, VecMap, XP2ps},
    gg20::{crypto_tools::k256_serde, keygen::SecretKeyShare},
    sdk::{
        api::{BytesVec, Fault::ProtocolFault, TofnFatal, TofnResult},
        implementer_api::{Executer, ProtocolInfo, XProtocolBuilder},
    },
};
use ecdsa::hazmat::VerifyPrimitive;
use k256::{ecdsa::Signature, ProjectivePoint, Scalar};
use serde::{Deserialize, Serialize};
use tracing::{error, warn};

use super::super::{r5, r6, r7, SignShareId};

#[allow(non_snake_case)]
pub(in super::super) struct R8Happy {
    pub(in super::super) secret_key_share: SecretKeyShare,
    pub(in super::super) msg_to_sign: Scalar,
    pub(in super::super) R: ProjectivePoint,
    pub(in super::super) r: Scalar,
    pub(in super::super) r5bcasts: VecMap<SignShareId, r5::Bcast>,
    pub(in super::super) r6bcasts: VecMap<SignShareId, r6::BcastHappy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub(in super::super) struct Bcast {
    pub(in super::super) s_i: k256_serde::Scalar,
}

impl Executer for R8Happy {
    type FinalOutput = BytesVec;
    type Index = SignShareId;
    type Bcast = r7::Bcast;
    type P2p = ();

    #[allow(non_snake_case)]
    fn execute(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        bcasts_in: FillVecMap<Self::Index, Self::Bcast>,
        p2ps_in: XP2ps<Self::Index, Self::P2p>,
    ) -> TofnResult<XProtocolBuilder<Self::FinalOutput, Self::Index>> {
        let my_share_id = info.share_id();
        let mut faulters = FillVecMap::with_size(info.share_count());

        // anyone who did not send a bcast is a faulter
        for (share_id, bcast) in bcasts_in.iter() {
            if bcast.is_none() {
                warn!(
                    "peer {} says: missing bcast from peer {}",
                    my_share_id, share_id
                );
                faulters.set(share_id, ProtocolFault)?;
            }
        }
        // anyone who sent p2ps is a faulter
        for (share_id, p2ps) in p2ps_in.iter() {
            if p2ps.is_some() {
                warn!(
                    "peer {} says: unexpected p2ps from peer {}",
                    my_share_id, share_id
                );
                faulters.set(share_id, ProtocolFault)?;
            }
        }
        if !faulters.is_empty() {
            return Ok(XProtocolBuilder::Done(Err(faulters)));
        }

        let participants_count = info.share_count();

        // everyone sent their bcast/p2ps---unwrap all bcasts/p2ps
        let bcasts_in = bcasts_in.to_vecmap()?;

        let mut bcasts = FillVecMap::with_size(participants_count);

        // our check for 'type 7' error passed, so anyone who complained is a faulter
        for (sign_peer_id, bcast) in bcasts_in.into_iter() {
            match bcast {
                r7::Bcast::Happy(bcast) => {
                    bcasts.set(sign_peer_id, bcast)?;
                }
                r7::Bcast::SadType7(_) => {
                    warn!(
                        "peer {} says: peer {} broadcasted a 'type 7' failure",
                        my_share_id, sign_peer_id
                    );
                    faulters.set(sign_peer_id, ProtocolFault)?;
                }
            }
        }
        if !faulters.is_empty() {
            return Ok(XProtocolBuilder::Done(Err(faulters)));
        }

        let bcasts_in = bcasts.to_vecmap()?;

        // compute s = sum_i s_i
        let s = bcasts_in
            .iter()
            .fold(Scalar::zero(), |acc, (_, bcast)| acc + bcast.s_i.as_ref());

        let sig = {
            let mut sig = Signature::from_scalars(self.r, s).map_err(|_| {
                error!("scalars to signature conversion failed");
                TofnFatal
            })?;

            sig.normalize_s().map_err(|_| {
                error!("signature normalization failed");
                TofnFatal
            })?;

            sig
        };

        let pub_key = &self.secret_key_share.group().y().as_ref().to_affine();

        if pub_key.verify_prehashed(&self.msg_to_sign, &sig).is_ok() {
            // convert signature into ASN1/DER (Bitcoin) format
            let sig_bytes = sig.to_der().as_bytes().to_vec();

            return Ok(XProtocolBuilder::Done(Ok(sig_bytes)));
        }

        // verify proofs
        for (sign_peer_id, bcast) in &bcasts_in {
            let R_i = self.r5bcasts.get(sign_peer_id)?.R_i.as_ref();
            let S_i = self.r6bcasts.get(sign_peer_id)?.S_i.as_ref();

            let R_s = self.R * bcast.s_i.as_ref();
            let R_s_prime = R_i * &self.msg_to_sign + S_i * &self.r;

            if R_s != R_s_prime {
                warn!(
                    "peer {} says: 'type 8' fault detected for peer {}",
                    my_share_id, sign_peer_id
                );
                faulters.set(sign_peer_id, ProtocolFault)?;
            }
        }
        if !faulters.is_empty() {
            Ok(XProtocolBuilder::Done(Err(faulters)))
        } else {
            error!(
                "peer {} says: invalid signature detected but no faulters identified",
                my_share_id
            );
            Err(TofnFatal)
        }
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
