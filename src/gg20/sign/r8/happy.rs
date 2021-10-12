use crate::{
    collections::{FillVecMap, P2ps, VecMap},
    crypto_tools::k256_serde,
    gg20::{keygen::SecretKeyShare, sign::r8::common::R8Path},
    sdk::{
        api::{BytesVec, Fault::ProtocolFault, TofnFatal, TofnResult},
        implementer_api::{Executer, ProtocolBuilder, ProtocolInfo},
    },
};
use ecdsa::hazmat::VerifyPrimitive;
use k256::{ecdsa::Signature, ProjectivePoint, Scalar};
use serde::{Deserialize, Serialize};
use tracing::{error, warn};

use super::{
    super::{r5, r6, r7, SignShareId},
    common::check_message_types,
};

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
    type P2p = r7::P2p;

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

        // our check for type 7 succeeded, so anyone who claimed failure is a faulter
        for (peer_sign_id, path) in paths.iter() {
            if matches!(path, R8Path::Type7) {
                warn!(
                    "peer {} says: peer {} falsely claimed type 7 failure",
                    my_sign_id, peer_sign_id
                );
                faulters.set(peer_sign_id, ProtocolFault)?;
            }
        }
        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        // happy path: unwrap bcasts into Happy
        // TODO combine the next 2 lines into a new FillVecMap::map2_result method?
        let bcasts_in = bcasts_in.to_vecmap()?;
        let bcasts_in = bcasts_in.map2_result(|(_, bcast)| {
            if let r7::Bcast::Happy(h) = bcast {
                Ok(h)
            } else {
                Err(TofnFatal)
            }
        })?;

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

            return Ok(ProtocolBuilder::Done(Ok(sig_bytes)));
        }

        // verify proofs
        for (peer_sign_id, bcast) in &bcasts_in {
            let R_i = self.r5bcasts.get(peer_sign_id)?.R_i.as_ref();
            let S_i = self.r6bcasts.get(peer_sign_id)?.S_i.as_ref();

            let R_s = self.R * bcast.s_i.as_ref();
            let R_s_prime = R_i * &self.msg_to_sign + S_i * &self.r;

            if R_s != R_s_prime {
                warn!(
                    "peer {} says: 'type 8' fault detected for peer {}",
                    my_sign_id, peer_sign_id
                );
                faulters.set(peer_sign_id, ProtocolFault)?;
            }
        }
        if !faulters.is_empty() {
            Ok(ProtocolBuilder::Done(Err(faulters)))
        } else {
            error!(
                "peer {} says: invalid signature detected but no faulters identified",
                my_sign_id
            );
            Err(TofnFatal)
        }
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
