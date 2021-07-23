use crate::{
    collections::{FillVecMap, TypedUsize, VecMap},
    gg20::{
        crypto_tools::{hash::Randomness, k256_serde, paillier},
        keygen::{KeygenPartyIndex, SecretKeyShare},
    },
    sdk::{
        api::{BytesVec, Fault::ProtocolFault, TofnFatal, TofnResult},
        implementer_api::{bcast_only, ProtocolBuilder, ProtocolInfo},
    },
};
use ecdsa::hazmat::VerifyPrimitive;
use k256::{ecdsa::Signature, ProjectivePoint, Scalar};
use serde::{Deserialize, Serialize};
use tracing::{error, warn};
use zeroize::Zeroize;

use super::super::{r1, r5, r6, r7, Peers, SignParticipantIndex, SignProtocolBuilder};

#[cfg(feature = "malicious")]
use super::super::malicious::Behaviour;

#[allow(non_snake_case)]
pub struct R8 {
    pub secret_key_share: SecretKeyShare,
    pub msg_to_sign: Scalar,
    pub peers: Peers,
    pub keygen_id: TypedUsize<KeygenPartyIndex>,
    pub gamma_i: Scalar,
    pub Gamma_i: ProjectivePoint,
    pub Gamma_i_reveal: Randomness,
    pub w_i: Scalar,
    pub k_i: Scalar,
    pub k_i_randomness: paillier::Randomness,
    pub sigma_i: Scalar,
    pub l_i: Scalar,
    pub T_i: ProjectivePoint,
    pub r1bcasts: VecMap<SignParticipantIndex, r1::Bcast>,
    pub delta_inv: Scalar,
    pub R: ProjectivePoint,
    pub r: Scalar,
    pub r5bcasts: VecMap<SignParticipantIndex, r5::Bcast>,
    pub r6bcasts: VecMap<SignParticipantIndex, r6::BcastHappy>,

    #[cfg(feature = "malicious")]
    pub behaviour: Behaviour,
}

// Zeroize the auxiliary secret information
impl Drop for R8 {
    fn drop(&mut self) {
        self.gamma_i.zeroize();
        self.k_i.zeroize();
        self.w_i.zeroize();
        self.sigma_i.zeroize();
        self.l_i.zeroize();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct Bcast {
    pub s_i: k256_serde::Scalar,
}

impl bcast_only::Executer for R8 {
    type FinalOutput = BytesVec;
    type Index = SignParticipantIndex;
    type Bcast = r7::happy::Bcast;

    #[allow(non_snake_case)]
    fn execute(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        bcasts_in: VecMap<Self::Index, Self::Bcast>,
    ) -> TofnResult<SignProtocolBuilder> {
        let sign_id = info.share_id();
        let participants_count = info.share_count();
        let mut faulters = FillVecMap::with_size(participants_count);

        let mut bcasts = FillVecMap::with_size(participants_count);

        // our check for 'type 7` error failed, so any peer broadcasting a success is a faulter
        for (sign_peer_id, bcast) in bcasts_in.into_iter() {
            match bcast {
                r7::happy::Bcast::Happy(bcast) => {
                    bcasts.set(sign_peer_id, bcast)?;
                }
                r7::happy::Bcast::Sad(_) => {
                    warn!(
                        "peer {} says: peer {} broadcasted a 'type 7' failure",
                        sign_id, sign_peer_id
                    );
                    faulters.set(sign_peer_id, ProtocolFault)?;
                }
            }
        }

        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        let bcasts_in = bcasts.unwrap_all()?;

        // compute s = sum_i s_i
        let s = bcasts_in
            .iter()
            .fold(Scalar::zero(), |acc, (_, bcast)| acc + bcast.s_i.unwrap());

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

        let pub_key = &self.secret_key_share.group().y().unwrap().to_affine();

        if pub_key.verify_prehashed(&self.msg_to_sign, &sig).is_ok() {
            // convert signature into ASN1/DER (Bitcoin) format
            let sig_bytes = sig.to_der().as_bytes().to_vec();

            return Ok(ProtocolBuilder::Done(Ok(sig_bytes)));
        }

        // verify proofs
        for (sign_peer_id, bcast) in &bcasts_in {
            let R_i = self.r5bcasts.get(sign_peer_id)?.R_i.unwrap();
            let S_i = self.r6bcasts.get(sign_peer_id)?.S_i.unwrap();

            let R_s = self.R * bcast.s_i.unwrap();
            let R_s_prime = R_i * &self.msg_to_sign + S_i * &self.r;

            if R_s != R_s_prime {
                warn!(
                    "peer {} says: 'type 8' fault detected for peer {}",
                    sign_id, sign_peer_id
                );

                faulters.set(sign_peer_id, ProtocolFault)?;
            }
        }

        if !faulters.is_empty() {
            Ok(ProtocolBuilder::Done(Err(faulters)))
        } else {
            error!(
                "peer {} says: invalid signature detected but no faulters identified",
                sign_id
            );
            Err(TofnFatal)
        }
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
