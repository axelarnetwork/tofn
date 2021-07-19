use crate::{
    hash::Randomness,
    k256_serde, paillier_k256,
    refactor::{
        collections::{FillVecMap, TypedUsize, VecMap},
        keygen::{KeygenPartyIndex, SecretKeyShare},
        protocol::{
            api::{BytesVec, Fault::ProtocolFault, TofnResult},
            bcast_only,
            implementer_api::ProtocolBuilder,
        },
    },
};
use ecdsa::hazmat::VerifyPrimitive;
use k256::{ecdsa::Signature, ProjectivePoint, Scalar};
use serde::{Deserialize, Serialize};
use tracing::{error, warn};

use super::{r1, r5, r6, r7, Peers, SignParticipantIndex, SignProtocolBuilder};

#[cfg(feature = "malicious")]
use super::malicious::Behaviour;

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
    pub k_i_randomness: paillier_k256::Randomness,
    pub sigma_i: Scalar,
    pub l_i: Scalar,
    pub T_i: ProjectivePoint,
    pub r1bcasts: VecMap<SignParticipantIndex, r1::Bcast>,
    pub delta_inv: Scalar,
    pub R: ProjectivePoint,
    pub r: Scalar,
    pub r5bcasts: VecMap<SignParticipantIndex, r5::Bcast>,
    pub r6bcasts: VecMap<SignParticipantIndex, r6::Bcast>,

    #[cfg(feature = "malicious")]
    pub behaviour: Behaviour,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct Bcast {
    pub s_i: k256_serde::Scalar,
}

impl bcast_only::Executer for R8 {
    type FinalOutput = BytesVec;
    type Index = SignParticipantIndex;
    type Bcast = r7::Bcast;

    #[allow(non_snake_case)]
    fn execute(
        self: Box<Self>,
        participants_count: usize,
        sign_id: TypedUsize<Self::Index>,
        bcasts_in: VecMap<Self::Index, Self::Bcast>,
    ) -> TofnResult<SignProtocolBuilder> {
        let mut faulters = FillVecMap::with_size(participants_count);

        // compute s = sum_i s_i
        let s = bcasts_in
            .iter()
            .fold(Scalar::zero(), |acc, (_, bcast)| acc + bcast.s_i.unwrap());

        let sig = {
            let mut sig = Signature::from_scalars(self.r, s).map_err(|_| {
                error!("scalars to signature conversion failed");
            })?;

            sig.normalize_s().map_err(|_| {
                error!("signature normalization failed");
            })?;

            sig
        };

        let pub_key = &self.secret_key_share.group.y.unwrap().to_affine();

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
            Err(())
        }
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
