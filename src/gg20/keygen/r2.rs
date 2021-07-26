use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::{
    collections::{FillVecMap, VecMap},
    corrupt,
    gg20::{
        crypto_tools::{hash, paillier, vss},
        keygen::{r3, SecretKeyShare},
    },
    sdk::{
        api::{Fault::ProtocolFault, TofnResult},
        implementer_api::{bcast_only, serialize, ProtocolBuilder, ProtocolInfo, RoundBuilder},
    },
};

use super::{r1, KeygenPartyShareCounts, KeygenProtocolBuilder, KeygenShareId};

#[cfg(feature = "malicious")]
use super::malicious::Behaviour;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Bcast {
    pub y_i_reveal: hash::Randomness,
    pub u_i_vss_commit: vss::Commit,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct P2p {
    pub u_i_share_ciphertext: paillier::Ciphertext,
}

pub struct R2 {
    pub(crate) threshold: usize,
    pub(crate) party_share_counts: KeygenPartyShareCounts,
    pub(crate) dk: paillier::DecryptionKey,
    pub(crate) u_i_vss: vss::Vss,
    pub(crate) y_i_reveal: hash::Randomness,

    #[cfg(feature = "malicious")]
    pub behaviour: Behaviour,
}

impl bcast_only::Executer for R2 {
    type FinalOutput = SecretKeyShare;
    type Index = KeygenShareId;
    type Bcast = r1::Bcast;

    fn execute(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        bcasts_in: VecMap<Self::Index, Self::Bcast>,
    ) -> TofnResult<KeygenProtocolBuilder> {
        let keygen_id = info.share_id();
        let mut faulters = FillVecMap::with_size(info.share_count());

        // check Paillier proofs
        for (keygen_peer_id, bcast) in bcasts_in.iter() {
            if !bcast.ek.verify(&bcast.ek_proof) {
                warn!(
                    "peer {} says: ek proof from peer {} failed to verify",
                    keygen_id, keygen_peer_id
                );

                faulters.set(keygen_peer_id, ProtocolFault)?;
                continue;
            }

            if !bcast.zkp.verify(&bcast.zkp_proof) {
                warn!(
                    "peer {} says: zk setup proof from peer {} failed to verify",
                    keygen_id, keygen_peer_id,
                );

                faulters.set(keygen_peer_id, ProtocolFault)?;
                continue;
            }
        }

        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        let (peer_u_i_shares, u_i_share) =
            VecMap::from_vec(self.u_i_vss.shares(info.share_count())).puncture_hole(keygen_id)?;

        corrupt!(
            peer_u_i_shares,
            self.corrupt_share(keygen_id, peer_u_i_shares)?
        );

        let p2ps_out = peer_u_i_shares.map2_result(|(keygen_peer_id, share)| {
            // encrypt the share for party i
            let (peer_u_i_share_ciphertext, _) = bcasts_in
                .get(keygen_peer_id)?
                .ek
                .encrypt(&share.get_scalar().into());

            corrupt!(
                peer_u_i_share_ciphertext,
                self.corrupt_ciphertext(keygen_id, keygen_peer_id, peer_u_i_share_ciphertext)
            );

            serialize(&P2p {
                u_i_share_ciphertext: peer_u_i_share_ciphertext,
            })
        })?;

        let bcast_out = serialize(&Bcast {
            y_i_reveal: self.y_i_reveal.clone(),
            u_i_vss_commit: self.u_i_vss.commit(),
        })?;

        Ok(ProtocolBuilder::NotDone(RoundBuilder::BcastAndP2p {
            round: Box::new(r3::R3 {
                threshold: self.threshold,
                party_share_counts: self.party_share_counts,
                dk: self.dk,
                u_i_share,
                r1bcasts: bcasts_in,
                #[cfg(feature = "malicious")]
                behaviour: self.behaviour,
            }),
            bcast_out,
            p2ps_out,
        }))
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(feature = "malicious")]
mod malicious {
    use crate::{
        collections::{HoleVecMap, TypedUsize},
        gg20::{
            crypto_tools::{paillier::Ciphertext, vss::Share},
            keygen::{malicious::Behaviour, KeygenShareId},
        },
        sdk::api::TofnResult,
    };

    use super::R2;

    use tracing::info;

    impl R2 {
        pub fn corrupt_share(
            &self,
            keygen_id: TypedUsize<KeygenShareId>,
            mut other_shares: HoleVecMap<KeygenShareId, Share>,
        ) -> TofnResult<HoleVecMap<KeygenShareId, Share>> {
            if let Behaviour::R2BadShare { victim } = self.behaviour {
                info!("malicious peer {} does {:?}", keygen_id, self.behaviour);
                other_shares.get_mut(victim)?.corrupt();
            }

            Ok(other_shares)
        }

        pub fn corrupt_ciphertext(
            &self,
            keygen_id: TypedUsize<KeygenShareId>,
            target_index: TypedUsize<KeygenShareId>,
            mut ciphertext: Ciphertext,
        ) -> Ciphertext {
            if let Behaviour::R2BadEncryption { victim } = self.behaviour {
                if victim == target_index {
                    info!("malicious peer {} does {:?}", keygen_id, self.behaviour);
                    ciphertext.corrupt();
                }
            }

            ciphertext
        }
    }
}
