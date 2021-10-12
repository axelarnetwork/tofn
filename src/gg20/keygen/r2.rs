use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::{
    collections::{FillVecMap, P2ps, VecMap},
    crypto_tools::{hash, paillier, vss},
    gg20::keygen::{r3, SecretKeyShare},
    sdk::{
        api::{Fault::ProtocolFault, TofnResult},
        implementer_api::{serialize, Executer, ProtocolBuilder, ProtocolInfo, RoundBuilder},
    },
};

use super::{r1, KeygenPartyShareCounts, KeygenShareId};

#[cfg(feature = "malicious")]
use super::malicious::Behaviour;

/// TODO: The byte length of this struct is proportional to the threshold: 34t + 73
/// Instead it should be constant.
/// https://github.com/axelarnetwork/tofn/issues/171
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct Bcast {
    pub(super) y_i_reveal: hash::Randomness,
    pub(super) u_i_vss_commit: vss::Commit,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct P2p {
    pub(super) u_i_share_ciphertext: paillier::Ciphertext,
}

pub(super) struct R2 {
    pub(super) threshold: usize,
    pub(super) party_share_counts: KeygenPartyShareCounts,
    pub(super) dk: paillier::DecryptionKey,
    pub(super) u_i_vss: vss::Vss,
    pub(super) y_i_reveal: hash::Randomness,

    #[cfg(feature = "malicious")]
    pub behaviour: Behaviour,
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
        // TODO strictly speaking peer_keygen_id might be me so we should not use peer_?
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
        let bcasts_in = bcasts_in.to_vecmap()?;

        // check Paillier proofs
        for (peer_keygen_id, bcast) in bcasts_in.iter() {
            let peer_keygen_party_id = self.party_share_counts.share_to_party_id(peer_keygen_id)?;

            if !bcast
                .ek
                .verify_correctness(&bcast.ek_proof, &peer_keygen_party_id.to_bytes())
            {
                warn!(
                    "peer {} says: ek proof from peer {} failed to verify",
                    my_keygen_id, peer_keygen_id
                );

                faulters.set(peer_keygen_id, ProtocolFault)?;
                continue;
            }

            if !bcast
                .zkp
                .verify(&bcast.zkp_proof, &peer_keygen_party_id.to_bytes())
            {
                warn!(
                    "peer {} says: zk setup proof from peer {} failed to verify",
                    my_keygen_id, peer_keygen_id,
                );

                faulters.set(peer_keygen_id, ProtocolFault)?;
                continue;
            }
        }

        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        let (peer_u_i_shares, u_i_share) =
            VecMap::from_vec(self.u_i_vss.shares(info.total_share_count()))
                .puncture_hole(my_keygen_id)?;

        corrupt!(
            peer_u_i_shares,
            self.corrupt_share(my_keygen_id, peer_u_i_shares)?
        );

        let p2ps_out = Some(peer_u_i_shares.map2_result(|(peer_keygen_id, share)| {
            // encrypt the share for party i
            let (u_i_share_ciphertext, _) = bcasts_in
                .get(peer_keygen_id)?
                .ek
                .encrypt(&share.get_scalar().into());

            corrupt!(
                u_i_share_ciphertext,
                self.corrupt_ciphertext(my_keygen_id, peer_keygen_id, u_i_share_ciphertext)
            );

            serialize(&P2p {
                u_i_share_ciphertext,
            })
        })?);

        let bcast_out = Some(serialize(&Bcast {
            y_i_reveal: self.y_i_reveal.clone(),
            u_i_vss_commit: self.u_i_vss.commit(),
        })?);

        Ok(ProtocolBuilder::NotDone(RoundBuilder::new(
            Box::new(r3::R3 {
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
        )))
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
        crypto_tools::{paillier::Ciphertext, vss::Share},
        gg20::keygen::{malicious::Behaviour, KeygenShareId},
        sdk::api::TofnResult,
    };

    use super::R2;

    use tracing::info;

    impl R2 {
        pub fn corrupt_share(
            &self,
            my_keygen_id: TypedUsize<KeygenShareId>,
            mut peer_shares: HoleVecMap<KeygenShareId, Share>,
        ) -> TofnResult<HoleVecMap<KeygenShareId, Share>> {
            if let Behaviour::R2BadShare { victim } = self.behaviour {
                info!("malicious peer {} does {:?}", my_keygen_id, self.behaviour);
                peer_shares.get_mut(victim)?.corrupt();
            }

            Ok(peer_shares)
        }

        pub fn corrupt_ciphertext(
            &self,
            my_keygen_id: TypedUsize<KeygenShareId>,
            victim_keygen_id: TypedUsize<KeygenShareId>,
            mut ciphertext: Ciphertext,
        ) -> Ciphertext {
            if let Behaviour::R2BadEncryption { victim } = self.behaviour {
                if victim == victim_keygen_id {
                    info!("malicious peer {} does {:?}", my_keygen_id, self.behaviour);
                    ciphertext.corrupt();
                }
            }

            ciphertext
        }
    }
}
