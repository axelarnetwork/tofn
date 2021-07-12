use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::{
    hash, paillier_k256,
    protocol::gg20::{vss_k256, SecretKeyShare},
    refactor::{
        api::{Fault::ProtocolFault, TofnResult},
        implementer_api::{bcast_only, serialize, ProtocolBuilder, RoundBuilder},
        keygen::r3,
    },
    vecmap::{FillVecMap, TypedUsize, VecMap},
};

use super::{r1, KeygenPartyIndex, KeygenProtocolBuilder};

#[cfg(feature = "malicious")]
use super::malicious::Behaviour;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Bcast {
    pub y_i_reveal: hash::Randomness,
    pub u_i_vss_commit: vss_k256::Commit,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct P2p {
    pub u_i_share_ciphertext: paillier_k256::Ciphertext,
}

pub struct R2 {
    pub threshold: usize,
    pub dk: paillier_k256::DecryptionKey,
    pub u_i_vss: vss_k256::Vss,
    pub y_i_reveal: hash::Randomness,

    #[cfg(feature = "malicious")]
    pub behaviour: Behaviour,
}

impl bcast_only::Executer for R2 {
    type FinalOutput = SecretKeyShare;
    type Index = KeygenPartyIndex;
    type Bcast = r1::Bcast;

    fn execute(
        self: Box<Self>,
        party_count: usize,
        index: TypedUsize<Self::Index>,
        bcasts_in: VecMap<Self::Index, Self::Bcast>,
    ) -> TofnResult<KeygenProtocolBuilder> {
        let mut faulters = FillVecMap::with_size(party_count);

        // check Paillier proofs
        for (from, bcast) in bcasts_in.iter() {
            if !bcast.ek.verify(&bcast.ek_proof) {
                warn!("party {} detect bad ek proof by {}", index, from);
                faulters.set(from, ProtocolFault)?;
            }
            if !bcast.zkp.verify(&bcast.zkp_proof) {
                warn!("party {} detect bad zk setup proof by {}", index, from);
                faulters.set(from, ProtocolFault)?;
            }
        }
        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        let (u_i_other_shares, u_i_my_share) =
            VecMap::from_vec(self.u_i_vss.shares(party_count)).puncture_hole(index);

        let u_i_other_shares = self.corrupt_share(index, u_i_other_shares)?;

        let p2ps_out = u_i_other_shares.map2(|(i, share)| {
            // encrypt the share for party i
            let (u_i_share_ciphertext, _) =
                bcasts_in.get(i)?.ek.encrypt(&share.get_scalar().into());

            let u_i_share_ciphertext = self.corrupt_ciphertext(index, i, u_i_share_ciphertext);

            serialize(&P2p {
                u_i_share_ciphertext,
            })
        })?;

        let bcast_out = serialize(&Bcast {
            y_i_reveal: self.y_i_reveal.clone(),
            u_i_vss_commit: self.u_i_vss.commit(),
        })?;

        Ok(ProtocolBuilder::NotDone(RoundBuilder::BcastAndP2p {
            round: Box::new(r3::R3 {
                threshold: self.threshold,
                dk: self.dk,
                u_i_my_share,
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

pub mod malicious {
    #![allow(unused_variables)]
    #![allow(unused_mut)]
    use crate::{
        paillier_k256::Ciphertext,
        protocol::gg20::vss_k256::Share,
        refactor::{api::TofnResult, keygen::KeygenPartyIndex},
        vecmap::{HoleVecMap, TypedUsize},
    };

    use super::R2;

    #[cfg(feature = "malicious")]
    use crate::refactor::keygen;

    #[cfg(feature = "malicious")]
    use tracing::info;

    impl R2 {
        pub fn corrupt_share(
            &self,
            my_index: TypedUsize<KeygenPartyIndex>,
            mut other_shares: HoleVecMap<KeygenPartyIndex, Share>,
        ) -> TofnResult<HoleVecMap<KeygenPartyIndex, Share>> {
            #[cfg(feature = "malicious")]
            if let keygen::Behaviour::R2BadShare { victim } = self.behaviour {
                info!("malicious party {} do {:?}", my_index, self.behaviour);
                other_shares.get_mut(victim)?.corrupt();
            }

            Ok(other_shares)
        }

        pub fn corrupt_ciphertext(
            &self,
            my_index: TypedUsize<KeygenPartyIndex>,
            target_index: TypedUsize<KeygenPartyIndex>,
            mut ciphertext: Ciphertext,
        ) -> Ciphertext {
            #[cfg(feature = "malicious")]
            if let keygen::Behaviour::R2BadEncryption { victim } = self.behaviour {
                if victim == target_index {
                    info!("malicious party {} do {:?}", my_index, self.behaviour);
                    ciphertext.corrupt();
                }
            }

            ciphertext
        }
    }
}
