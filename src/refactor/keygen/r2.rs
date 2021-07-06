use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::{
    hash, paillier_k256,
    protocol::gg20::vss_k256,
    refactor::{
        keygen::{r3, Fault},
        protocol::{
            executer::{serialize, ProtocolBuilder, ProtocolRoundBuilder, RoundExecuter},
            P2ps,
        },
    },
    vecmap::{Index, Pair, VecMap},
};

use super::{r1, KeygenOutput, KeygenPartyIndex, KeygenProtocolBuilder};

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

impl RoundExecuter for R2 {
    type FinalOutput = KeygenOutput;
    type Index = KeygenPartyIndex;
    type Bcast = r1::Bcast;
    type P2p = ();

    fn execute(
        self: Box<Self>,
        party_count: usize,
        index: Index<Self::Index>,
        bcasts_in: VecMap<Self::Index, Self::Bcast>,
        _p2ps_in: P2ps<Self::Index, Self::P2p>,
    ) -> KeygenProtocolBuilder {
        // check Paillier proofs
        let faulters_ek: Vec<_> = bcasts_in
            .iter()
            .filter_map(|(i, bcast)| {
                if !bcast.ek.verify(&bcast.ek_proof) {
                    let fault = Fault::R2BadEncryptionKeyProof;
                    warn!("party {} detect {:?} by {}", index, fault, i);
                    Some((i, fault))
                } else {
                    None
                }
            })
            .collect();
        if !faulters_ek.is_empty() {
            return ProtocolBuilder::Done(Err(faulters_ek));
        }
        let faulters_zkp: Vec<_> = bcasts_in
            .iter()
            .filter_map(|(i, bcast)| {
                if !bcast.zkp.verify(&bcast.zkp_proof) {
                    let fault = Fault::R2BadZkSetupProof;
                    warn!("party {} detect {:?} by {}", index, fault, i);
                    Some((i, fault))
                } else {
                    None
                }
            })
            .collect();
        if !faulters_zkp.is_empty() {
            return ProtocolBuilder::Done(Err(faulters_zkp));
        }

        let (u_i_other_shares, u_i_my_share) =
            VecMap::from_vec(self.u_i_vss.shares(party_count)).puncture_hole(index);

        let u_i_other_shares = self.corrupt_share(index, u_i_other_shares);

        let p2ps_out = Some(
            u_i_other_shares
                .into_iter()
                .map(|(i, share)| {
                    // encrypt the share for party i
                    let (u_i_share_ciphertext, _) =
                        bcasts_in.get(i).ek.encrypt(&share.get_scalar().into());

                    // #[cfg(feature = "malicious")]
                    // let u_i_share_ciphertext_k256 = match self.behaviour {
                    //     Behaviour::R2BadEncryption { victim } if victim == i => {
                    //         info!(
                    //             "(k256) malicious party {} do {:?}",
                    //             self.my_index, self.behaviour
                    //         );
                    //         u_i_share_ciphertext_k256.corrupt()
                    //     }
                    //     _ => u_i_share_ciphertext_k256,
                    // };

                    Pair(
                        i,
                        serialize(&P2p {
                            u_i_share_ciphertext,
                        }),
                    )
                })
                .collect(),
        );

        let bcast_out = Some(serialize(&Bcast {
            y_i_reveal: self.y_i_reveal.clone(),
            u_i_vss_commit: self.u_i_vss.commit(),
        }));

        ProtocolBuilder::NotDone(ProtocolRoundBuilder {
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
        })
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

pub mod malicious {
    use tracing::info;

    use crate::{
        protocol::gg20::vss_k256::Share,
        refactor::keygen::{self, KeygenPartyIndex},
        vecmap::{HoleVecMap, Index},
    };

    use super::R2;

    impl R2 {
        pub fn corrupt_share(
            &self,
            index: Index<KeygenPartyIndex>,
            mut other_shares: HoleVecMap<KeygenPartyIndex, Share>,
        ) -> HoleVecMap<KeygenPartyIndex, Share> {
            #[cfg(feature = "malicious")]
            if let keygen::Behaviour::R2BadShare { victim } = self.behaviour {
                info!("malicious party {} do {:?}", index, self.behaviour);
                other_shares.get_mut(victim).corrupt();
            }

            other_shares
        }
    }
}
