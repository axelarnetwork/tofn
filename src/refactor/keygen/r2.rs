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
pub(super) struct Bcast {
    pub(super) y_i_reveal: hash::Randomness,
    pub(super) u_i_vss_commit: vss_k256::Commit,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct P2p {
    pub(super) u_i_share_ciphertext: paillier_k256::Ciphertext,
}

pub(super) struct R2 {
    pub(super) threshold: usize,
    pub(super) dk: paillier_k256::DecryptionKey,
    pub(super) u_i_vss: vss_k256::Vss,
    pub(super) y_i_reveal: hash::Randomness,

    #[cfg(feature = "malicious")]
    pub(super) behaviour: Behaviour,
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

        // #[cfg(feature = "malicious")]
        // let my_u_i_shares_k256 = if let Behaviour::R2BadShare { victim } = self.behaviour {
        //     info!(
        //         "(k256) malicious party {} do {:?}",
        //         self.my_index, self.behaviour
        //     );
        //     my_u_i_shares_k256
        //         .iter()
        //         .enumerate()
        //         .map(|(i, s)| {
        //             if i == victim {
        //                 vss_k256::Share::from_scalar(
        //                     s.get_scalar() + k256::Scalar::one(),
        //                     s.get_index(),
        //                 )
        //             } else {
        //                 s.clone()
        //             }
        //         })
        //         .collect()
        // } else {
        //     my_u_i_shares_k256
        // };

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
