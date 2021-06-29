use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::{
    fillvec::FillVec,
    hash, paillier_k256,
    protocol::gg20::vss_k256,
    refactor::{
        keygen::{r3, Crime},
        protocol::executer::{
            serialize, serialize_as_option, ProtocolBuilder, ProtocolRoundBuilder,
            RoundExecuterTyped,
        },
    },
    vecmap::{Index, VecMap},
};

use super::{r1, KeygenOutput, KeygenPartyIndex, KeygenProtocolBuilder};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct OutMsg {
    pub(super) bcast: Bcast,
    pub(super) p2ps: FillVec<P2p>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct Bcast {
    pub(super) y_i_reveal: hash::Randomness,
    pub(super) u_i_share_commits: vss_k256::Commit,
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
}

impl RoundExecuterTyped for R2 {
    type FinalOutputTyped = KeygenOutput;
    type Index = KeygenPartyIndex;
    type Bcast = r1::Bcast;
    type P2p = ();

    fn execute_typed(
        self: Box<Self>,
        party_count: usize,
        index: usize,
        bcasts_in: VecMap<Self::Index, Self::Bcast>,
        _p2ps_in: Vec<FillVec<Self::P2p>>,
    ) -> KeygenProtocolBuilder {
        // check Paillier proofs
        // TODO `criminals` should have its own struct, something like VecMap<Vec<Crime>>
        let mut criminals = vec![Vec::new(); party_count];
        for (i, r1bcast) in bcasts_in.iter() {
            if !r1bcast.ek.verify(&r1bcast.ek_proof) {
                let crime = Crime::R2BadEncryptionKeyProof;
                warn!("party {} detect {:?} by {}", index, crime, i);
                criminals[i.as_usize()].push(crime);
            }
            if !r1bcast.zkp.verify(&r1bcast.zkp_proof) {
                let crime = Crime::R2BadZkSetupProof;
                warn!("party {} detect {:?} by {}", index, crime, i);
                criminals[i.as_usize()].push(crime);
            }
        }
        if !criminals.iter().all(Vec::is_empty) {
            return ProtocolBuilder::Done(Err(criminals));
        }

        let u_i_shares = self.u_i_vss.shares(party_count);

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

        // TODO better pattern to get p2ps_out
        let p2ps_out_bytes = Some(FillVec::from_vec(
            u_i_shares
                .iter()
                .enumerate()
                .map(|(i, u_i_share)| {
                    if i == index {
                        None
                    } else {
                        // encrypt the share for party i
                        let (u_i_share_ciphertext, _) = bcasts_in
                            .get(Index::from_usize(i))
                            .ek
                            .encrypt(&u_i_share.get_scalar().into());

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

                        let p2p = P2p {
                            u_i_share_ciphertext,
                        };
                        serialize_as_option(&p2p)
                    }
                })
                .collect(),
        ));

        let bcast_out = Some(serialize(&Bcast {
            y_i_reveal: self.y_i_reveal.clone(),
            u_i_share_commits: self.u_i_vss.commit(),
        }));

        ProtocolBuilder::NotDone(ProtocolRoundBuilder {
            round: Box::new(r3::R3 {
                threshold: self.threshold,
                dk: self.dk,
                u_i_my_share: u_i_shares[index].clone(),
                r1bcasts: bcasts_in.into_iter().map(|(_, x)| x).collect(), // TODO r1bcasts should be a VecMap
            }),
            bcast_out,
            p2ps_out: p2ps_out_bytes,
        })
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
