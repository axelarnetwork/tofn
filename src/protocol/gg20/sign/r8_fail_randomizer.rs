use super::{Sign, Status};
use crate::{
    fillvec::FillVec,
    protocol::{CrimeType, Criminal},
};
use curv::elliptic::curves::traits::ECScalar;
// use curv::{elliptic::curves::traits::ECPoint, BigInt, FE, GE};
// use log::warn;
// use serde::{Deserialize, Serialize};
use tracing::warn;

impl Sign {
    // execute blame protocol from section 4.3 of https://eprint.iacr.org/2020/540.pdf
    pub(super) fn r8_fail_randomizer(&self) -> Vec<Criminal> {
        assert!(matches!(self.status, Status::R7FailRandomizer));
        assert!(self.in_r7bcasts_fail_randomizer.some_count() > 0);

        let mut criminals = FillVec::with_len(self.participant_indices.len());

        for (i, r7_participant_data) in self
            .in_r7bcasts_fail_randomizer
            .vec_ref()
            .iter()
            .enumerate()
        {
            if r7_participant_data.is_none() {
                // we took an extra round to ensure all other parties know to switch to blame mode
                // thus, any party that did not send abort data must be a criminal
                // TODO is that party a criminal even in case of timeout?
                warn!(
                    "participant {} says: participant {} failed to send R7FailRandomizer data",
                    self.my_participant_index, i
                );
                criminals.overwrite(
                    i,
                    Criminal {
                        index: i,
                        crime_type: CrimeType::Malicious,
                    },
                );
                continue;
            }
            let r7_participant_data = r7_participant_data.as_ref().unwrap();

            // verify correct computation of nonce_x_blind_summand (delta_i)
            // as per definition of delta_i in page 17 of https://eprint.iacr.org/2020/540.pdf doc version 20200511:155431
            let mut nonce_x_blind_summand = r7_participant_data
                .ecdsa_nonce_summand
                .mul(&r7_participant_data.secret_blind_summand.get_element()); // k_i * gamma_i
            for (j, mta_blind_summand) in r7_participant_data.mta_blind_summands.iter().enumerate()
            {
                if j == i {
                    continue;
                }
                let mta_blind_summand = mta_blind_summand.as_ref().unwrap_or_else(|| {
                    panic!(
                        // TODO these checks should be unnecessary after refactoring
                        "r8_fail_randomizer participant {} missing mta_blind_summand from {} for {}",
                        self.my_participant_index, i, j
                    )
                });
                nonce_x_blind_summand =
                    nonce_x_blind_summand + mta_blind_summand.lhs + mta_blind_summand.rhs;
                // alpha_ij + beta_ji
            }
            let in_r3bcast = self.in_r3bcasts.vec_ref()[i].as_ref().unwrap_or_else(|| {
                panic!(
                    // TODO these checks should be unnecessary after refactoring
                    "r8_fail_randomizer participant {} missing in_r3bcast from {}",
                    self.my_participant_index, i
                )
            });
            if nonce_x_blind_summand != in_r3bcast.nonce_x_blind_summand {
                warn!(
                    "participant {} detect bad nonce_x_blind_summand from {}",
                    self.my_participant_index, i
                );
                criminals.overwrite(
                    i,
                    Criminal {
                        index: i,
                        crime_type: CrimeType::Malicious,
                    },
                );
            }
        }

        criminals
            .into_vec()
            .into_iter()
            .filter_map(|opt| opt)
            .collect()
    }
}
