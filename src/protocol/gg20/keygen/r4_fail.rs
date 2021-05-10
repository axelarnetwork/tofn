use super::{crimes::Crime, Keygen, Status};
use crate::protocol::gg20::vss;
use tracing::{error, info};

impl Keygen {
    pub(super) fn r4_fail(&self) -> Vec<Vec<Crime>> {
        assert!(matches!(self.status, Status::R3Fail));
        assert!(self.in_r3bcasts_fail.some_count() > 0);

        let mut criminals = vec![Vec::new(); self.share_count];

        // TODO refactor copied code to iterate over (accuser, accused)
        // TODO clarify confusion: participant vs party indices
        for accuser in 0..self.share_count {
            if let Some(fail_bcast) = self.in_r3bcasts_fail.vec_ref()[accuser].as_ref() {
                for accused in fail_bcast.vss_failures.iter() {
                    if accuser == accused.criminal_index {
                        let crime = Crime::R4FailFalseAccusation { victim: accuser };
                        info!(
                            "participant {} detect {:?} by {} (self accusation)",
                            self.my_index, crime, accuser
                        );
                        criminals[accuser].push(crime);
                        continue;
                    }

                    // TODO verify encryption

                    let accused_share_commitments = &self.in_r2bcasts.vec_ref()
                        [accused.criminal_index]
                        .as_ref()
                        .unwrap()
                        .u_i_share_commitments;
                    let accuser_share = &self.in_all_r2p2ps[accused.criminal_index].vec_ref()
                        [accuser]
                        .as_ref()
                        .unwrap()
                        .u_i_share;
                    if vss::validate_share(accused_share_commitments, accuser_share, accuser)
                        .is_ok()
                    {
                        let crime = Crime::R4FailFalseAccusation {
                            victim: accused.criminal_index,
                        };
                        info!("party {} detect {:?} by {}", self.my_index, crime, accuser);
                        criminals[accuser].push(crime);
                    } else {
                        let crime = Crime::R4FailBadVss { victim: accuser };
                        info!(
                            "party {} detect {:?} by {}",
                            self.my_index, crime, accused.criminal_index,
                        );
                        criminals[accused.criminal_index].push(crime);
                    }
                }
            }
        }

        if criminals.iter().all(|c| c.is_empty()) {
            error!("party {} r4_fail found no criminals", self.my_index,);
        }
        criminals
    }
}
