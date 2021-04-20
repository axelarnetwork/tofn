use super::{EcdsaSig, Sign, Status};
use crate::protocol::{CrimeType, Criminal};
use k256::ecdsa::Asn1Signature;
use tracing::{error, warn};

// round 8

pub enum Output {
    Success { sig: Asn1Signature },
    Fail { criminals: Vec<Criminal> },
}

impl Sign {
    pub(super) fn r8(&self) -> Output {
        assert!(matches!(self.status, Status::R7));
        let r7state = self.r7state.as_ref().unwrap();

        // compute s = sum of s_i (aka ecdsa_sig_summand) as per phase 7 of 2020/540
        let mut s = r7state.my_ecdsa_sig_summand;
        for (i, in_r7bcast) in self.in_r7bcasts.vec_ref().iter().enumerate() {
            if i == self.my_participant_index {
                continue;
            }
            let in_r7bcast = in_r7bcast.as_ref().unwrap();
            s = s + in_r7bcast.ecdsa_sig_summand;
        }

        // if (r,s) is a valid ECDSA signature then we're done
        let sig = EcdsaSig { r: r7state.r, s };
        if sig.verify(
            &self.my_secret_key_share.ecdsa_public_key,
            &self.msg_to_sign,
        ) {
            // convet signature into ASN1/DER (Bitcoin) format
            return Output::Success {
                sig: sig.to_k256().to_asn1(),
            };
        }

        // (r,s) is an invalid ECDSA signature
        // compute a list of culprits
        // culprits fail Eq. (1) of https://eprint.iacr.org/2020/540.pdf
        let mut criminals = Vec::new();
        let r5state = self.r5state.as_ref().unwrap();
        for (i, participant_index) in self.participant_indices.iter().enumerate() {
            if i == self.my_participant_index {
                continue;
            }
            let in_r5bcast = self.in_r5bcasts.vec_ref()[i].as_ref().unwrap();
            let in_r6bcast = self.in_r6bcasts.vec_ref()[i].as_ref().unwrap();
            let in_r7bcast = self.in_r7bcasts.vec_ref()[i].as_ref().unwrap();

            let r_i_m = in_r5bcast.ecdsa_randomizer_x_nonce_summand * self.msg_to_sign;
            let s_i_r = in_r6bcast.ecdsa_public_key_check * r7state.r;
            let rhs = r_i_m + s_i_r;

            let lhs = r5state.ecdsa_randomizer * in_r7bcast.ecdsa_sig_summand;

            if lhs != rhs {
                warn!(
                    "party {} says: sig check failure for party {}",
                    self.my_secret_key_share.my_index, participant_index
                );
                criminals.push(Criminal {
                    index: i,
                    crime_type: CrimeType::Malicious,
                });
            }
        }

        if criminals.is_empty() {
            error!("party {} says: sig is invalid, yet all sig checks pass. proceeding to fail mode with zero culprits",
            self.my_secret_key_share.my_index);
        }

        Output::Fail { criminals }
    }
}
