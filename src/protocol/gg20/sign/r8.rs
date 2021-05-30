use super::{crimes::Crime, EcdsaSig, Sign, Status};
use k256::ecdsa::DerSignature;
use tracing::{error, warn};

// round 8

pub(super) enum Output {
    Success { sig: DerSignature },
    Fail { criminals: Vec<Vec<Crime>> },
}

impl Sign {
    pub(super) fn r8(&self) -> Output {
        assert!(matches!(self.status, Status::R7));
        let r7state = self.r7state.as_ref().unwrap();

        // compute s = sum of s_i (aka ecdsa_sig_summand) as per phase 7 of 2020/540
        let mut s = r7state.s_i;
        for (i, in_r7bcast) in self.in_r7bcasts.vec_ref().iter().enumerate() {
            if i == self.my_participant_index {
                continue;
            }
            let in_r7bcast = in_r7bcast.as_ref().unwrap();
            s = s + in_r7bcast.s_i;
        }

        // if (r,s) is a valid ECDSA signature then we're done
        let sig = EcdsaSig { r: r7state.r, s };
        if sig.verify(
            &self.my_secret_key_share.ecdsa_public_key,
            &self.msg_to_sign,
        ) {
            // convet signature into ASN1/DER (Bitcoin) format
            return Output::Success {
                sig: sig.to_k256().to_der(),
            };
        }

        // (r,s) is an invalid ECDSA signature => compute criminals
        // criminals fail Eq. (1) of https://eprint.iacr.org/2020/540.pdf
        let mut criminals = vec![Vec::new(); self.participant_indices.len()];
        let r5state = self.r5state.as_ref().unwrap();
        for (i, criminal) in criminals.iter_mut().enumerate() {
            let in_r5bcast = self.in_r5bcasts.vec_ref()[i].as_ref().unwrap();
            let in_r6bcast = self.in_r6bcasts.vec_ref()[i].as_ref().unwrap();
            let in_r7bcast = self.in_r7bcasts.vec_ref()[i].as_ref().unwrap();

            let r_i_m = in_r5bcast.R_i * self.msg_to_sign;
            let s_i_r = in_r6bcast.S_i * r7state.r;
            let rhs = r_i_m + s_i_r;

            let lhs = r5state.R * in_r7bcast.s_i;

            if lhs != rhs {
                let crime = Crime::R8BadSigSummand;
                warn!(
                    "participant {} detect {:?} by {}",
                    self.my_participant_index, crime, i
                );
                criminal.push(crime);
            }
        }

        if criminals.iter().map(|v| v.len()).sum::<usize>() == 0 {
            error!("participant {} detect invalid signature but no criminals. proceeding to fail mode with zero criminals",
            self.my_participant_index);
        }

        Output::Fail { criminals }
    }
}
