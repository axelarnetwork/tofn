use super::{crimes::Crime, Sign, Status};
use ecdsa::hazmat::VerifyPrimitive;
use k256::ecdsa::{DerSignature, Signature};
use tracing::{error, warn};

// round 8

pub(super) enum Output {
    Success { sig_k256: DerSignature },
    Fail { criminals: Vec<Vec<Crime>> },
}

impl Sign {
    pub(super) fn r8(&self) -> Output {
        assert!(matches!(self.status, Status::R7));
        let r7state = self.r7state.as_ref().unwrap();

        // compute s = sum_i s_i
        let s_k256 = self
            .in_r7bcasts
            .vec_ref()
            .iter()
            .map(|o| *o.as_ref().unwrap().s_i_k256.unwrap())
            .reduce(|acc, s_i| acc + s_i)
            .unwrap();

        // k256: if (r,s) is a valid ECDSA signature then we're done
        let sig_k256 = {
            let mut sig_k256 = Signature::from_scalars(r7state.r_k256, s_k256)
                .expect("fail to convert scalars to signature");
            sig_k256.normalize_s().expect("fail to normalize signature");
            sig_k256
        };
        let verifying_key_k256 = &self.my_secret_key_share.y_k256.unwrap().to_affine();
        if verifying_key_k256
            .verify_prehashed(&self.msg_to_sign_k256, &sig_k256)
            .is_ok()
        {
            // convert signature into ASN1/DER (Bitcoin) format
            return Output::Success {
                sig_k256: sig_k256.to_der(),
            };
        }

        // (r,s) is an invalid ECDSA signature => compute criminals
        // criminals fail Eq. (1) of https://eprint.iacr.org/2020/540.pdf
        // check: s_i*R =? m*R_i + r*S_i
        let mut criminals = vec![Vec::new(); self.participant_indices.len()];
        let r5state = self.r5state.as_ref().unwrap();
        for (i, criminal) in criminals.iter_mut().enumerate() {
            let in_r5bcast = self.in_r5bcasts.vec_ref()[i].as_ref().unwrap();
            let in_r6bcast = self.in_r6bcasts.vec_ref()[i].as_ref().unwrap();
            let in_r7bcast = self.in_r7bcasts.vec_ref()[i].as_ref().unwrap();

            let rhs_k256 = in_r5bcast.R_i_k256.unwrap() * &self.msg_to_sign_k256
                + in_r6bcast.S_i_k256.unwrap() * &r7state.r_k256;
            let lhs_k256 = r5state.R_k256 * in_r7bcast.s_i_k256.unwrap();
            if lhs_k256 != rhs_k256 {
                let crime = Crime::R8SICheckFail;
                warn!(
                    "(k256) participant {} detect {:?} by {}",
                    self.my_participant_index, crime, i
                );
                criminal.push(crime);
            }
        }

        if criminals.iter().all(Vec::is_empty) {
            error!("participant {} detect invalid signature but no criminals. proceeding to fail mode with zero criminals",
            self.my_participant_index);
        }

        Output::Fail { criminals }
    }
}
