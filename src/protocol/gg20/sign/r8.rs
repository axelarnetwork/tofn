use super::{crimes::Crime, EcdsaSig, Sign, Status};
use ecdsa::hazmat::VerifyPrimitive;
use k256::ecdsa::{DerSignature, Signature};
use tracing::{debug, error, warn};

// round 8

pub(super) enum Output {
    Success {
        sig: DerSignature,
        sig_k256: DerSignature,
    },
    Fail {
        criminals: Vec<Vec<Crime>>,
    },
}

impl Sign {
    pub(super) fn r8(&self) -> Output {
        assert!(matches!(self.status, Status::R7));
        let r7state = self.r7state.as_ref().unwrap();

        // curv: compute s = sum_i s_i
        let mut s = r7state.s_i;
        for (i, in_r7bcast) in self.in_r7bcasts.vec_ref().iter().enumerate() {
            if i == self.my_participant_index {
                continue;
            }
            let in_r7bcast = in_r7bcast.as_ref().unwrap();
            s = s + in_r7bcast.s_i;
        }

        // k256: compute s = sum_i s_i
        let s_k256 = self
            .in_r7bcasts
            .vec_ref()
            .iter()
            .map(|o| *o.as_ref().unwrap().s_i_k256.unwrap())
            .reduce(|acc, s_i| acc + s_i)
            .unwrap();

        // curv: if (r,s) is a valid ECDSA signature then we're done
        let sig = EcdsaSig { r: r7state.r, s };
        let curv_success = sig.verify(
            &self.my_secret_key_share.ecdsa_public_key,
            &self.msg_to_sign,
        );

        // k256: if (r,s) is a valid ECDSA signature then we're done
        let sig_k256 = {
            let mut sig_k256 = Signature::from_scalars(r7state.r_k256, s_k256)
                .expect("fail to convert scalars to signature");
            sig_k256.normalize_s().expect("fail to normalize signature");
            sig_k256
        };
        let verifying_key_k256 = &self.my_secret_key_share.y_k256.unwrap().to_affine();
        let k256_success = verifying_key_k256
            .verify_prehashed(&self.msg_to_sign_k256, &sig_k256)
            .is_ok();
        if curv_success && k256_success {
            // convet signature into ASN1/DER (Bitcoin) format
            return Output::Success {
                sig: sig.to_k256().to_der(),
                sig_k256: sig_k256.to_der(),
            };
        }

        // DONE TO HERE
        debug!(
            "verification success: curv: {}, k256: {}",
            curv_success, k256_success
        );

        // (r,s) is an invalid ECDSA signature => compute criminals
        // criminals fail Eq. (1) of https://eprint.iacr.org/2020/540.pdf
        // check: s_i*R =? m*R_i + r*S_i
        let mut criminals = vec![Vec::new(); self.participant_indices.len()];
        let r5state = self.r5state.as_ref().unwrap();
        for (i, criminal) in criminals.iter_mut().enumerate() {
            let in_r5bcast = self.in_r5bcasts.vec_ref()[i].as_ref().unwrap();
            let in_r6bcast = self.in_r6bcasts.vec_ref()[i].as_ref().unwrap();
            let in_r7bcast = self.in_r7bcasts.vec_ref()[i].as_ref().unwrap();

            // curv
            let r_i_m = in_r5bcast.R_i * self.msg_to_sign;
            let s_i_r = in_r6bcast.S_i * r7state.r;
            let rhs = r_i_m + s_i_r;
            let lhs = r5state.R * in_r7bcast.s_i;
            if lhs != rhs {
                let crime = Crime::R8SICheckFail;
                warn!(
                    "(curv) participant {} detect {:?} by {}",
                    self.my_participant_index, crime, i
                );
                criminal.push(crime);
            }

            // k256
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
