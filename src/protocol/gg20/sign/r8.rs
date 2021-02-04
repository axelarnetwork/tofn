use super::{EcdsaSig, Sign, Status};
use curv::{
    elliptic::curves::traits::{ECPoint, ECScalar},
    FE, GE,
};
use serde::{Deserialize, Serialize};

// round 8

impl Sign {
    pub(super) fn r8(&self) -> EcdsaSig {
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

        // verify that (r,s) is a valid ECDSA signature
        let sig = EcdsaSig { r: r7state.r, s };
        assert!(sig.verify(
            &self.my_secret_key_share.ecdsa_public_key,
            &self.msg_to_sign
        ));

        sig
    }
}
