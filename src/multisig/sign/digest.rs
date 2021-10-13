use k256::ecdsa::digest;
use k256::ecdsa::digest::consts::{U28, U32, U64};
use k256::ecdsa::digest::{BlockInput, FixedOutputDirty, Reset, Update};
use k256::ecdsa::digest::{Digest, Output};

#[derive(Clone)]
pub struct DigestWrapper {
    output: [u8; 32],
}

impl Default for DigestWrapper {
    fn default() -> Self {
        unimplemented!()
    }
}

impl BlockInput for DigestWrapper {
    type BlockSize = U64;
}

impl Update for DigestWrapper {
    fn update(&mut self, input: impl AsRef<[u8]>) {
        unimplemented!()
    }
}

impl FixedOutputDirty for DigestWrapper {
    type OutputSize = U32;

    fn finalize_into_dirty(&mut self, out: &mut digest::Output<Self>) {
        *out = digest::Output::<Self>::from(self.output);
    }
}

impl Reset for DigestWrapper {
    fn reset(&mut self) {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use ecdsa::signature::{DigestSigner, DigestVerifier};

    use super::DigestWrapper;

    #[test]
    fn basic_correctness() {
        let digest = DigestWrapper { output: [42u8; 32] };
        let signing_key = k256::ecdsa::SigningKey::random(rand::thread_rng());
        let signature: k256::ecdsa::Signature = signing_key.sign_digest(digest.clone());
        let verifying_key = signing_key.verifying_key();
        verifying_key.verify_digest(digest, &signature).unwrap();
    }
}
