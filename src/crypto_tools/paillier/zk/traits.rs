pub trait NIZKStatement {
    type Witness;
    type Proof;

    /// Generate a NIZK proof of self
    fn prove(&self, wit: &Self::Witness, domain: &[u8]) -> Self::Proof;

    /// Verify a NIZK proof of self
    fn verify(&self, proof: &Self::Proof, domain: &[u8]) -> bool;
}
