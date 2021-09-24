pub trait NIZKStatement {
    type Witness;
    type Proof;
    type Domain;

    /// Generate a NIZK proof of self
    fn prove(&self, wit: &Self::Witness, domain: Self::Domain) -> Self::Proof;

    /// Verify a NIZK proof of self
    fn verify(&self, proof: &Self::Proof, domain: Self::Domain) -> bool;
}
