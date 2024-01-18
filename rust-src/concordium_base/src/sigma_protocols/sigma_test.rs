use crate::{
    curve_arithmetic::arkworks_instances::ArkGroup,
    random_oracle::RandomOracle,
    sigma_protocols::{com_enc_eq, com_eq_sig, common::*, dlog},
};
use ark_bls12_381::{G1Projective, G2Projective};

type G1 = ArkGroup<G1Projective>;
type G2 = ArkGroup<G2Projective>;
type Bls12 = ark_ec::models::bls12::Bls12<ark_bls12_381::Config>;

#[test]
pub fn test_and() {
    let mut csprng = rand::thread_rng();
    AndAdapter::<
        AndAdapter<dlog::Dlog<G1>, com_eq_sig::ComEqSig<Bls12, G1>>,
        com_enc_eq::ComEncEq<G2>,
    >::with_valid_data(38, &mut csprng, |prover, secret, csprng| {
        let proof = prove(&mut RandomOracle::domain("test"), &prover, secret, csprng)
            .expect("Proving should succeed.");
        assert!(verify(&mut RandomOracle::domain("test"), &prover, &proof))
    })
}
