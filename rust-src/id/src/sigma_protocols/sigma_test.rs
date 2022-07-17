use crate::sigma_protocols::{com_enc_eq, com_eq_sig, common::*, dlog};
use pairing::bls12_381::{Bls12, G1, G2};
use random_oracle::RandomOracle;

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

#[test]
pub fn test_or() {
    let mut csprng = rand::thread_rng();
    //Knowledge of both
    OrAdapter::<
        AndAdapter<dlog::Dlog<G1>, com_eq_sig::ComEqSig<Bls12, G1>>,
        com_enc_eq::ComEncEq<G2>,
    >::with_valid_data(38, &mut csprng, |prover, secret, csprng| {
        let proof = prove(&mut RandomOracle::domain("test"), &prover, secret, csprng)
            .expect("Proving should succeed.");
        assert!(verify(&mut RandomOracle::domain("test"), &prover, &proof))
    });
    //Knowledge of of one
    OrAdapter::<
        AndAdapter<dlog::Dlog<G1>, com_eq_sig::ComEqSig<Bls12, G1>>,
        com_enc_eq::ComEncEq<G2>,
    >::with_valid_data(38, &mut csprng, |prover, secret, csprng| {
        if let OrSecret::Both(s1,s2) = secret{
            let sec1 = OrSecret::P1(s1);
            let proof = prove(&mut RandomOracle::domain("test"), &prover, sec1, csprng)
            .expect("Proving should succeed.");
            assert!(verify(&mut RandomOracle::domain("test"), &prover, &proof));
            let sec2 = OrSecret::P2(s2);
            let proof = prove(&mut RandomOracle::domain("test"), &prover, sec2, csprng)
            .expect("Proving should succeed.");
            assert!(verify(&mut RandomOracle::domain("test"), &prover, &proof))
        } else {panic!("with_valid_data should provide both secrets")}
    })
}