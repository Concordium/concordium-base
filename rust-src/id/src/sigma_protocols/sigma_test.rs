use crate::sigma_protocols::{com_enc_eq, com_eq_sig, common::*, dlog};
use curve_arithmetic::Curve;
use pairing::bls12_381::{Bls12, G1, G2};
use pedersen_scheme::{Commitment, CommitmentKey};
use random_oracle::RandomOracle;

use super::com_eq;

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

// Just an example, "real" sigma-protocol atomic statements will be determined once we know
// what kind of (in)equalities we want to prove
#[derive(Clone, Copy)]
enum SigmaAtom<C: Curve> {
    Eq(C, C),
    EqCommitment(Commitment<C>, C, CommitmentKey<C>, C),
}
enum ZkLang<C: Curve> {
    And(Vec<SigmaAtom<C>>),
}

fn interpret_sigma_atom<C: Curve>(
    s: SigmaAtom<C>,
) -> EitherAdapter<dlog::Dlog<C>, com_eq::ComEq<C, C>> {
    match s {
        SigmaAtom::Eq(c1, c2) => EitherAdapter {
            // discrete log for this one
            protocol: Either::Left(dlog::Dlog {
                public: c1,
                coeff: c2,
            }),
        },
        SigmaAtom::EqCommitment(c1, y, c2, g) => EitherAdapter {
            protocol: Either::Right(com_eq::ComEq {
                // discrete log and commitments
                commitment: c1,
                y,
                cmm_key: c2,
                g,
            }),
        },
    }
}

fn interpret_sigma_zk_lang<C : Curve> (
    s : ZkLang<C>
 ) -> ReplicateAdapter<EitherAdapter<dlog::Dlog<C>, com_eq::ComEq<C,C>>> {
    match s {
        ZkLang::And(statements) => {
            let protocols = 
                statements.iter().map(|s| interpret_sigma_atom(*s)).collect();
            ReplicateAdapter { protocols }
        }
    }
    
 }
