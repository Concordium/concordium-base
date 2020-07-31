use bulletproofs::range_proof::{prove as bulletprove, RangeProof};
use curve_arithmetic::{Curve, Value};
use elgamal::{
    cipher::{Cipher, Randomness as ElgamalRandomness},
    public::PublicKey,
    secret::SecretKey,
};
use id::sigma_protocols::{com_eq::*, common::*};
use pedersen_scheme::{Commitment, CommitmentKey, Randomness as PedersenRandomness};
use random_oracle::*;

fn enc_exp<C: Curve, R: rand::Rng>(
    ro: RandomOracle,
    csprng: &mut R,
    cmm_key: &CommitmentKey<C>,
    pk: &PublicKey<C>,
    cipher: &[Cipher<C>],
    value: &[Value<C>],
    randomness: &[ElgamalRandomness<C>],
    s: u8,
) -> (/*impl SigmaProtocol, RangeProof<C>*/) {
    let x = *value[0];
    let r = *randomness[0];
    let (g, h) = (cmm_key.0, cmm_key.1);
    let pk_eg = pk.key;
    let commitment = Commitment(h.mul_by_scalar(&x).plus_point(&pk_eg.mul_by_scalar(&r)));
    let y = g.mul_by_scalar(&r);
    let cmm_key_comeq = CommitmentKey(pk_eg, h);
    let comeq = ComEq {
        commitment,
        y,
        cmm_key: cmm_key_comeq,
        g,
    };
    let secret_r = PedersenRandomness::<C>::new(x);
    let secret_a = Value::new(r);
    let comeq_secret = ComEqSecret {
        r: secret_r,
        a: secret_a,
    };
}
