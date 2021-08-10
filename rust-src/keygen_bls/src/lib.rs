//! Generate a private key in a deterministic way from a secret seed and key
//! description.
use curve_arithmetic::Curve;
use ff::{Field, PrimeField};
use hkdf::Hkdf;
use pairing::bls12_381::{Fr, FrRepr, G1};
use sha2::{Digest, Sha256};

/// This function is an implementation of the procedure described in <https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-2.3>
/// It computes a random scalar in Fr given a seed (the argument `ikm`).
///
/// This is a building block for deterministic key generation for identity
/// provider and anonymity revoker keys.
pub fn keygen_bls(ikm: &[u8], key_info: &[u8]) -> Result<Fr, hkdf::InvalidLength> {
    let mut ikm = ikm.to_vec();
    ikm.push(0);
    let l = 48; // = 48 for G1; r is
                // 52435875175126190479447740508185965837690552500527637822603658699938581184513
    let mut l_bytes = key_info.to_vec();
    l_bytes.push(l);
    l_bytes.push(0);
    let salt = b"BLS-SIG-KEYGEN-SALT-";
    let mut sk = Fr::zero();
    // shift with
    // 452312848583266388373324160190187140051835877600158453279131187530910662656 =
    // 2^248
    let shift = Fr::from_repr(FrRepr([0, 0, 0, 72057594037927936])).unwrap();
    let mut salt = Sha256::digest(&salt[..]);
    while sk.is_zero() {
        let (_, h) = Hkdf::<Sha256>::extract(Some(&salt), &ikm);
        let mut okm = vec![0u8; l as usize];
        h.expand(&l_bytes, &mut okm)?;
        let mut y1_vec = [0; 32];
        let mut y2_vec = [0; 32];
        let slice_y1 = &mut y1_vec[0..31];
        slice_y1.clone_from_slice(&okm[0..31]);
        let slice_y2 = &mut y2_vec[0..okm.len() - slice_y1.len()];
        slice_y2.clone_from_slice(&okm[31..]);
        let y1 = G1::scalar_from_bytes(&y1_vec);
        let mut y2 = G1::scalar_from_bytes(&y2_vec);
        y2.mul_assign(&shift);
        sk = y1;
        sk.add_assign(&y2);
        salt = Sha256::digest(&salt);
    }
    Ok(sk)
}
