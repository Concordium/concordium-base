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
/// provider, anonymity revoker keys and PRF keys.
pub fn keygen_bls(ikm: &[u8], key_info: &[u8]) -> Result<Fr, hkdf::InvalidLength> {
    let mut ikm = ikm.to_vec();
    ikm.push(0);
    let l = 48; // = 48 for G1; r is
                // 52435875175126190479447740508185965837690552500527637822603658699938581184513
    let mut l_bytes = key_info.to_vec();
    l_bytes.push(0);
    l_bytes.push(l);
    let salt = b"BLS-SIG-KEYGEN-SALT-";
    let mut sk = Fr::zero();
    // shift with
    // 452312848583266388373324160190187140051835877600158453279131187530910662656 =
    // 2^248 = 2^(31*8)
    let shift = Fr::from_repr(FrRepr([0, 0, 0, 72057594037927936])).unwrap();
    let mut salt = Sha256::digest(&salt[..]);
    while sk.is_zero() {
        let (_, h) = Hkdf::<Sha256>::extract(Some(&salt), &ikm);
        let mut okm = vec![0u8; l as usize];
        h.expand(&l_bytes, &mut okm)?;
        // Reverse the vector since `scalar_from_bytes` expects the bytes in
        // little-endian
        okm.reverse();
        // Following the standard, we have to
        // interpret the 48 bytes in `okm` as an integer and then reduce modulo r.
        // Since 2^(31*8) < r < 2^(32*8), we use `scalar_from_bytes` twice by
        // calculating (in Fr) y1 + shift*y2, where
        // y1 = scalar_from_bytes(first 31 bytes of okm), and
        // y2 = scalar_from_bytes(last 17 bytes of okm)
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

/// This function is a deprecated version of the above `keygen_bls`.
/// The difference is that it uses little-endian instead of big-endian, both as
/// input to the `expand` function and when interpreting the bytes in `okm` as
/// an integer modulo r. It therefore does not follow the standard (cf. <https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-2.3>),
/// but is still secure.
/// This function is needed for backwards compatibility.
pub fn keygen_bls_deprecated(ikm: &[u8], key_info: &[u8]) -> Result<Fr, hkdf::InvalidLength> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen() {
        let inputs: [&str; 10] = [
            "09e74ad3ead373439388bf7cfb52b151c450632e67f3c84e6ed762bc0928d5eb",
            "9dcce7d6b6a70ddb382d2c212273ad9b99d8ea206353313beabc14b7e5833a0f",
            "8a430bd1343b5cb1686961d7959095214952767f80bb681e465aebf467ca05c0",
            "c940716ce93f72b2d4f9ff792193ee541e3748ff5b13f1bb01d5d091af4e2635",
            "bc14d035741cd9225795ad1e7070a1b488deb0cc19daedcb47f12408cbfe71cc",
            "00bbfd863df0068b841c12f6e6a8d6c571c80eaf37fae324c669d214f90a762c",
            "30c0a09b5175febb462b64efe28475fa434b0ccfb05bc77d16fd2f1ba13bc05c",
            "34a3f5d8b0cfaa9d235c8c1ecfbf10223259d45be5f4d30b33c697e19ac9e525",
            "d57e90d96aab5616c266568ad4659dfe985f8baf24042e5e28e901801944f49d",
            "725150bb38d49fc2a7ad8a8cba1f0dc32c3a468739e88b9aa62c450ce3ce1f32",
        ];

        // The expected outputs have been derived using https://github.com/paulmillr/bls12-381-keygen
        // and double checked with https://github.com/ChainSafe/bls-hd-key
        let expected_outputs: [[u64; 4]; 10] = [
            [
                17351079049985859042,
                9243168354177730561,
                1354598858808160974,
                6326193586470323551,
            ], // 0x57cb278c9deb055f12cc807c3068f2ce804654a54de54801f0cb6a774c211de2
            [
                5120851860807520862,
                7537404979026392860,
                17958325247724939891,
                2827706577331116975,
            ], // 0x273e082676db5baff938c9aa5f92ea73689a3de4bf20f71c4710eba2ced4925e
            [
                15727871129641048774,
                11988799985501999947,
                1388620089874179915,
                8145693946474164108,
            ], // 0x710b517c90a46f8c13455e9d50ebe74ba660c611430e134bda449f766b605ac6
            [
                3932271522535121134,
                8872934998377405368,
                7259163645480412069,
                3750812284986048912,
            ], // 0x340d8fe689c3c19064bdbadff74a23a57b22ff5ec56a9bb836923c1d9d1720ee
            [
                16107158621426899190,
                10500072591120856542,
                15181573451644741747,
                3125850084510497659,
            ], // 0x2b614017245f7b7bd2afc89e6cc9287391b7c063cd92f5dedf881f6d430558f6
            [
                13771624569621348445,
                3146403120475439736,
                18069601902237922649,
                6758674237477415953,
            ], // 0x5dcba268f56cec11fac41f31779d35592baa44f7bc1e8278bf1ea394b452805d
            [
                4833464224170637233,
                15025051245287273709,
                1074686477808441037,
                3419044651413101239,
            ], // 0x2f72e2fedead5ab70eea0da85ab016cdd083b4805f6374ed4313ea1a643ff7b1
            [
                3385693996904717713,
                6453425908238454111,
                11250048985110811077,
                3660893330520285257,
            ], // 0x32ce1b167e4220499c2033f2574611c5598f2cabfcdb0d5f2efc66c083ad9d91
            [
                13103272484668436394,
                12668243431219103286,
                12426998760715496251,
                6676359852315787176,
            ], // 0x5ca731e9adf63fa8ac75918824aaab3bafcea4480dfd8636b5d82ce693cfefaa
            [
                12161214505729619043,
                2991033334211776658,
                18345117405735658320,
                4138888141383584617,
            ], // 0x397048d5f83ecb69fe96f3157bb5a350298248f8650b9092a8c55028fb577463
        ];

        for i in 0..10 {
            if let Ok(seed) = hex::decode(inputs[i]) {
                if let Ok(sk) = keygen_bls(&seed, b"") {
                    assert_eq!(sk.into_repr(), FrRepr(expected_outputs[i]))
                } else {
                    panic!("Could not generate key from seed.")
                }
            } else {
                panic!("Could not hex decode.")
            }
        }
    }
}
