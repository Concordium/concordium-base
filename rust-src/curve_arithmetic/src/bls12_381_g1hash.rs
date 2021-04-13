use crate::curve_arithmetic::CurveDecodingError;
use ff::{Field, PrimeField, SqrtField};
use group::{CurveProjective, EncodedPoint};
use pairing::bls12_381::{Fq, FqRepr, G1Uncompressed, G1};
use sha2::{Digest, Sha256};
use std::{
    convert::TryInto,
    io::{Cursor, Write},
};

// (p-3)/4 where p is the prime characteristic of the field Fq (p=q)
#[allow(clippy::unreadable_literal)]
pub(crate) const P_MINUS_3_DIV_4: [u64; 6] = [
    0xee7fbfffffffeaaa,
    0x07aaffffac54ffff,
    0xd9cc34a83dac3d89,
    0xd91dd2e13ce144af,
    0x92c6e9ed90d2eb35,
    0x680447a8e5ff9a6,
];

// (p-1)/2 where p is the prime characteristic of the field Fq (p=q)
#[allow(clippy::unreadable_literal)]
pub(crate) const P_MINUS_1_DIV_2: [u64; 6] = [
    0xdcff7fffffffd555,
    0x0f55ffff58a9ffff,
    0xb39869507b587b12,
    0xb23ba5c279c2895f,
    0x258dd3db21a5d66b,
    0xd0088f51cbff34d,
];

// The a-coefficient of the 11-isogenous curve to G1
#[allow(clippy::unreadable_literal)]
pub(crate) const E11_A: [u64; 6] = [
    0x5cf428082d584c1d,
    0x98936f8da0e0f97f,
    0xd8e8981aefd881ac,
    0xb0ea985383ee66a8,
    0x3d693a02c96d4982,
    0x00144698a3b8e943,
];

// The b-coefficient of the 11-isogenous curve to G1
#[allow(clippy::unreadable_literal)]
pub(crate) const E11_B: [u64; 6] = [
    0xd1cc48e98e172be0,
    0x5a23215a316ceaa5,
    0xa0b9c14fcef35ef5,
    0x2016c1f0f24f4070,
    0x018b12e8753eee3b,
    0x12e2908d11688030,
];

// Coefficients of the 11-isogeny rational maps,
// See https://eprint.iacr.org/2019/403.pdf section 4
#[allow(clippy::unreadable_literal)]
pub(crate) const K1: [[u64; 6]; 12] = [
    [
        0xaeac1662734649b7,
        0x5610c2d5f2e62d6e,
        0xf2627b56cdb4e2c8,
        0x6b303e88a2d7005f,
        0xb809101dd9981585,
        0x11a05f2b1e833340,
    ],
    [
        0xe834eef1b3cb83bb,
        0x4838f2a6f318c356,
        0xf565e33c70d1e86b,
        0x7c17e75b2f6a8417,
        0x0588bab22147a81c,
        0x17294ed3e943ab2f,
    ],
    [
        0xe0179f9dac9edcb0,
        0x958c3e3d2a09729f,
        0x6878e501ec68e25c,
        0xce032473295983e5,
        0x1d1048c5d10a9a1b,
        0xd54005db97678ec,
    ],
    [
        0xc5b388641d9b6861,
        0x5336e25ce3107193,
        0xf1b33289f1b33083,
        0xd7f5e4656a8dbf25,
        0x4e0609d307e55412,
        0x1778e7166fcc6db7,
    ],
    [
        0x51154ce9ac8895d9,
        0x985a286f301e77c4,
        0x086eeb65982fac18,
        0x99db995a1257fb3f,
        0x6642b4b3e4118e54,
        0xe99726a3199f443,
    ],
    [
        0xcd13c1c66f652983,
        0xa0870d2dcae73d19,
        0x9ed3ab9097e68f90,
        0xdb3cb17dd952799b,
        0x01d1201bf7a74ab5,
        0x1630c3250d7313ff,
    ],
    [
        0xddd7f225a139ed84,
        0x8da25128c1052eca,
        0x9008e218f9c86b2a,
        0xb11586264f0f8ce1,
        0x6a3726c38ae652bf,
        0xd6ed6553fe44d29,
    ],
    [
        0x9ccb5618e3f0c88e,
        0x39b7c8f8c8f475af,
        0xa682c62ef0f27533,
        0x356de5ab275b4db1,
        0xe8743884d1117e53,
        0x17b81e7701abdbe2,
    ],
    [
        0x6d71986a8497e317,
        0x4fa295f296b74e95,
        0xa2c596c928c5d1de,
        0xc43b756ce79f5574,
        0x7b90b33563be990d,
        0x80d3cf1f9a78fc4,
    ],
    [
        0x7f241067be390c9e,
        0xa3190b2edc032779,
        0x676314baf4bb1b7f,
        0xdd2ecb803a0c5c99,
        0x2e0c37515d138f22,
        0x169b1f8e1bcfa7c4,
    ],
    [
        0xca67df3f1605fb7b,
        0xf69b771f8c285dec,
        0xd50af36003b14866,
        0xfa7dccdde6787f96,
        0x72d8ec09d2565b0d,
        0x10321da079ce07e2,
    ],
    [
        0xa9c8ba2e8ba2d229,
        0xc24b1b80b64d391f,
        0x23c0bf1bc24c6b68,
        0x31d79d7e22c837bc,
        0xbd1e962381edee3d,
        0x6e08c248e260e70,
    ],
];

#[allow(clippy::unreadable_literal)]
pub(crate) const K2: [[u64; 6]; 11] = [
    [
        0x993cf9fa40d21b1c,
        0xb558d681be343df8,
        0x9c9588617fc8ac62,
        0x01d5ef4ba35b48ba,
        0x18b2e62f4bd3fa6f,
        0x8ca8d548cff19ae,
    ],
    [
        0xe5c8276ec82b3bff,
        0x13daa8846cb026e9,
        0x0126c2588c48bf57,
        0x7041e8ca0cf0800c,
        0x48b4711298e53636,
        0x12561a5deb559c43,
    ],
    [
        0xfcc239ba5cb83e19,
        0xd6a3d0967c94fedc,
        0xfca64e00b11aceac,
        0x6f89416f5a718cd1,
        0x8137e629bff2991f,
        0xb2962fe57a3225e,
    ],
    [
        0x130de8938dc62cd8,
        0x4976d5243eecf5c4,
        0x54cca8abc28d6fd0,
        0x5b08243f16b16551,
        0xc83aafef7c40eb54,
        0x3425581a58ae2fe,
    ],
    [
        0x539d395b3532a21e,
        0x9bd29ba81f35781d,
        0x8d6b44e833b306da,
        0xffdfc759a12062bb,
        0x0a6f1d5f43e7a07d,
        0x13a8e162022914a8,
    ],
    [
        0xc02df9a29f6304a5,
        0x7400d24bc4228f11,
        0x0a43bcef24b8982f,
        0x395735e9ce9cad4d,
        0x55390f7f0506c6e9,
        0xe7355f8e4e667b9,
    ],
    [
        0xec2574496ee84a3a,
        0xea73b3538f0de06c,
        0x4e2e073062aede9c,
        0x570f5799af53a189,
        0x0f3e0c63e0596721,
        0x772caacf1693619,
    ],
    [
        0x11f7d99bbdcc5a5e,
        0x0fa5b9489d11e2d3,
        0x1996e1cdf9822c58,
        0x6e7f63c21bca68a8,
        0x30b3f5b074cf0199,
        0x14a7ac2a9d64a8b2,
    ],
    [
        0x4776ec3a79a1d641,
        0x03826692abba4370,
        0x74100da67f398835,
        0xe07f8d1d7161366b,
        0x5e920b3dafc7a3cc,
        0xa10ecf6ada54f82,
    ],
    [
        0x2d6384d168ecdd0a,
        0x93174e4b4b786500,
        0x76df533978f31c15,
        0xf682b4ee96f7d037,
        0x476d6e3eb3a56680,
        0x95fc13ab9e92ad4,
    ],
    [0x1, 0x0, 0x0, 0x0, 0x0, 0x0],
];

#[allow(clippy::unreadable_literal)]
pub(crate) const K3: [[u64; 6]; 16] = [
    [
        0xbe9845719707bb33,
        0xcd0c7aee9b3ba3c2,
        0x2b52af6c956543d3,
        0x11ad138e48a86952,
        0x259d1f094980dcfa,
        0x90d97c81ba24ee0,
    ],
    [
        0xe097e75a2e41c696,
        0xd6c56711962fa8bf,
        0x0f906343eb67ad34,
        0x1223e96c254f383d,
        0xd51036d776fb4683,
        0x134996a104ee5811,
    ],
    [
        0xb8dfe240c72de1f6,
        0xd26d521628b00523,
        0xc344be4b91400da7,
        0x2552e2d658a31ce2,
        0xf4a384c86a3b4994,
        0xcc786baa966e66,
    ],
    [
        0xa6355c77b0e5f4cb,
        0xde405aba9ec61dec,
        0x09e4a3ec03251cf9,
        0xd42aa7b90eeb791c,
        0x7898751ad8746757,
        0x1f86376e8981c21,
    ],
    [
        0x41b6daecf2e8fedb,
        0x2ee7f8dc099040a8,
        0x79833fd221351adc,
        0x195536fbe3ce50b8,
        0x5caf4fe2a21529c4,
        0x8cc03fdefe0ff13,
    ],
    [
        0x99b23ab13633a5f0,
        0x203f6326c95a8072,
        0x76505c3d3ad5544e,
        0x74a7d0d4afadb7bd,
        0x2211e11db8f0a6a0,
        0x16603fca40634b6a,
    ],
    [
        0xc961f8855fe9d6f2,
        0x47a87ac2460f415e,
        0x5231413c4d634f37,
        0xe75bb8ca2be184cb,
        0xb2c977d027796b3c,
        0x4ab0b9bcfac1bbc,
    ],
    [
        0xa15e4ca31870fb29,
        0x42f64550fedfe935,
        0xfd038da6c26c8426,
        0x170a05bfe3bdd81f,
        0xde9926bd2ca6c674,
        0x987c8d5333ab86f,
    ],
    [
        0x60370e577bdba587,
        0x69d65201c78607a3,
        0x1e8b6e6a1f20cabe,
        0x8f3abd16679dc26c,
        0xe88c9e221e4da1bb,
        0x9fc4018bd96684b,
    ],
    [
        0x2bafaaebca731c30,
        0x9b3f7055dd4eba6f,
        0x06985e7ed1e4d43b,
        0xc42a0ca7915af6fe,
        0x223abde7ada14a23,
        0xe1bba7a1186bdb5,
    ],
    [
        0xe813711ad011c132,
        0x31bf3a5cce3fbafc,
        0xd1183e416389e610,
        0xcd2fcbcb6caf493f,
        0x0dfd0b8f1d43fb93,
        0x19713e47937cd1be,
    ],
    [
        0xce07c8a4d0074d8e,
        0x49d9cdf41b44d606,
        0x2e6bfe7f911f6432,
        0x523559b8aaf0c246,
        0xb918c143fed2edcc,
        0x18b46a908f36f6de,
    ],
    [
        0x0d4c04f00b971ef8,
        0x06c851c1919211f2,
        0xc02710e807b4633f,
        0x7aa7b12a3426b08e,
        0xd155096004f53f44,
        0xb182cac101b9399,
    ],
    [
        0x42d9d3f5db980133,
        0xc6cf90ad1c232a64,
        0x13e6632d3c40659c,
        0x757b3b080d4c1580,
        0x72fc00ae7be315dc,
        0x245a394ad1eca9b,
    ],
    [
        0x866b1e715475224b,
        0x6ba1049b6579afb7,
        0xd9ab0f5d396a7ce4,
        0x5e673d81d7e86568,
        0x02a159f748c4a3fc,
        0x5c129645e44cf11,
    ],
    [
        0x04b456be69c8b604,
        0xb665027efec01c77,
        0x57add4fa95af01b2,
        0xcb181d8f84965a39,
        0x4ea50b3b42df2eb5,
        0x15e6be4e990f03ce,
    ],
];

#[allow(clippy::unreadable_literal)]
pub(crate) const K4: [[u64; 6]; 16] = [
    [
        0x01479253b03663c1,
        0x07f3688ef60c206d,
        0xeec3232b5be72e7a,
        0x601a6de578980be6,
        0x52181140fad0eae9,
        0x16112c4c3a9c98b2,
    ],
    [
        0x32f6102c2e49a03d,
        0x78a4260763529e35,
        0xa4a10356f453e01f,
        0x85c84ff731c4d59c,
        0x1a0cbd6c43c348b8,
        0x1962d75c2381201e,
    ],
    [
        0x1e2538b53dbf67f2,
        0xa6757cd636f96f89,
        0x0c35a5dd279cd2ec,
        0x78c4855551ae7f31,
        0x6faaae7d6e8eb157,
        0x58df3306640da27,
    ],
    [
        0xa8d26d98445f5416,
        0x727364f2c28297ad,
        0x123da489e726af41,
        0xd115c5dbddbcd30e,
        0xf20d23bf89edb4d1,
        0x16b7d288798e5395,
    ],
    [
        0xda39142311a5001d,
        0xa20b15dc0fd2eded,
        0x542eda0fc9dec916,
        0xc6d19c9f0f69bbb0,
        0xb00cc912f8228ddc,
        0xbe0e079545f43e4,
    ],
    [
        0x02c6477faaf9b7ac,
        0x49f38db9dfa9cce2,
        0xc5ecd87b6f0f5a64,
        0xb70152c65550d881,
        0x9fb266eaac783182,
        0x8d9e5297186db2d,
    ],
    [
        0x3d1a1399126a775c,
        0xd5fa9c01a58b1fb9,
        0x5dd365bc400a0051,
        0x5eecfdfa8d0cf8ef,
        0xc3ba8734ace9824b,
        0x166007c08a99db2f,
    ],
    [
        0x60ee415a15812ed9,
        0xb920f5b00801dee4,
        0xfeb34fd206357132,
        0xe5a4375efa1f4fd7,
        0x03bcddfabba6ff6e,
        0x16a3ef08be3ea7ea,
    ],
    [
        0x6b233d9d55535d4a,
        0x52cfe2f7bb924883,
        0xabc5750c4bf39b48,
        0xf9fb0ce4c6af5920,
        0x1a1be54fd1d74cc4,
        0x1866c8ed336c6123,
    ],
    [
        0x346ef48bb8913f55,
        0xc7385ea3d529b35e,
        0x5308592e7ea7d4fb,
        0x3216f763e13d87bb,
        0xea820597d94a8490,
        0x167a55cda70a6e1c,
    ],
    [
        0x00f8b49cba8f6aa8,
        0x71a5c29f4f830604,
        0x0e591b36e636a5c8,
        0x9c6dd039bb61a629,
        0x48f010a01ad2911d,
        0x4d2f259eea405bd,
    ],
    [
        0x9684b529e2561092,
        0x16f968986f7ebbea,
        0x8c0f9a88cea79135,
        0x7f94ff8aefce42d2,
        0xf5852c1e48c50c47,
        0xaccbb67481d033f,
    ],
    [
        0x1e99b138573345cc,
        0x93000763e3b90ac1,
        0x7d5ceef9a00d9b86,
        0x543346d98adf0226,
        0xc3613144b45f1496,
        0xad6b9514c767fe3,
    ],
    [
        0xd1fadc1326ed06f7,
        0x420517bd8714cc80,
        0xcb748df27942480e,
        0xbf565b94e72927c1,
        0x628bdd0d53cd76f2,
        0x2660400eb2e4f3b,
    ],
    [
        0x4415473a1d634b8f,
        0x5ca2f570f1349780,
        0x324efcd6356caa20,
        0x71c40f65e273b853,
        0x6b24255e0d7819c1,
        0xe0fa1d816ddc03e,
    ],
    [0x1, 0x0, 0x0, 0x0, 0x0, 0x0],
];

pub fn hash_to_g1(bytes: &[u8]) -> G1 {
    // Concatenate the message with 0u8 and 1u8 respectively
    // The paper suggests concatenating a single bit - but since the point is to
    // get two unrelated field elements, concatenating with 0u8 and 1u8 is ok
    // Instead of forming two new byte arrays we pass a boolean to hash_bytes_to_fq
    // function below.

    let (t0, t1) = hash_to_field(&bytes, "QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_".as_bytes());

    // compute the two points on E1'(Fq) - the 11 isogenous curve
    let (x0, y0, z0) = simplified_swu(t0);
    let (x1, y1, z1) = simplified_swu(t1);


    // evaluate the 11-isogeny on the points.
    // it is faster to add the two points before evaluating the isogeny, but
    // we omit this for now, since we don't have an efficient implementation
    // of the curve.
    let (x0, y0, z0) = iso_11(x0, y0, z0); // todo would it be significantly faster?
    let (x1, y1, z1) = iso_11(x1, y1, z1);

    // convert into points on the curve
    let mut p0 = from_coordinates_unchecked(x0, y0, z0).expect("should not happen");
    let p1 = from_coordinates_unchecked(x1, y1, z1).expect("should not happen");

    // add the two points on E1: y^2 = x^3 + 4
    p0.add_assign(&p1);

    // Clear cofactors (ensuring that the point is in the correct order subgroup of
    // the curve)
    p0.mul_assign(1 + 15_132_376_222_941_642_752); // 15_132_376_222_941_642_753
    p0
}

fn hash_to_field(msg: &[u8], dst: &[u8]) -> (Fq, Fq) {
    let (u_0, u_1, u_2, u_3) = expand_message_xmd(msg, dst);

    (fq_from_bytes(&u_0, &u_1), fq_from_bytes(&u_2, &u_3))
}

// Interpret input as integers (big endian)
// Return (left*2^256 + right) as Fq
fn fq_from_bytes(left_bytes: &[u8; 32], right_bytes: &[u8; 32]) -> Fq {
    fn le_u64s_from_be_bytes(bytes: &[u8]) -> Fq {
        let mut digits = [0u64; 6];

        for i in 0..4 {
            digits[3-i] = u64::from_be_bytes(bytes[i*8..(i+1)*8].try_into().expect("Chunk Size is always 8."));
        }

        Fq::from_repr(FqRepr(digits)).expect("Only the leading 4 u64s are initialized")
    }

    let two_to_256_fqrepr = [0u64, 0, 0, 0, 1, 0]; // 2^256
    let two_to_256_fq = Fq::from_repr(FqRepr(two_to_256_fqrepr)).expect("2^256 fits in modulus");

    let mut left_fq = le_u64s_from_be_bytes(left_bytes);
    let right_fq = le_u64s_from_be_bytes(right_bytes);
    left_fq.mul_assign(&two_to_256_fq); // u_0[..32] * 2^256
    left_fq.add_assign(&right_fq); // u_0[32..] + u_0[32..] * 2^256 = u_0

    left_fq
}

// Implements https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-10#section-5.4.1
// len_in_bytes is fixed to 128
// Domain separation string (dst) should be at most 255 bytes
fn expand_message_xmd(msg: &[u8], dst: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
    // DST_prime = DST || I2OSP(len(DST), 1)
    let mut dst_prime = dst.to_vec();
    dst_prime.push(dst.len().try_into().unwrap()); // panics if dst is more than 255 bytes
    // msg_prime = Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime
    
    // b_0 = H(msg_prime)
    let mut h = Sha256::new();
    // todo a possible optimization here would be to save the state of H(Z_pad)
    h.update(vec![0; 64]); // z_pad = I2OSP(0, 64), 64 is the input block size of Sha265
    h.update(msg);
    h.update(vec![0, 128]); // l_i_b_str = I2OSP(128, 2)
    h.update(vec![0]);
    h.update(&dst_prime);
    let mut b_0: [u8; 32] = [0u8; 32];
    b_0.copy_from_slice(h.finalize().as_slice());
    
    // b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
    let mut h = Sha256::new();
    h.update(b_0);
    h.update(vec![1]);
    h.update(&dst_prime);
    let mut b_1: [u8; 32] = [0u8; 32];
    b_1.copy_from_slice(h.finalize().as_slice());
    
    // b_2 = H(strxor(b_0, b_1)  || I2OSP(2, 1) || DST_prime)
    let mut h = Sha256::new();
    let xor: Vec<u8> = b_0.iter().zip(b_1.iter()).map(|(x, y)| x ^ y).collect();
    h.update(xor);
    h.update(vec![2]);
    h.update(&dst_prime);
    let mut b_2: [u8; 32] = [0u8; 32];
    b_2.copy_from_slice(h.finalize().as_slice());
    
    // b_3 = H(strxor(b_1, b_2)  || I2OSP(3, 1) || DST_prime)
    let mut h = Sha256::new();
    let xor: Vec<u8> = b_0.iter().zip(b_2.iter()).map(|(x, y)| x ^ y).collect();
    h.update(xor);
    h.update(vec![3]);
    h.update(&dst_prime);
    let mut b_3: [u8; 32] = [0u8; 32];
    b_3.copy_from_slice(h.finalize().as_slice());
    
    // b_4 = H(strxor(b_2, b_3)  || I2OSP(4, 1) || DST_prime)
    let mut h = Sha256::new();
    let xor: Vec<u8> = b_0.iter().zip(b_3.iter()).map(|(x, y)| x ^ y).collect();
    h.update(xor);
    h.update(vec![4]);
    h.update(dst_prime);
    let mut b_4: [u8; 32] = [0u8; 32];
    b_4.copy_from_slice(h.finalize().as_slice());

    //todo use loop

    (b_1, b_2, b_3, b_4)
}

// Returns a point on E1 with coordinates x,y,z.
// CAREFUL! This point is NOT guaranteed to be in the correct order subgroup
// To get the point into the correct order subgroup, multiply by 1 +
// 15132376222941642752
#[inline]
fn from_coordinates_unchecked(x: Fq, y: Fq, z: Fq) -> Result<G1, CurveDecodingError> {
    if z.is_zero() {
        Ok(G1::zero())
    } else {
        let z_inv = z.inverse().unwrap();
        let mut z_inv2 = z_inv;
        z_inv2.square();
        let mut p_x = x;
        p_x.mul_assign(&z_inv2);
        let mut p_y = y;
        p_y.mul_assign(&z_inv);
        p_y.mul_assign(&z_inv2);

        let mut uncompress_point = G1Uncompressed::empty();
        let mut cursor = Cursor::new(uncompress_point.as_mut());

        for digit in p_x.into_repr().as_ref().iter().rev() {
            cursor
                .write(&digit.to_be_bytes())
                .map_err(|_| CurveDecodingError::NotOnCurve)?;
        }
        for digit in p_y.into_repr().as_ref().iter().rev() {
            cursor
                .write(&digit.to_be_bytes())
                .map_err(|_| CurveDecodingError::NotOnCurve)?;
        }

        match uncompress_point.into_affine_unchecked() {
            Ok(p) => Ok(G1::from(p)),
            Err(_) => Err(CurveDecodingError::NotOnCurve),
        }
    }
}

// Input: u, an element of F.
// Output: (xn, xd, yn, yd) such that (xn / xd, yn / yd) is a
//         point on the target curve.
fn sswu_3mod4(u: Fq) -> (Fq, Fq, Fq, Fq) {
    let a = Fq::from_repr(FqRepr(E11_A)).unwrap(); // this unwrap can't fail, E11_A is an element of the field
    let b = Fq::from_repr(FqRepr(E11_B)).unwrap(); // this unwrap can't fail, E11_B is an element of the field
    // Constants:
    // 1.  c1 = (q - 3) / 4           # Integer arithmetic
    // 2.  c2 = sqrt(-Z^3)
    // Z = 11
    let z = Fq::from_repr(FqRepr::from(11)).unwrap();
    let mut c2 = z;
    c2.square();
    c2.mul_assign(&z);
    c2.negate();
    c2 = c2.sqrt().unwrap(); //todo use constant

    // Steps:
    // 1.  tv1 = u^2
    let mut tv1 = u.clone();
    tv1.square();

    // 2.  tv3 = Z * tv1
    let mut tv3 = z.clone();
    tv3.mul_assign(&tv1);

    // 3.  tv2 = tv3^2
    let mut tv2 = tv3.clone();
    tv2.square();

    // 4.   xd = tv2 + tv3
    let mut xd = tv2.clone();
    xd.add_assign(&tv3);

    // 5.  x1n = xd + 1
    // 6.  x1n = x1n * B
    let mut x1n = xd.clone();
    x1n.add_assign(&Fq::one());
    x1n.mul_assign(&b);

    // 7.   xd = -A * xd
    let mut neg_a = a.clone();
    neg_a.negate();
    xd.mul_assign(&neg_a);

    // 8.   e1 = xd == 0
    let e1 = xd.is_zero();

    // 9.   xd = CMOV(xd, Z * A, e1)  # If xd == 0, set xd = Z * A
    if e1 {
        xd = z.clone();
        xd.mul_assign(&a);//todo should we use equivalent of CMOV?
    }

    // 10. tv2 = xd^2
    tv2 = xd.clone();
    tv2.square();

    // 11. gxd = tv2 * xd             # gxd == xd^3
    let mut gxd = tv2.clone();
    gxd.mul_assign(&xd);

    // 12. tv2 = A * tv2
    tv2.mul_assign(&a);

    // 13. gx1 = x1n^2
    let mut gx1 = x1n.clone();
    gx1.square();

    // 14. gx1 = gx1 + tv2            # x1n^2 + A * xd^2
    gx1.add_assign(&tv2);

    // 15. gx1 = gx1 * x1n            # x1n^3 + A * x1n * xd^2
    gx1.mul_assign(&x1n);

    // 16. tv2 = B * gxd
    tv2 = b.clone();
    tv2.mul_assign(&gxd);

    // 17. gx1 = gx1 + tv2            # x1n^3 + A * x1n * xd^2 + B * xd^3
    gx1.add_assign(&tv2);

    // 18. tv4 = gxd^2
    let mut tv4 = gxd.clone();
    tv4.square();

    // 19. tv2 = gx1 * gxd
    tv2 = gx1.clone();
    tv2.mul_assign(&gxd);

    // 20. tv4 = tv4 * tv2            # gx1 * gxd^3
    tv4.mul_assign(&tv2);

    // 21.  y1 = tv4^c1               # (gx1 * gxd^3)^((q - 3) / 4)
    let mut y1 = tv4.clone();
    y1.pow(&P_MINUS_3_DIV_4);

    // 22.  y1 = y1 * tv2             # gx1 * gxd * (gx1 * gxd^3)^((q - 3) / 4)
    y1.mul_assign(&tv2);

    // 23. x2n = tv3 * x1n            # x2 = x2n / xd = Z * u^2 * x1n / xd
    let mut x2n = tv3.clone();
    x2n.mul_assign(&x1n);

    // 24.  y2 = y1 * c2              # y2 = y1 * sqrt(-Z^3)
    let mut y2 = y1.clone();
    y2.mul_assign(&c2);

    // 25.  y2 = y2 * tv1
    y2.mul_assign(&tv1);

    // 26.  y2 = y2 * u
    y2.mul_assign(&u);

    // 27. tv2 = y1^2
    tv2 = y1.clone();
    tv2.square();

    // 28. tv2 = tv2 * gxd
    tv2.mul_assign(&gxd);

    // 29.  e2 = tv2 == gx1
    tv2.sub_assign(&gx1);
    let e2 = tv2.is_zero(); 

    let mut xn = x2n.clone();
    let mut y = y2.clone();
    // 30.  xn = CMOV(x2n, x1n, e2)   # If e2, x = x1, else x = x2
    // 31.   y = CMOV(y2, y1, e2)     # If e2, y = y1, else y = y2
    if e2 {
        xn = x1n.clone();
        y = y1.clone();//todo use match or CMOV
    }

    // 32.  e3 = sgn0(u) == sgn0(y)   # Fix sign of y
    let e3 = sign(u) == sign(y);

    // 33.   y = CMOV(-y, y, e3)
    if !e3 {
        y.negate();
    }

    // 34. return (xn, xd, y, 1)
    // i.e. (xn / xd, y) is a point on the target curve

    (xn, xd, y, Fq::one())
}

fn iso_map(x: &Fq, y: &Fq) -> (Fq, Fq) {
    fn horners(coefficients: &[[u64; 6]], variable: &Fq) -> Fq {
        let clen = coefficients.len();
        // unwrapping the Ki constants never fails
        let mut res = Fq::from_repr(FqRepr(coefficients[clen - 1])).unwrap();
        // skip the last coefficient since we already used it
        for coeff in coefficients.iter().rev().skip(1) {
            res.mul_assign(variable);
            let coeff = Fq::from_repr(FqRepr(*coeff)).unwrap(); // unwrapping the Ki constants never fails
            res.add_assign(&coeff);
        }
        res
    }
    let mut x_num = horners(&K1, x);
    let x_den = horners(&K2, x);
    x_num.mul_assign(&x_den.inverse().unwrap());
    let mut y_num = horners(&K3, x);
    let y_den = horners(&K4, x);
    y_num.mul_assign(&y_den.inverse().unwrap());
    y_num.mul_assign(y);

    (x_num, y_num)
}

// Implements section 4 of https://eprint.iacr.org/2019/403.pdf
#[allow(clippy::many_single_char_names, clippy::unreadable_literal)]
fn simplified_swu(t: Fq) -> (Fq, Fq, Fq) {
    // this check can be potentially be made faster by replacing the constructions
    // of one amd zero with constants, as done with B_COEFF in Fq of the pairing
    // crate

    let one = Fq::one();
    let zero = Fq::zero();
    let mut minus_one = Fq::one();
    minus_one.negate();
    if t == one || t == zero || t == minus_one {
        return (zero, one, zero);
    }

    // compute N
    let mut t2 = t;
    t2.square(); // t^2
    let mut t4 = t2;
    t4.square(); // t^4
    let mut t4_t2_1 = t4;
    t4_t2_1.sub_assign(&t2);
    t4_t2_1.add_assign(&Fq::one()); // t^4 - t^2 + 1
    let b = Fq::from_repr(FqRepr(E11_B)).unwrap(); // this unwrap can't fail, E11_B is an element of the field
    let mut n = b;
    n.mul_assign(&t4_t2_1); // N = b(t^4 - t^2 + 1)

    // compute D
    let mut t2_t4 = t2;
    t2_t4.sub_assign(&t4); // t^2 - t^4
    let a = Fq::from_repr(FqRepr(E11_A)).unwrap(); // this unwrap can't fail, E11_A is an element of the field
    let mut d = a;
    d.mul_assign(&t2_t4); // D = a(t^2 - t^4) = -a(t^4 - t^2)

    // if d, the denominator of X0(u), is 0 then we set the denominator to -a
    // instead, since -b/a is square in Fq
    if d.is_zero() {
        println!("d was zero!");
        d = a;
        d.negate();
    }

    // compute V and U
    let mut d2 = d;
    d2.square(); // D^2
    let mut v = d2;
    v.mul_assign(&d); // V = D^3
    let mut n3 = n;
    n3.square();
    n3.mul_assign(&n); // N^3
    let mut and2 = a;
    and2.mul_assign(&n);
    and2.mul_assign(&d2); // aND^2
    let mut bv = b;
    bv.mul_assign(&v); // bV = bD^3
    let mut u = n3;
    u.add_assign(&and2);
    u.add_assign(&bv); // U = N^3 + aND^2 + bD^3

    // compute alpha
    let mut v3 = v;
    v3.square();
    v3.mul_assign(&v); // V^3
    let mut uv3p34 = u;
    uv3p34.mul_assign(&v3);
    uv3p34 = uv3p34.pow(&P_MINUS_3_DIV_4); // (UV^3)^((p-3)/4))
    let mut alpha = u;
    alpha.mul_assign(&v);
    alpha.mul_assign(&uv3p34); // alpha = UV(UV^3)^((p-3)/4))

    // We use jacobian projective coordinates when computing the isogeny
    let mut x_proj: Fq;
    let mut y_proj: Fq;
    let z_proj = d;

    // compute alpha^2-V to check if g(X_0(t)) is square in Fq
    // if alpha^2 == V, then g(X_0(t)) is square, so we can pick y = sqrt(g(X_0(t)))
    let mut alpha2v_u = alpha;
    alpha2v_u.square();
    alpha2v_u.mul_assign(&v);
    alpha2v_u.sub_assign(&u);
    if alpha2v_u.is_zero() {
        // g(X_0(t)) is square in Fq
        x_proj = n;
        x_proj.mul_assign(&d); // X = ND
        y_proj = alpha;
        y_proj.mul_assign(&v); // Y = alpha D^3
                               // multiply y by sign(t)
        match sign(t) {
            Sign::Plus => (),
            Sign::Minus => y_proj.negate(),
        }
    } else {
        // g(X_1(t)) is square in Fq
        x_proj = t2;
        x_proj.mul_assign(&n);
        x_proj.mul_assign(&d);
        x_proj.negate(); // X = - t^2 ND
        y_proj = t2;
        y_proj.mul_assign(&t);
        y_proj.mul_assign(&alpha);
        y_proj.mul_assign(&v); // Y = t^3 alpha D^3
    }
    (x_proj, y_proj, z_proj)
}

// Computes the 11-isogeny E1'(Fq): y^2 = x^3 + E11_A x + E11_B
// used for hashing
fn iso_11(x: Fq, y: Fq, z: Fq) -> (Fq, Fq, Fq) {
    // Compute Z^2i for i = 1,...,15
    let mut z_pow_2i: [Fq; 15] = [z; 15];
    z_pow_2i[0].square(); // Z^2
    z_pow_2i[1] = z_pow_2i[0];
    z_pow_2i[1].square(); // Z^4
    let mut z_ = z_pow_2i[1];
    z_.mul_assign(&z_pow_2i[0]);
    z_pow_2i[2] = z_; // Z^6
    z_pow_2i[3] = z_pow_2i[1];
    z_pow_2i[3].square(); // Z^8
    for i in 0..3 {
        // Z^10, Z^12, Z^14,
        z_ = z_pow_2i[3 + i];
        z_.mul_assign(&z_pow_2i[0]);
        z_pow_2i[4 + i] = z_;
    }
    z_pow_2i[7] = z_pow_2i[3];
    z_pow_2i[7].square(); // Z^16
    for i in 0..7 {
        // Z^18, Z^20, Z^22, Z^24, Z^26, Z^28, Z^30,
        z_ = z_pow_2i[7 + i];
        z_.mul_assign(&z_pow_2i[0]);
        z_pow_2i[8 + i] = z_;
    }

    let x_num = horner(&K1, &z_pow_2i, &x);

    let x_den_ = horner(&K2, &z_pow_2i, &x);
    let mut x_den = z_pow_2i[0];
    x_den.mul_assign(&x_den_);

    let y_num_ = horner(&K3, &z_pow_2i, &x);
    let mut y_num = y;
    y_num.mul_assign(&y_num_);

    let y_den_ = horner(&K4, &z_pow_2i, &x);
    let mut y_den = z_pow_2i[0];
    y_den.mul_assign(&z);
    y_den.mul_assign(&y_den_);

    let mut z_jac = x_den;
    z_jac.mul_assign(&y_den);
    let mut x_jac = x_num;
    x_jac.mul_assign(&y_den);
    x_jac.mul_assign(&z_jac);
    let mut z_jac_pow2 = z_jac;
    z_jac_pow2.square();
    let mut y_jac = y_num;
    y_jac.mul_assign(&x_den);
    y_jac.mul_assign(&z_jac_pow2);

    (x_jac, y_jac, z_jac)
}

// Macro for evaluating polynomials using Horner's rule
// Donald E. Knuth. Seminumerical Algorithms, volume 2 of The Art of Computer
// Programming, chapter 4.6.4. Addison-Wesley, 3rd edition, 1997
//
// Evaluates the polynomial with the given coefficients where the i'th
// coefficient has been multiplied by z^(degree - i) where degree is the degree
// of the polynomial.
// z_powers is an array of the even powers of z, ordered [z^2, z^4, ...] The
// polynomial is evaluated in 'variable'. Note: It's a prerequisite that
// Fq::from_repr(FqRepr(coefficient[i])) doesn't produce an error!!!
fn horner(coefficients: &[[u64; 6]], z_powers: &[Fq], variable: &Fq) -> Fq {
    let clen = coefficients.len();
    // unwrapping the Ki constants never fails
    let mut res = Fq::from_repr(FqRepr(coefficients[clen - 1])).unwrap();
    // skip the last coefficient since we already used it
    for (coeff, pow) in coefficients.iter().rev().skip(1).zip(z_powers.iter()) {
        res.mul_assign(variable);
        let mut coeff = Fq::from_repr(FqRepr(*coeff)).unwrap(); // unwrapping the Ki constants never fails
        coeff.mul_assign(pow);
        res.add_assign(&coeff);
    }
    res
}

fn sign(a: Fq) -> Sign {
    if a.into_repr() > FqRepr(P_MINUS_1_DIV_2) {
        Sign::Minus
    } else {
        Sign::Plus
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Sign {
    Minus,
    Plus,
}

#[cfg(test)]
mod tests {
    use super::*;
    use byteorder::{BigEndian, ReadBytesExt};
    use ff::SqrtField;
    use rand::{rngs::StdRng, thread_rng, SeedableRng};

    // testing from_coordinates_unchecked for point at infinity
    #[test]
    fn test_from_coordinates_point_at_infinity() {
        let mut rng: StdRng = SeedableRng::from_rng(thread_rng()).unwrap();

        let expected = G1::zero();
        let z = Fq::zero();
        for _ in 0..1000 {
            let x = Fq::random(&mut rng);
            let y = Fq::random(&mut rng);
            let paf = from_coordinates_unchecked(x, y, z).unwrap();

            assert!(paf == expected);
        }
    }

    // testing from_coordinates_unchecked for random points
    #[test]
    fn test_from_coordinates() {
        let mut rng: StdRng = SeedableRng::from_rng(thread_rng()).unwrap();

        let mut i = 0;
        while i <= 10000 {
            let x = Fq::random(&mut rng);
            let mut y = x;
            y.square();
            y.mul_assign(&x);
            y.add_assign(&Fq::from_repr(FqRepr::from(4)).unwrap());
            match y.sqrt() {
                Some(sqrt) => {
                    let p = from_coordinates_unchecked(x, sqrt, Fq::one()).unwrap();
                    println!("{:?}", p);

                    let encodedpoint = G1Uncompressed::from_affine(p.into_affine());
                    let mut xref = &encodedpoint.as_ref()[0..48];
                    let mut yref = &encodedpoint.as_ref()[48..96];

                    let mut xrepr = FqRepr([0u64; 6]);
                    for digit in xrepr.as_mut().iter_mut().rev() {
                        *digit = xref.read_u64::<BigEndian>().unwrap();
                    }

                    assert!(Fq::from_repr(xrepr).unwrap() == x);

                    let mut yrepr = FqRepr([0u64; 6]);
                    for digit in yrepr.as_mut().iter_mut().rev() {
                        *digit = yref.read_u64::<BigEndian>().unwrap();
                    }

                    println!("y        = {:?}", sqrt);
                    let actual_y = Fq::from_repr(yrepr).unwrap();
                    println!("actual_y = {:?}", actual_y);
                    assert!(actual_y == sqrt);

                    i += 1;
                }
                None => (),
            };
        }
    }

    // See readme for explanation of test cases
    #[test]
    fn test_simplified_swu() {
        fn test_point_at_inf(t: Fq) {
            let (x, y, z) = simplified_swu(t);
            assert_eq!(x, Fq::zero());
            assert_eq!(y, Fq::one());
            assert_eq!(z, Fq::zero());
        }

        let t = Fq::one();
        test_point_at_inf(t);
        let t = Fq::zero();
        test_point_at_inf(t);
        let mut t = Fq::one();
        t.negate();
        test_point_at_inf(t);

        fn test(t: Fq, expected_x: Fq, expected_y: Fq) {
            let (x, y, z) = simplified_swu(t);

            let z_inverse = z.inverse().unwrap();
            let mut z_inverse2 = z_inverse;
            z_inverse2.square();
            let mut z_inverse3 = z_inverse2;
            z_inverse3.mul_assign(&z_inverse);
            let mut x = x;
            x.mul_assign(&z_inverse2);
            let mut y = y;
            y.mul_assign(&z_inverse3);

            // println!("t         : {}", t);
            // println!("x         : {}", x);
            // println!("expected x: {}", expected_x);
            // println!("y         : {}", y);
            // println!("expected y: {}", expected_y);

            assert!(expected_x == x);
            assert!(expected_y == y);
        }

        // t0 = 969b9cc7315e4ac2371da3f9c675eed35b6384ca795d17d8dd8e12da6b833c01c1c6afa860d860060020964873e1264
        // swu(t0) = (
        //      8968f732dbad02a9b2a0d54346a068e6aaf1de330a9d09e816547444f05b17d0df13adc16356f5cbcd2ceaab47d55c4,
        //      11ec46738b7631c340bedd967d35f68873eb067edfbfc9bf725a3823e2850722830ea0c294779dff8ad0b1aed441d0a2,
        //      1,
        // )
        // g(X0(t0))^((p-1)/2) == 1
        // sign(t0) = Plus
        let t0 = Fq::from_repr(FqRepr([
            0x60020964873e1264,
            0x1c1c6afa860d8600,
            0x8dd8e12da6b833c0,
            0x35b6384ca795d17d,
            0x2371da3f9c675eed,
            0x969b9cc7315e4ac,
        ]))
        .unwrap();
        let expected_x = Fq::from_repr(FqRepr([
            0xbcd2ceaab47d55c4,
            0x0df13adc16356f5c,
            0x816547444f05b17d,
            0x6aaf1de330a9d09e,
            0x9b2a0d54346a068e,
            0x8968f732dbad02a,
        ]))
        .unwrap();
        let expected_y = Fq::from_repr(FqRepr([
            0x8ad0b1aed441d0a2,
            0x830ea0c294779dff,
            0x725a3823e2850722,
            0x73eb067edfbfc9bf,
            0x40bedd967d35f688,
            0x11ec46738b7631c3,
        ]))
        .unwrap();
        test(t0, expected_x, expected_y);

        // t1 = 128ca46d7ba7268dda23e2c7bb0bbb1bb32802e3e19c195ecd9109b45f9ffc633e8f682b456faae4067f6840d661620c
        // swu(t1) = (
        //      888d8e87baad9c27bfba7a144a45cb9093da5b2b13be8b430ccb4314efb43a448c4e273b7d14a482e079116e9e85d2d,
        //      cd6450cd98477ae7ed9889b59a528e2d05182042257d2b41fe00315fce28200ea14b5d50f14b7906da0f00e3a3e3b53,
        //      1,
        // )
        // g(X0(t1))^((p-1)/2) == 1
        // sign(t1) = Minus
        let t1 = Fq::from_repr(FqRepr([
            0x067f6840d661620c,
            0x3e8f682b456faae4,
            0xcd9109b45f9ffc63,
            0xb32802e3e19c195e,
            0xda23e2c7bb0bbb1b,
            0x128ca46d7ba7268d,
        ]))
        .unwrap();
        let expected_x = Fq::from_repr(FqRepr([
            0x2e079116e9e85d2d,
            0x48c4e273b7d14a48,
            0x30ccb4314efb43a4,
            0x093da5b2b13be8b4,
            0x7bfba7a144a45cb9,
            0x888d8e87baad9c2,
        ]))
        .unwrap();
        let expected_y = Fq::from_repr(FqRepr([
            0x6da0f00e3a3e3b53,
            0xea14b5d50f14b790,
            0x1fe00315fce28200,
            0xd05182042257d2b4,
            0x7ed9889b59a528e2,
            0xcd6450cd98477ae,
        ]))
        .unwrap();
        test(t1, expected_x, expected_y);

        // t2 = 154ed432ba8d7d846c12f670b2f9ee68703b9270167358189de20ab9ee5fc81c6dd4649aa57b7d28414831e9ea6a1c7c
        // swu(t2) = (
        //      537d5f03530d09edfe5627c6c1d90796505cb2ada43ef113c8ca5b097e3ee74b97f4768c2944bba540b426a6cc9b007,
        //      14e44b5a03cfcc14869b5bbb33801bf4149fa85fe17bcebcac5abeefae61495e1c67182a42ad8600e15bdfb065c828d9,
        //      1,
        // )
        // g(X0(t2))^((p-1)/2) != 1
        // sign(t2) = Minus
        let t2 = Fq::from_repr(FqRepr([
            0x414831e9ea6a1c7c,
            0x6dd4649aa57b7d28,
            0x9de20ab9ee5fc81c,
            0x703b927016735818,
            0x6c12f670b2f9ee68,
            0x154ed432ba8d7d84,
        ]))
        .unwrap();
        let expected_x = Fq::from_repr(FqRepr([
            0x540b426a6cc9b007,
            0xb97f4768c2944bba,
            0x3c8ca5b097e3ee74,
            0x6505cb2ada43ef11,
            0xdfe5627c6c1d9079,
            0x537d5f03530d09e,
        ]))
        .unwrap();
        let expected_y = Fq::from_repr(FqRepr([
            0xe15bdfb065c828d9,
            0x1c67182a42ad8600,
            0xac5abeefae61495e,
            0x149fa85fe17bcebc,
            0x869b5bbb33801bf4,
            0x14e44b5a03cfcc14,
        ]))
        .unwrap();
        test(t2, expected_x, expected_y);

        // t3 = bdb5243c7b6b15dbe4a8fd0901af2cf8a297a516eeaa6ed685f682eb98311989bc64f8b0c846a167575ab9f2cdc376
        // swu(t3) = (
        //      646144588fd3473b16ee9f40dd57aa542f8d90c54684e6f69fdceaaf9728fd88f8455f1f235b2ceae13df3509345c9b,
        //      c89264ed2bf4ee21c08615aaa8389683dec01a1567cd3d3cfbb85cc60d0004f3c6441b5575e005964ef53cc0839aa33,
        //      1,
        //  )
        // g(X0(t3))^((p-1)/2) != 1
        // sign(t3) = Plus
        let t3 = Fq::from_repr(FqRepr([
            0x67575ab9f2cdc376,
            0x89bc64f8b0c846a1,
            0xd685f682eb983119,
            0xf8a297a516eeaa6e,
            0xdbe4a8fd0901af2c,
            0xbdb5243c7b6b15,
        ]))
        .unwrap();
        let expected_x = Fq::from_repr(FqRepr([
            0xae13df3509345c9b,
            0x8f8455f1f235b2ce,
            0x69fdceaaf9728fd8,
            0x42f8d90c54684e6f,
            0xb16ee9f40dd57aa5,
            0x646144588fd3473,
        ]))
        .unwrap();
        let expected_y = Fq::from_repr(FqRepr([
            0x64ef53cc0839aa33,
            0x3c6441b5575e0059,
            0xcfbb85cc60d0004f,
            0x3dec01a1567cd3d3,
            0x1c08615aaa838968,
            0xc89264ed2bf4ee2,
        ]))
        .unwrap();
        test(t3, expected_x, expected_y);
    }

    #[test]
    fn test_sign() {
        assert_eq!(sign(Fq::from_repr(FqRepr::from(1)).unwrap()), Sign::Plus);
        assert_eq!(
            sign(Fq::from_repr(FqRepr(P_MINUS_1_DIV_2)).unwrap()),
            Sign::Plus
        );

        assert_eq!(
            sign(
                Fq::from_repr(FqRepr([
                    0xdcff7fffffffd556,
                    0x0f55ffff58a9ffff,
                    0xb39869507b587b12,
                    0xb23ba5c279c2895f,
                    0x258dd3db21a5d66b,
                    0xd0088f51cbff34d,
                ]))
                .unwrap()
            ),
            Sign::Minus,
            "Sign should be Minus"
        );
    }

    macro_rules! test_isogeny_constants {
        ($test_name:ident, $l:expr) => {
            #[test]
            fn $test_name() {
                for k in $l {
                    let fq_ = Fq::from_repr(FqRepr(*k)).unwrap();
                    let repr = fq_.into_repr();
                    assert!(FqRepr(*k) == repr);
                }
            }
        };
    }

    test_isogeny_constants!(test_k1, &K1);
    test_isogeny_constants!(test_k2, &K2);
    test_isogeny_constants!(test_k3, &K3);
    test_isogeny_constants!(test_k4, &K4);

    macro_rules! test_const {
        ($test_name:ident, $k:expr) => {
            #[test]
            fn $test_name() {
                let fq_ = Fq::from_repr(FqRepr($k)).unwrap();
                let repr = fq_.into_repr();
                assert!(FqRepr($k) == repr);
            }
        };
    }

    test_const!(test_e11_a, E11_A);
    test_const!(test_e11_b, E11_B);
    test_const!(test_p_minus_3_div_4, P_MINUS_3_DIV_4);
    test_const!(test_p_minus_1_div_2, P_MINUS_1_DIV_2);

    #[test]
    fn test_iso11() {
        fn test_isogeny_map(x: Fq, y: Fq, z: Fq, x_expected: Fq, y_expected: Fq, z_expected: Fq) {
            let (x_iso, y_iso, z_iso) = iso_11(x, y, z);

            let z_inverse = z_iso.inverse().unwrap();
            let mut z_inverse2 = z_inverse;
            z_inverse2.square();
            let mut z_inverse3 = z_inverse2;
            z_inverse3.mul_assign(&z_inverse);
            let mut x_iso = x_iso;
            x_iso.mul_assign(&z_inverse2);
            let mut y_iso = y_iso;
            y_iso.mul_assign(&z_inverse3);
            let mut z_iso = z_iso;
            z_iso.mul_assign(&z_inverse);

            assert!(x_expected == x_iso);
            assert!(y_expected == y_iso);
            assert!(z_expected == z_iso);
        }

        // test case 1, affine point on 11-isogeny:
        // x: 231676323333219032364207663160931012408135689080701790049416995747433764605315759399331076266193515570430995049583,
        // y: 1679701275502850236404761224635518110616107305447740765847030766801057551645601784778242705363960817147253464979660
        //
        // resulting affine point on y^2 = x^3 + 4, computed using Sage:
        // x: 2462470316687406725265935944033330307865993658929330879249576046234792668690184598793893670391772666445389495997970
        // y: 1305585544177362738895827194786305935351300563185311476107805270117356948076235166602872188538678439100090683175388
        let x = Fq::from_repr(FqRepr([
            0x68608ed954cbac6f,
            0x65676cfc0f8bfb80,
            0xd70a6c11c45d1c07,
            0x7e8458a01605e048,
            0xff5d19ee27f38db3,
            0x18156d91aae27cc,
        ]))
        .unwrap();
        let y = Fq::from_repr(FqRepr([
            0xddb6c5f190d758cc,
            0x5b3e6c9220fc6a55,
            0xe052aaf632d5ffcf,
            0xc4c8305e904e5446,
            0x70beb5d30c08ee74,
            0xae9ca0eb3be343e,
        ]))
        .unwrap();
        let z = Fq::from_repr(FqRepr([1, 0, 0, 0, 0, 0])).unwrap();
        let x_expected = Fq::from_repr(FqRepr([
            0x579fc665b50b1612,
            0x84f14441fecfb0d8,
            0x7dbc911b151848c7,
            0xd96c755dd2b0a190,
            0xe9fc535fe433bf3b,
            0xfffbdf8b8989a76,
        ]))
        .unwrap();
        let y_expected = Fq::from_repr(FqRepr([
            0x93ab61d6e91b31dc,
            0x1042678018e3cdc7,
            0x9027928a6135e9ad,
            0x00f896c024c7bfcc,
            0xa40980cf7b0ad597,
            0x87b8914dbe39524,
        ]))
        .unwrap();
        let z_expected = Fq::from_repr(FqRepr([1, 0, 0, 0, 0, 0])).unwrap();
        test_isogeny_map(x, y, z, x_expected, y_expected, z_expected);

        // test case 2, affine point on 11-isogeny:
        // x: 200672990962149954463803146802967864720527670550092954518341273224587459684808873511630728943600649771874365573754
        // y: 3771658320633238787764443471835928880231542729858183816905716275784304196017898359904922975462921081984123896844037
        // the x,y,z coordinates below are the jacobian coordinates (x*1000000^2,
        // y*1000000^3, 1000000)
        //
        // resulting affine point on y^2 = x^3 + 4, computed using Sage:
        // x: 751464328052491409370915162588147071834631858446608699879213045826820895244140093535995699583970173378180279055064
        // y: 3766342793094137890660475956436782650146903774069499310802413350809867070503035142752911481430587061848145471128246
        let x = Fq::from_repr(FqRepr([
            0x71ae3b7c4614ac63,
            0x0645eeb5fe9a5714,
            0xc3ce0a80be8d8e34,
            0xd63ecf7124c3f319,
            0x5d8492ffc6f05671,
            0xadc0dda804ea96a,
        ]))
        .unwrap();
        let y = Fq::from_repr(FqRepr([
            0xf4112fd0ccb6f2a7,
            0x7425fc157162679e,
            0x6de4be0915cc3a49,
            0x08239de97826c864,
            0x288f77250bf33de4,
            0x247b456e0a426b8,
        ]))
        .unwrap();
        let z = Fq::from_repr(FqRepr([0xf4240, 0, 0, 0, 0, 0])).unwrap();
        let x_expected = Fq::from_repr(FqRepr([
            0x6a2e445da19e32d8,
            0x686f68e3be0c200e,
            0x66626a48f825305c,
            0x900b2832f3b69833,
            0x48949ce6f9ba8435,
            0x4e1e27e358d07c1,
        ]))
        .unwrap();
        let y_expected = Fq::from_repr(FqRepr([
            0xc9483a6d60dec2b6,
            0x8b8586d8c8ca556f,
            0x09279c0316e87332,
            0x348bd993c7cadb0c,
            0xf5a74b1bb7ab0896,
            0x18786da2bb432953,
        ]))
        .unwrap();
        let z_expected = Fq::from_repr(FqRepr([1, 0, 0, 0, 0, 0])).unwrap();
        test_isogeny_map(x, y, z, x_expected, y_expected, z_expected);
    }

    // Test vectors for expand_message_xmd from
    // https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-10#appendix-K.1
    // DST          = QUUX-V01-CS02-with-expander
    // hash         = SHA256
    // len_in_bytes = 0x80
    #[test]
    fn test_expand_message_xmd() {
        let domain_string = "QUUX-V01-CS02-with-expander";
        let dst = domain_string.as_bytes();
        {
            // msg     =
            // uniform_bytes =  8bcffd1a3cae24cf9cd7ab85628fd111bb17e3739d3b53f89580d217aa79526f
            //                  1708354a76a402d3569d6a9d19ef3de4d0b991e4f54b9f20dcde9b95a66824cb
            //                  df6c1a963a1913d43fd7ac443a02fc5d9d8d77e2071b86ab114a9f34150954a7
            //                  531da568a1ea8c760861c0cde2005afc2c114042ee7b5848f5303f0611cf297f
            
            let msg = "".as_bytes();
            let (a, b, c, d) = expand_message_xmd(msg, dst);

            assert_eq!(a.to_vec(), vec![0x8b, 0xcf, 0xfd, 0x1a, 0x3c, 0xae, 0x24, 0xcf, 0x9c, 0xd7, 0xab, 0x85, 0x62, 0x8f, 0xd1, 0x11, 0xbb, 0x17, 0xe3, 0x73, 0x9d, 0x3b, 0x53, 0xf8, 0x95, 0x80, 0xd2, 0x17, 0xaa, 0x79, 0x52, 0x6f]);
            assert_eq!(b.to_vec(), vec![0x17, 0x08, 0x35, 0x4a, 0x76, 0xa4, 0x02, 0xd3, 0x56, 0x9d, 0x6a, 0x9d, 0x19, 0xef, 0x3d, 0xe4, 0xd0, 0xb9, 0x91, 0xe4, 0xf5, 0x4b, 0x9f, 0x20, 0xdc, 0xde, 0x9b, 0x95, 0xa6, 0x68, 0x24, 0xcb]);
            assert_eq!(c.to_vec(), vec![0xdf, 0x6c, 0x1a, 0x96, 0x3a, 0x19, 0x13, 0xd4, 0x3f, 0xd7, 0xac, 0x44, 0x3a, 0x02, 0xfc, 0x5d, 0x9d, 0x8d, 0x77, 0xe2, 0x07, 0x1b, 0x86, 0xab, 0x11, 0x4a, 0x9f, 0x34, 0x15, 0x09, 0x54, 0xa7]);
            assert_eq!(d.to_vec(), vec![0x53, 0x1d, 0xa5, 0x68, 0xa1, 0xea, 0x8c, 0x76, 0x08, 0x61, 0xc0, 0xcd, 0xe2, 0x00, 0x5a, 0xfc, 0x2c, 0x11, 0x40, 0x42, 0xee, 0x7b, 0x58, 0x48, 0xf5, 0x30, 0x3f, 0x06, 0x11, 0xcf, 0x29, 0x7f]);
        }

        {
            // msg     = abc
            // uniform_bytes =  fe994ec51bdaa821598047b3121c149b364b178606d5e72bfbb713933acc29c1
            //                  86f316baecf7ea22212f2496ef3f785a27e84a40d8b299cec56032763eceeff4
            //                  c61bd1fe65ed81decafff4a31d0198619c0aa0c6c51fca15520789925e813dcf
            //                  d318b542f8799441271f4db9ee3b8092a7a2e8d5b75b73e28fb1ab6b4573c192
            
            let msg = "abc".as_bytes();
            let (a, b, c, d) = expand_message_xmd(msg, dst);

            assert_eq!(a.to_vec(), vec![0xfe, 0x99, 0x4e, 0xc5, 0x1b, 0xda, 0xa8, 0x21, 0x59, 0x80, 0x47, 0xb3, 0x12, 0x1c, 0x14, 0x9b, 0x36, 0x4b, 0x17, 0x86, 0x06, 0xd5, 0xe7, 0x2b, 0xfb, 0xb7, 0x13, 0x93, 0x3a, 0xcc, 0x29, 0xc1]);
            assert_eq!(b.to_vec(), vec![0x86, 0xf3, 0x16, 0xba, 0xec, 0xf7, 0xea, 0x22, 0x21, 0x2f, 0x24, 0x96, 0xef, 0x3f, 0x78, 0x5a, 0x27, 0xe8, 0x4a, 0x40, 0xd8, 0xb2, 0x99, 0xce, 0xc5, 0x60, 0x32, 0x76, 0x3e, 0xce, 0xef, 0xf4]);
            assert_eq!(c.to_vec(), vec![0xc6, 0x1b, 0xd1, 0xfe, 0x65, 0xed, 0x81, 0xde, 0xca, 0xff, 0xf4, 0xa3, 0x1d, 0x01, 0x98, 0x61, 0x9c, 0x0a, 0xa0, 0xc6, 0xc5, 0x1f, 0xca, 0x15, 0x52, 0x07, 0x89, 0x92, 0x5e, 0x81, 0x3d, 0xcf]);
            assert_eq!(d.to_vec(), vec![0xd3, 0x18, 0xb5, 0x42, 0xf8, 0x79, 0x94, 0x41, 0x27, 0x1f, 0x4d, 0xb9, 0xee, 0x3b, 0x80, 0x92, 0xa7, 0xa2, 0xe8, 0xd5, 0xb7, 0x5b, 0x73, 0xe2, 0x8f, 0xb1, 0xab, 0x6b, 0x45, 0x73, 0xc1, 0x92]);
        }

    }

    // Test vectors for BLS12381G1_XMD:SHA-256_SSWU_RO_ from 
    // https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-10#appendix-J.9.1
    // DST = QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_
    #[test]
    fn test_hash_to_curve() {
        // Legend:
            // Steps:
            // 1. u = hash_to_field(msg, 2)
            // 2. Q0 = map_to_curve(u[0])
            // 3. Q1 = map_to_curve(u[1])
            // 4. R = Q0 + Q1              # Point addition
            // 5. P = clear_cofactor(R)
            // 6. return P
        
        let dst = "QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_".as_bytes();
        
        {
            // msg = ""
            let msg = "".as_bytes();
            // P.x     = 052926add2207b76ca4fa57a8734416c8dc95e24501772c814278700eed6d1e4e8cf62d9c09db0fac349612b759e79a1
            // P.y     = 08ba738453bfed09cb546dbb0783dbb3a5f1f566ed67bb6be0e8c67e2e81a4cc68ee29813bb7994998f3eae0c9c6a265
            // u[0]    = 0ba14bd907ad64a016293ee7c2d276b8eae71f25a4b941eece7b0d89f17f75cb3ae5438a614fb61d6835ad59f29c564f
            // u[1]    = 019b9bd7979f12657976de2884c7cce192b82c177c80e0ec604436a7f538d231552f0d96d9f7babe5fa3b19b3ff25ac9
            // Q0.x    = 11a3cce7e1d90975990066b2f2643b9540fa40d6137780df4e753a8054d07580db3b7f1f03396333d4a359d1fe3766fe
            // Q0.y    = 0eeaf6d794e479e270da10fdaf768db4c96b650a74518fc67b04b03927754bac66f3ac720404f339ecdcc028afa091b7
            // Q1.x    = 160003aaf1632b13396dbad518effa00fff532f604de1a7fc2082ff4cb0afa2d63b2c32da1bef2bf6c5ca62dc6b72f9c
            // Q1.y    = 0d8bb2d14e20cf9f6036152ed386d79189415b6d015a20133acb4e019139b94e9c146aaad5817f866c95d609a361735e
    
            // Verify hash to field:
            let (u0, u1) = hash_to_field(msg, dst);
            assert_eq!(u0.into_repr().0, [0x6835ad59f29c564f, 0x3ae5438a614fb61d, 0xce7b0d89f17f75cb, 0xeae71f25a4b941ee, 0x16293ee7c2d276b8, 0x0ba14bd907ad64a0]);
            assert_eq!(u1.into_repr().0, [0x5fa3b19b3ff25ac9, 0x552f0d96d9f7babe, 0x604436a7f538d231, 0x92b82c177c80e0ec, 0x7976de2884c7cce1, 0x019b9bd7979f1265]);
            
            fn is_on_curve(x: Fq, y: Fq) -> bool {
                let mut y2 = y;
                y2.square();
                let mut x3b = x;
                x3b.square();
                x3b.mul_assign(&x);
                x3b.add_assign(&Fq::from_repr(FqRepr::from(4)).unwrap());
                y2 == x3b
            }
            
            fn is_on_curve_iso(x: Fq, y: Fq) -> bool {
                
                let mut y2 = y;
                y2.square();
                
                let mut x3axb = x;
                x3axb.square();
                x3axb.mul_assign(&x);

                let mut ax = Fq::from_repr(FqRepr(E11_A)).unwrap(); // this unwrap can't fail, E11_A is an element of the field
                ax.mul_assign(&x);
                x3axb.add_assign(&ax);

                let b = Fq::from_repr(FqRepr(E11_B)).unwrap(); // this unwrap can't fail, E11_A is an element of the field
                x3axb.add_assign(&b);
                y2 == x3axb
            }
            
            // Verify map to curve:
            let (xn, xd, y, _) = sswu_3mod4(u0);
            
            let mut x = xn;
            x.mul_assign(&xd.inverse().unwrap()); // x = xn/xd

            // let mut encoded_point = G1Uncompressed::empty();
            println!("SSWU:");
            println!("x: {:x?}", x);
            println!("y: {:x?}", y);
            // assert!(is_on_curve_iso(x, y)); // the point is not on the curve
            
            let (xiso, yiso) = iso_map(&x, &y);
            println!("New iso map:");
            println!("x: {:x?}", xiso);
            println!("y: {:x?}", yiso);

            // assert!(is_on_curve(xiso, yiso)); // the point is not on the curve

            println!("Old iso map:");
            let (xi, yi, zi) = iso_11(x, y, Fq::one());
            println!("xi: {:x?}", xi);
            println!("yi: {:x?}", yi);
            println!("zi: {:x?}", zi);
            println!("Old iso map affine:");
            let q = from_coordinates_unchecked(xi, yi, zi).unwrap();
            println!("q: {:#x?}", q);// has the right x
            println!("Old iso map affine negated:");
            let mut neg_q = q;
            neg_q.negate();
            println!("-q: {:#x?}", neg_q);// 

            

            // sswu_3mod4(u1);


            //Verify hash to curve:
            // let res = hash_to_g1(msg);
            // println!("P: {:x?}", res);
            // println!("P: {:x?}", res.into_affine());
            assert_eq!(1,0); // fail to println debug
        }
    }

}
