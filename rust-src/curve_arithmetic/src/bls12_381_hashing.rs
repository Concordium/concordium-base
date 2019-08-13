use crate::curve_arithmetic::FieldDecodingError;
use byteorder::{BigEndian, ReadBytesExt};
use bytes::IntoBuf;
use pairing::{
    bls12_381::{Fq, FqRepr},
    PrimeField,
};
use sha2::{Digest, Sha512};
use std::io::Cursor;

pub const E11_B: [u64; 6] = [
    0xd1cc48e98e172be0,
    0x5a23215a316ceaa5,
    0xa0b9c14fcef35ef5,
    0x2016c1f0f24f4070,
    0x018b12e8753eee3b,
    0x12e2908d11688030,
];

pub const E11_A: [u64; 6] = [
    0x5cf428082d584c1d,
    0x98936f8da0e0f97f,
    0xd8e8981aefd881ac,
    0xb0ea985383ee66a8,
    0x3d693a02c96d4982,
    0x00144698a3b8e943,
];

pub const K1: [[u64; 6]; 12] = [
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

pub const K2: [[u64; 6]; 11] = [
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

pub const K3: [[u64; 6]; 16] = [
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

pub const K4: [[u64; 6]; 16] = [
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

pub fn hash_bytes_to_fq(b: &[u8]) -> Fq {
    let mut h = Sha512::new();
    let mut hash: [u8; 64] = [0u8; 64];
    h.input(b);
    hash.copy_from_slice(h.result().as_slice());
    let mut buffer = hash.into_buf();

    match decode_hash_to_fq(&mut buffer) {
        Ok(fq) => fq,
        Err(_) => hash_bytes_to_fq(&hash),
    }
}

fn decode_hash_to_fq(bytes: &mut Cursor<&[u8]>) -> Result<Fq, FieldDecodingError> {
    let mut fqrepr: FqRepr = FqRepr([0u64; 6]);
    let mut i = true;
    for digit in fqrepr.as_mut().iter_mut().rev() {
        *digit = bytes
            .read_u64::<BigEndian>()
            .map_err(|_| FieldDecodingError::NotFieldElement)?;
        if i {
            *digit &= !(1 << 63);
            i = false;
        }
    }
    match Fq::from_repr(fqrepr) {
        Ok(fq) => Ok(fq),
        Err(_) => Err(FieldDecodingError::NotFieldElement),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::{Fq, FqRepr};

    fn fq_from_u64arr(arr: [u64; 6]) -> Fq {
        Fq::from_repr(FqRepr(arr)).unwrap()
    }

    macro_rules! test_k {
        ($test_name:ident, $l:expr) => {
            #[test]
            fn $test_name() {
                for k in $l {
                    let _ = fq_from_u64arr(*k);
                }
            }
        };
    }

    test_k!(test_k1, &K1);
    test_k!(test_k2, &K2);
    test_k!(test_k3, &K3);
    test_k!(test_k4, &K4);

    macro_rules! test_const {
        ($test_name:ident, $k:expr) => {
            #[test]
            fn $test_name() {
                let _ = fq_from_u64arr($k);
            }
        };
    }

    test_const!(test_e11_a, E11_A);
    test_const!(test_e11_b, E11_B);
}
