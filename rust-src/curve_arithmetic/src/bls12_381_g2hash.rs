use ff::{Field, PrimeField, SqrtField};
use group::{CurveProjective, EncodedPoint};
use pairing::bls12_381::{Fq, Fq2, FqRepr, G2Uncompressed, G2};
use sha2::{Digest, Sha256};
use std::{
    convert::TryInto,
    io::{Cursor, Write},
};

/// Implements https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-10#section-3
/// It follows the steps
///    1. u = hash_to_field(msg, 2)
///    2. Q0 = map_to_curve(u[0])
///    3. Q1 = map_to_curve(u[1])
///    4. R = Q0 + Q1              
///    5. P = clear_cofactor(R) = h_eff * R   # Clearing cofactor
///    6. return P,
/// where the choices of hash_to_field, map_to_curve and h_eff are as described in https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-10#section-8.8.2.
pub fn hash_to_curve_g2(msg: &[u8], dst: &[u8]) -> G2 {
    let (u0, u1) = hash_to_field_fq2(msg, dst);

    let q0 = map_to_curve_g2(u0); // This is on E, but not necessarily in G2
    let q1 = map_to_curve_g2(u1); // This is on E, but not necessarily in G2

    let mut r = q0;
    r.add_assign(&q1); // This is on E, but not necessarily in G2
                       // Clearing cofactor with h_eff
    clear_cofactor_g2(r) // This now guaranteed to be in G2
}

/// This is an inefficient method for clearing the cofactor.
/// Corresponds to multiplying by h_eff in https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-10#section-8.8.2
/// A much faster equivalent implementation is available in https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-10#appendix-G.4
fn clear_cofactor_g2(p: G2) -> G2 {
    // h_eff = 0xbc69f08f2ee75b3584c6a0ea91b352888e2a8e9145ad7689986ff031508ffe1329c2f178731db956d82bf015d1212b02ec0ec69d7477c1ae954cbc06689f6a359894c0adebbf6b4e8020005aaa95551
    // it is not possible to use the implementation of mul_assign for G2 directly
    // the implementation of scalar (i.e. Fr) reduces h_eff by |G2|, which gives
    // equivalent results for points in G2, but not general points on the curve
    // |G2| = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
    let h_eff_u64s: [u64; 9] = [
        0x584c6a0ea91b3528,
        0x88e2a8e9145ad768,
        0x9986ff031508ffe1,
        0x329c2f178731db95,
        0x6d82bf015d1212b0,
        0x2ec0ec69d7477c1a,
        0xe954cbc06689f6a3,
        0x59894c0adebbf6b4,
        0xe8020005aaa95551,
    ];
    let mut res = p;
    res.mul_assign(0x0bc69f08f2ee75b3);
    for i in h_eff_u64s.iter() {
        for _ in 0..64 {
            res.double();
        }
        let mut next = p;

        next.mul_assign(*i);
        res.add_assign(&next);
    }
    res
}

fn map_to_curve_g2(u: Fq2) -> G2 {
    let (x, y) = sswu(u);
    let (x, y, z) = iso_map(x, y, Fq2::one());
    from_coordinates_unchecked(x, y, z)
}

/// Implements https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-10#section-6.6.2
/// This is not the optimized version described in https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-10#appendix-G.2.3
#[allow(clippy::many_single_char_names)]
fn sswu(u: Fq2) -> (Fq2, Fq2) {
    let a = Fq2 {
        c0: Fq::zero(),
        c1: Fq::from_repr(FqRepr::from(240)).unwrap(),
    };
    let b = Fq2 {
        c0: Fq::from_repr(FqRepr::from(1012)).unwrap(),
        c1: Fq::from_repr(FqRepr::from(1012)).unwrap(),
    };
    let mut z = Fq2 {
        c0: Fq::from_repr(FqRepr::from(2)).unwrap(),
        c1: Fq::from_repr(FqRepr::from(1)).unwrap(),
    };
    z.negate();

    // Constants:
    // 1.  c1 = -B / A
    let mut c1 = a;
    c1 = c1.inverse().unwrap();
    c1.mul_assign(&b);
    c1.negate();
    // 2.  c2 = -1 / Z
    let mut c2 = z.inverse().unwrap();
    c2.negate();

    // all values above are constants

    // Steps:
    // 1.  tv1 = Z * u^2
    let mut tv1 = u;
    tv1.square();
    tv1.mul_assign(&z);
    // 2.  tv2 = tv1^2
    let mut tv2 = tv1;
    tv2.square();
    // 3.   x1 = tv1 + tv2
    let mut x1 = tv1;
    x1.add_assign(&tv2);
    // 4.   x1 = inv0(x1)
    x1 = match x1.inverse() {
        None => Fq2::zero(),
        Some(x1inv) => x1inv,
    };
    // 5.   e1 = x1 == 0
    let e1 = x1.is_zero();
    // 6.   x1 = x1 + 1
    x1.add_assign(&Fq2::one());
    // 7.   x1 = CMOV(x1, c2, e1)    # If (tv1 + tv2) == 0, set x1 = -1 / Z
    if e1 {
        x1 = c2;
    }
    // 8.   x1 = x1 * c1      # x1 = (-B / A) * (1 + (1 / (Z^2 * u^4 + Z * u^2)))
    x1.mul_assign(&c1);
    // 9.  gx1 = x1^2
    let mut gx1 = x1;
    gx1.square();
    // 10. gx1 = gx1 + A
    gx1.add_assign(&a);
    // 11. gx1 = gx1 * x1
    gx1.mul_assign(&x1);
    // 12. gx1 = gx1 + B             # gx1 = g(x1) = x1^3 + A * x1 + B
    gx1.add_assign(&b);
    // 13.  x2 = tv1 * x1            # x2 = Z * u^2 * x1
    let mut x2 = tv1;
    x2.mul_assign(&x1);
    // 14. tv2 = tv1 * tv2
    tv2.mul_assign(&tv1);
    // 15. gx2 = gx1 * tv2           # gx2 = (Z * u^2)^3 * gx1
    let mut gx2 = gx1;
    gx2.mul_assign(&tv2);
    // 16.  e2 = is_square(gx1)
    let e2 = gx1.sqrt().is_some();
    // 17.   x = CMOV(x2, x1, e2)    # If is_square(gx1), x = x1, else x = x2
    // 18.  y2 = CMOV(gx2, gx1, e2)  # If is_square(gx1), y2 = gx1, else y2 = gx2
    let mut x = x2;
    let mut y2 = gx2;
    if e2 {
        x = x1;
        y2 = gx1;
    }
    // 19.   y = sqrt(y2)
    let mut y = y2.sqrt().unwrap();
    // 20.  e3 = sgn0(u) == sgn0(y)  # Fix sign of y
    let e3 = sgn0(u) == sgn0(y);
    // 21.   y = CMOV(-y, y, e3)
    if !e3 {
        y.negate();
    }
    // 22. return (x, y)
    (x, y)
}

/// The function sgn0 given at https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-10#section-4.1
fn sgn0(x: Fq2) -> u64 {
    let sign_0 = x.c0.into_repr().0[0] % 2;
    let zero_0 = x.c0.is_zero();
    let sign_1 = x.c1.into_repr().0[0] % 2;
    sign_0 | (zero_0 as u64 & sign_1)
}

/// Implements https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-10#section-5.4.1
/// len_in_bytes is fixed to 256
/// Domain separation string (dst) should be at most 255 bytes
fn expand_message_xmd(msg: &[u8], dst: &[u8]) -> [[u8; 32]; 8] {
    // DST_prime = DST || I2OSP(len(DST), 1)
    let mut dst_prime = dst.to_vec();
    dst_prime.push(dst.len().try_into().unwrap()); // panics if dst is more than 255 bytes

    // b_0 = H(msg_prime), msg_prime = Z_pad || msg || l_i_b_str || I2OSP(0, 1) ||
    // DST_prime
    let mut h = Sha256::new();
    h.update(vec![0; 64]); // z_pad = I2OSP(0, 64), 64 is the input block size of Sha265
    h.update(msg);
    h.update(vec![1, 0]); // l_i_b_str = I2OSP(256, 2)
    h.update([0u8]);
    h.update(&dst_prime);
    let mut b_0: [u8; 32] = [0u8; 32];
    b_0.copy_from_slice(h.finalize().as_slice());

    // b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
    let mut h = Sha256::new();
    h.update(b_0);
    h.update([1u8]);
    h.update(&dst_prime);

    let mut b = [[0u8; 32]; 8]; // b[i] corresponds to b_i+1 in specification.
    b[0].copy_from_slice(h.finalize().as_slice());

    // compute remaining uniform bytes
    for i in 1u8..8 {
        // b_i = H(strxor(b_0, b_i-1)  || I2OSP(i, 1) || DST_prime)
        let mut h = Sha256::new();
        let xor: Vec<u8> = b_0
            .iter()
            .zip(b[i as usize - 1].iter())
            .map(|(x, y)| x ^ y)
            .collect();
        h.update(xor);
        h.update([i + 1]); // offset as standard drops b_0 and returns index b_1-b_8
        h.update(&dst_prime);
        b[i as usize].copy_from_slice(h.finalize().as_slice());
    }

    b
}

/// Implements https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-10#section-3
/// with the choice of expand_message being expand_message_xmd, as specified in
/// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-10#section-8.8.2.
fn hash_to_field_fq2(msg: &[u8], dst: &[u8]) -> (Fq2, Fq2) {
    let b = expand_message_xmd(msg, dst);
    let u0 = Fq2 {
        c0: fq_from_bytes(&b[0], &b[1]),
        c1: fq_from_bytes(&b[2], &b[3]),
    };
    let u1 = Fq2 {
        c0: fq_from_bytes(&b[4], &b[5]),
        c1: fq_from_bytes(&b[6], &b[7]),
    };
    (u0, u1)
}

// Interpret input as integers (big endian)
// Return (left*2^256 + right) as Fq
fn fq_from_bytes(left_bytes: &[u8; 32], right_bytes: &[u8; 32]) -> Fq {
    fn le_u64s_from_be_bytes(bytes: &[u8; 32]) -> Fq {
        let mut digits = [0u64; 6];

        for (place, chunk) in digits.iter_mut().zip(bytes.chunks(8).rev()) {
            *place = u64::from_be_bytes(chunk.try_into().expect("Chunk Sie is always 8"))
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

/// Computes the 3-isogeny map for G2, specified in
/// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-10#appendix-E.3
fn iso_map(x: Fq2, y: Fq2, z: Fq2) -> (Fq2, Fq2, Fq2) {
    // Compute Z^2i for i = 1,...,15
    let mut z_pow_2i: [Fq2; 15] = [z; 15];
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

// Constants for the 3-isogeny map
const K1: [[[u64; 6]; 2]; 4] = [
    [
        [
            0x6238aaaaaaaa97d6,
            0x5c2638e343d9c71c,
            0x88b58423c50ae15d,
            0x32c52d39fd3a042a,
            0xbb5b7a9a47d7ed85,
            0x5c759507e8e333e,
        ],
        [
            0x6238aaaaaaaa97d6,
            0x5c2638e343d9c71c,
            0x88b58423c50ae15d,
            0x32c52d39fd3a042a,
            0xbb5b7a9a47d7ed85,
            0x5c759507e8e333e,
        ],
    ],
    [[0, 0, 0, 0, 0, 0], [
        0x26a9ffffffffc71a,
        0x1472aaa9cb8d5555,
        0x9a208c6b4f20a418,
        0x984f87adf7ae0c7f,
        0x32126fced787c88f,
        0x11560bf17baa99bc,
    ]],
    [
        [
            0x26a9ffffffffc71e,
            0x1472aaa9cb8d5555,
            0x9a208c6b4f20a418,
            0x984f87adf7ae0c7f,
            0x32126fced787c88f,
            0x11560bf17baa99bc,
        ],
        [
            0x9354ffffffffe38d,
            0x0a395554e5c6aaaa,
            0xcd104635a790520c,
            0xcc27c3d6fbd7063f,
            0x190937e76bc3e447,
            0x8ab05f8bdd54cde,
        ],
    ],
    [
        [
            0x88e2aaaaaaaa5ed1,
            0x7098e38d0f671c71,
            0x22d6108f142b8575,
            0xcb14b4e7f4e810aa,
            0xed6dea691f5fb614,
            0x171d6541fa38ccfa,
        ],
        [0, 0, 0, 0, 0, 0],
    ],
];

const K2: [[[u64; 6]; 2]; 3] = [
    [[0, 0, 0, 0, 0, 0], [
        0xb9feffffffffaa63,
        0x1eabfffeb153ffff,
        0x6730d2a0f6b0f624,
        0x64774b84f38512bf,
        0x4b1ba7b6434bacd7,
        0x1a0111ea397fe69a,
    ]],
    [[0xc, 0, 0, 0, 0, 0], [
        0xb9feffffffffaa9f,
        0x1eabfffeb153ffff,
        0x6730d2a0f6b0f624,
        0x64774b84f38512bf,
        0x4b1ba7b6434bacd7,
        0x1a0111ea397fe69a,
    ]],
    [[1, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0]],
];

const K3: [[[u64; 6]; 2]; 4] = [
    [
        [
            0x12cfc71c71c6d706,
            0xfc8c25ebf8c92f68,
            0xf54439d87d27e500,
            0x0f7da5d4a07f649b,
            0x59a4c18b076d1193,
            0x1530477c7ab4113b,
        ],
        [
            0x12cfc71c71c6d706,
            0xfc8c25ebf8c92f68,
            0xf54439d87d27e500,
            0x0f7da5d4a07f649b,
            0x59a4c18b076d1193,
            0x1530477c7ab4113b,
        ],
    ],
    [[0, 0, 0, 0, 0, 0], [
        0x6238aaaaaaaa97be,
        0x5c2638e343d9c71c,
        0x88b58423c50ae15d,
        0x32c52d39fd3a042a,
        0xbb5b7a9a47d7ed85,
        0x5c759507e8e333e,
    ]],
    [
        [
            0x26a9ffffffffc71c,
            0x1472aaa9cb8d5555,
            0x9a208c6b4f20a418,
            0x984f87adf7ae0c7f,
            0x32126fced787c88f,
            0x11560bf17baa99bc,
        ],
        [
            0x9354ffffffffe38f,
            0x0a395554e5c6aaaa,
            0xcd104635a790520c,
            0xcc27c3d6fbd7063f,
            0x190937e76bc3e447,
            0x8ab05f8bdd54cde,
        ],
    ],
    [
        [
            0xe1b371c71c718b10,
            0x4e79097a56dc4bd9,
            0xb0e977c69aa27452,
            0x761b0f37a1e26286,
            0xfbf7043de3811ad0,
            0x124c9ad43b6cf79b,
        ],
        [0, 0, 0, 0, 0, 0],
    ],
];

const K4: [[[u64; 6]; 2]; 4] = [
    [
        [
            0xb9feffffffffa8fb,
            0x1eabfffeb153ffff,
            0x6730d2a0f6b0f624,
            0x64774b84f38512bf,
            0x4b1ba7b6434bacd7,
            0x1a0111ea397fe69a,
        ],
        [
            0xb9feffffffffa8fb,
            0x1eabfffeb153ffff,
            0x6730d2a0f6b0f624,
            0x64774b84f38512bf,
            0x4b1ba7b6434bacd7,
            0x1a0111ea397fe69a,
        ],
    ],
    [[0, 0, 0, 0, 0, 0], [
        0xb9feffffffffa9d3,
        0x1eabfffeb153ffff,
        0x6730d2a0f6b0f624,
        0x64774b84f38512bf,
        0x4b1ba7b6434bacd7,
        0x1a0111ea397fe69a,
    ]],
    [[0x12, 0x0, 0x0, 0x0, 0x0, 0x0], [
        0xb9feffffffffaa99,
        0x1eabfffeb153ffff,
        0x6730d2a0f6b0f624,
        0x64774b84f38512bf,
        0x4b1ba7b6434bacd7,
        0x1a0111ea397fe69a,
    ]],
    [[1, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0]],
];

fn horner(coefficients: &[[[u64; 6]; 2]], z_powers: &[Fq2], variable: &Fq2) -> Fq2 {
    fn fq2_from_u64s(u64s: [[u64; 6]; 2]) -> Fq2 {
        // unwrapping the Ki constants never fails:
        Fq2 {
            c0: Fq::from_repr(FqRepr(u64s[0])).unwrap(),
            c1: Fq::from_repr(FqRepr(u64s[1])).unwrap(),
        }
    }

    let clen = coefficients.len();
    let mut res = fq2_from_u64s(coefficients[clen - 1]);
    // skip the last coefficient since we already used it
    for (coeff, pow) in coefficients.iter().rev().skip(1).zip(z_powers.iter()) {
        res.mul_assign(variable);
        let mut coeff = fq2_from_u64s(*coeff);
        coeff.mul_assign(pow);
        res.add_assign(&coeff);
    }
    res
}

// Returns a point on E1 with coordinates x,y,z.
// CAREFUL! This point is NOT guaranteed to be in the correct order subgroup
// To get the point into the correct order subgroup, clear cofactor.
#[inline]
fn from_coordinates_unchecked(x: Fq2, y: Fq2, z: Fq2) -> G2 {
    if z.is_zero() {
        G2::zero()
    } else {
        let z_inv = z.inverse().unwrap();
        let mut z_inv2 = z_inv;
        z_inv2.square();
        let mut p_x = x;
        p_x.mul_assign(&z_inv2);
        let mut p_y = y;
        p_y.mul_assign(&z_inv);
        p_y.mul_assign(&z_inv2);

        let mut uncompress_point = G2Uncompressed::empty();
        let mut cursor = Cursor::new(uncompress_point.as_mut());

        for digit in p_x.c1.into_repr().as_ref().iter().rev() {
            cursor
                .write_all(&digit.to_be_bytes())
                .expect("This write will always succeed.");
        }
        for digit in p_x.c0.into_repr().as_ref().iter().rev() {
            cursor
                .write_all(&digit.to_be_bytes())
                .expect("This write will always succeed.");
        }
        for digit in p_y.c1.into_repr().as_ref().iter().rev() {
            cursor
                .write_all(&digit.to_be_bytes())
                .expect("This write will always succeed.");
        }
        for digit in p_y.c0.into_repr().as_ref().iter().rev() {
            cursor
                .write_all(&digit.to_be_bytes())
                .expect("This write will always succeed.");
        }

        // The below is safe, since xiso, yiso, z are in Fq.
        // The into_affine_unchecked() used below can fail if
        // at least one of the bits representing 2^5, 2^6 or 2^7 in the first entry of
        // the `uncompress_point` are set, but this will not happen.
        // c1 lies in Fq, where
        // q = 4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787,
        // and since 27 * 2^(47*8) > q, the first entry of
        // `uncompress_point` will always be < 27 < 2^5, since this entry
        // represents the number of 2^(47*8)'s.
        let res = uncompress_point.into_affine_unchecked();
        G2::from(res.expect("Should not happen, since input coordinates are in Fq2."))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_to_field_fq2() {
        // https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-10#appendix-J.10.1
        let dst = b"QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_";

        {
            //    msg     =
            //    u[0]    = 03dbc2cce174e91ba93cbb08f26b917f98194a2ea08d1cce75b2b9
            //              cc9f21689d80bd79b594a613d0a68eb807dfdc1cf8
            //        + I * 05a2acec64114845711a54199ea339abd125ba38253b70a92c876d
            //              f10598bd1986b739cad67961eb94f7076511b3b39a
            //    u[1]    = 02f99798e8a5acdeed60d7e18e9120521ba1f47ec090984662846b
            //              c825de191b5b7641148c0dbc237726a334473eee94
            //        + I * 145a81e418d4010cc027a68f14391b30074e89e60ee7a22f87217b
            //              2f6eb0c4b94c9115b436e6fa4607e95a98de30a435
            let msg = b"";
            let (u0, u1) = hash_to_field_fq2(msg, dst);
            assert_eq!(
                u0,
                Fq2{
                c0: Fq::from_str("593868448310005448561172252387029516360409945786457439875974315031640021389835649561235021338510064922970633805048").unwrap(),
                c1: Fq::from_str("867375309489067512797459860887365951877054038763818448057326190302701649888849997836339069389536967202878289851290").unwrap()}
            );
            assert_eq!(
                u1,
                Fq2{
                c0: Fq::from_str("457889704519948843474026022562641969443315715595459159112874498082953431971323809145630315884223143822925947137684").unwrap(),
                c1: Fq::from_str("3132697209754082586339430915081913810572071485832539443682634025529375380328136128542015469873094481703191673087029").unwrap()}
            );
        }

        {
            //    msg     = abc
            // u[0]    = 15f7c0aa8f6b296ab5ff9c2c7581ade64f4ee6f1bf18f55179ff44
            //         a2cf355fa53dd2a2158c5ecb17d7c52f63e7195771
            //   + I * 01c8067bf4c0ba709aa8b9abc3d1cef589a4758e09ef53732d670f
            //         d8739a7274e111ba2fcaa71b3d33df2a3a0c8529dd
            // u[1]    = 187111d5e088b6b9acfdfad078c4dacf72dcd17ca17c82be35e79f
            //         8c372a693f60a033b461d81b025864a0ad051a06e4
            //   + I * 08b852331c96ed983e497ebc6dee9b75e373d923b729194af8e72a
            //         051ea586f3538a6ebb1e80881a082fa2b24df9f566
            let msg = b"abc";
            let (u0, u1) = hash_to_field_fq2(msg, dst);
            assert_eq!(
                u0,
                Fq2{
                c0: Fq::from_str("3381151350286428005095780827831774583653641216459357823974407145557165174365389989442078766443621078367363453769585").unwrap(),
                c1: Fq::from_str("274174695370444263853418070745339731640467919355184108253716879519695397069963034977795744692362177212201505728989").unwrap()}
            );
            assert_eq!(
                u1,
                Fq2{
                c0: Fq::from_str("3761918608077574755256083960277010506684793456226386707192711779006489497410866269311252402421709839991039401264868").unwrap(),
                c1: Fq::from_str("1342131492846344403298252211066711749849099599627623100864413228392326132610002371925674088601653350525231531947366").unwrap()}
            );
        }
    }

    #[test]
    fn test_hash_to_curve_g2() {
        // Test vectors are from https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-10#appendix-J.10.1
        let dst = b"QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_";
        {
            //    msg     =
            //    P.x     =
            // 0141ebfbdca40eb85b87142e130ab689c673cf60f1a3e98d69335266f30d9b8d4ac44c1038e9dcdd5393faf5c41fb78a
            //        + I *
            // 05cb8437535e20ecffaef7752baddf98034139c38452458baeefab379ba13dff5bf5dd71b72418717047f5b0f37da03d
            //    P.y     =
            // 0503921d7f6a12805e72940b963c0cf3471c7b2a524950ca195d11062ee75ec076daf2d4bc358c4b190c0c98064fdd92
            //        + I *
            // 12424ac32561493f3fe3c260708a12b7c620e7be00099a974e259ddc7d1f6395c3c811cdd19f1e8dbf3e9ecfdcbab8d6
            let msg = b"";
            let p_should_be = from_coordinates_unchecked(
                Fq2{
                    c0: Fq::from_str("193548053368451749411421515628510806626565736652086807419354395577367693778571452628423727082668900187036482254730").unwrap(),
                    c1: Fq::from_str("891930009643099423308102777951250899694559203647724988361022851024990473423938537113948850338098230396747396259901").unwrap()
                },
                Fq2{
                    c0: Fq::from_str("771717272055834152378281705972671257005357145478800908373659404991537354153455452961747174765859335819766715637138").unwrap(),
                    c1: Fq::from_str("2810310118582126634041133454180705304393079139103252956502404531123692847658283858246402311867775854528543237781718").unwrap()
                },
                Fq2::one()
            );
            let p = hash_to_curve_g2(msg, dst);
            assert_eq!(p, p_should_be);
        }
        {
            // msg     = abc
            // P.x     = 02c2d18e033b960562aae3cab37a27ce00d80ccd5ba4b7fe0e7a210245129dbec7780ccc7954725f4168aff2787776e6
            //     + I * 139cddbccdc5e91b9623efd38c49f81a6f83f175e80b06fc374de9eb4b41dfe4ca3a230ed250fbe3a2acf73a41177fd8
            // P.y     = 1787327b68159716a37440985269cf584bcb1e621d3a7202be6ea05c4cfe244aeb197642555a0645fb87bf7466b2ba48
            //     + I * 00aa65dae3c8d732d10ecd2c50f8a1baf3001578f71c694e03866e9f3d49ac1e1ce70dd94a733534f106d4cec0eddd16
            let msg = b"abc";
            let p_should_be = from_coordinates_unchecked(
                Fq2{
                    c0: Fq::from_str("424958340463073975547762735517193206833255107941790909009827635556634414746056077714431786321247871628515967727334").unwrap(),
                    c1: Fq::from_str("3018679803970127877262826393814472528557413504329194740495363852840690589001358162447917674089074634504498585239512").unwrap()
                },
                Fq2{
                    c0: Fq::from_str("3621308185128395459888995526527127556614768604472132176060423302734876099689739385100475320409412954617897892887112").unwrap(),
                    c1: Fq::from_str("102447784096837908713257069727879782642075240724579670654226801345708452018676587771714457671432122751958633012502").unwrap()
                },
                Fq2::one()
            );
            let p = hash_to_curve_g2(msg, dst);
            assert_eq!(p, p_should_be);
        }
        {
            // msg     = abcdef0123456789
            // P.x     = 121982811d2491fde9ba7ed31ef9ca474f0e1501297f68c298e9f4c0028add35aea8bb83d53c08cfc007c1e005723cd0
            //     + I * 190d119345b94fbd15497bcba94ecf7db2cbfd1e1fe7da034d26cbba169fb3968288b3fafb265f9ebd380512a71c3f2c
            // P.y     = 05571a0f8d3c08d094576981f4a3b8eda0a8e771fcdcc8ecceaf1356a6acf17574518acb506e435b639353c2e14827c8
            //     + I * 0bb5e7572275c567462d91807de765611490205a941a5a6af3b1691bfe596c31225d3aabdf15faff860cb4ef17c7c3be
            let msg = b"abcdef0123456789";
            let p_should_be = from_coordinates_unchecked(
                Fq2{
                    c0: Fq::from_str("2785790728239146617702443308248535381016035748520698399690132325213972292102741627498014391457605127656937478044880").unwrap(),
                    c1: Fq::from_str("3855709393631831880910167818276435187147963371126198799654803099743427431977934703201153169947378798970358200024876").unwrap()
                },
                Fq2{
                    c0: Fq::from_str("821938378705205565995357931232097952117504537366318395539093959918654729488074273868834599496909844419980823111624").unwrap(),
                    c1: Fq::from_str("1802420335575779950982935580421454302087567926385222707947527353462942499437987207287862072369052390195154530059198").unwrap()
                },
                Fq2::one()
            );
            let p = hash_to_curve_g2(msg, dst);
            assert_eq!(p, p_should_be);
        }
        {
            // msg     = q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
            // P.x     = 19a84dd7248a1066f737cc34502ee5555bd3c19f2ecdb3c7d9e24dc65d4e25e50d83f0f77105e955d78f4762d33c17da
            //     + I * 0934aba516a52d8ae479939a91998299c76d39cc0c035cd18813bec433f587e2d7a4fef038260eef0cef4d02aae3eb91
            // P.y     = 14f81cd421617428bc3b9fe25afbb751d934a00493524bc4e065635b0555084dd54679df1536101b2c979c0152d09192
            //     + I * 09bcccfa036b4847c9950780733633f13619994394c23ff0b32fa6b795844f4a0673e20282d07bc69641cee04f5e5662
            let msg = b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
            let p_should_be = from_coordinates_unchecked(
                Fq2{
                    c0: Fq::from_str("3949041098513688455491231180749724794697192943196730030853285011755806989731870696216017360514887069032515603535834").unwrap(),
                    c1: Fq::from_str("1416893694506131976809002935212216317132941942570763849323065381335907430566747765697423320407614734575486820936593").unwrap()
                },
                Fq2{
                    c0: Fq::from_str("3227453710863835032992962605851449401391399355135442728893790186263669279022343042444878900124369614767241382891922").unwrap(),
                    c1: Fq::from_str("1498738834073759871886466122933996764471889514532827927202777922460876335493588931070034160657995151627624577390178").unwrap()
                },
                Fq2::one()
            );
            let p = hash_to_curve_g2(msg, dst);
            assert_eq!(p, p_should_be);
        }
        {
            //   msg     =
            // a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
            //   P.x     =
            // 01a6ba2f9a11fa5598b2d8ace0fbe0a0eacb65deceb476fbbcb64fd24557c2f4b18ecfc5663e54ae16a84f5ab7f62534
            //       + I *
            // 11fca2ff525572795a801eed17eb12785887c7b63fb77a42be46ce4a34131d71f7a73e95fee3f812aea3de78b4d01569
            //   P.y     =
            // 0b6798718c8aed24bc19cb27f866f1c9effcdbf92397ad6448b5c9db90d2b9da6cbabf48adc1adf59a1a28344e79d57e
            //       + I *
            // 03a47f8e6d1763ba0cad63d6114c0accbef65707825a511b251a660a9b3994249ae4e63fac38b23da0c398689ee2ab52
            let msg = b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
            let p_should_be = from_coordinates_unchecked(
                Fq2{
                    c0: Fq::from_str("254155017921606149907129844368549510385368618440139550318910532874259603395336903946742408725761795820224536519988").unwrap(),
                    c1: Fq::from_str("2768431459296730426779166218544149791601585986233130583011501727704972362141149700714785450629498506208393873593705").unwrap()
                },
                Fq2{
                    c0: Fq::from_str("1755339344744337457318565116062025669984750617937721245220711425551575490663761638802010265668157125441634554205566").unwrap(),
                    c1: Fq::from_str("560643043433789571968941329642646582974304556331567393300563909451776257854214387388500126524984624222885267024722").unwrap()
                },
                Fq2::one()
            );
            let p = hash_to_curve_g2(msg, dst);
            assert_eq!(p, p_should_be);
        }
    }
}
