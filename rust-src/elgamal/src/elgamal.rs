use crate::{cipher::*, public::*, secret::*};
use rand::*;
use rayon::prelude::*;

use crypto_common::*;
use curve_arithmetic::{Curve, Value};

use std::io::Cursor;

// FIXME: This is a bad implementation. There is no need to involve
// serialization. endianness sensetive
pub fn value_to_chunks<C: Curve>(val: &C::Scalar, chunk_size: usize) -> Vec<Value<C>> {
    assert!(chunk_size <= C::SCALAR_LENGTH);
    assert_eq!(C::SCALAR_LENGTH % chunk_size, 0);
    let n = C::SCALAR_LENGTH / chunk_size;
    let scalar_bytes = to_bytes(val);
    let mut scalar_chunks = Vec::with_capacity(n);
    for i in (0..scalar_bytes.len()).step_by(chunk_size) {
        let mut buf = vec![0u8; C::SCALAR_LENGTH - chunk_size];
        buf.extend_from_slice(&scalar_bytes[i..(i + chunk_size)]);
        let scalar = (&mut Cursor::new(&mut buf)).get().unwrap();
        scalar_chunks.push(Value::new(scalar));
    }
    scalar_chunks
}

// FIXME: This is a bad implementation. There is no need to involve
// serialization.
// There is also no need to pass in a vector.
pub fn chunks_to_value<C: Curve>(chunks: Vec<Value<C>>) -> Value<C> {
    let number_of_chunks = chunks.len();
    assert!(number_of_chunks <= C::SCALAR_LENGTH);
    assert_eq!(C::SCALAR_LENGTH % number_of_chunks, 0);
    let chunk_size = C::SCALAR_LENGTH / number_of_chunks;
    let assertion_vec = vec![0u8; C::SCALAR_LENGTH - chunk_size];
    let mut scalar_bytes: Vec<u8> = Vec::with_capacity(C::SCALAR_LENGTH);
    for chunk in chunks.iter() {
        let chunk_bytes = to_bytes(chunk);
        assert_eq!(
            &chunk_bytes[..C::SCALAR_LENGTH - chunk_size],
            assertion_vec.as_slice()
        );
        scalar_bytes.extend_from_slice(&chunk_bytes[C::SCALAR_LENGTH - chunk_size..]);
    }
    Value::new((&mut Cursor::new(&mut scalar_bytes)).get().unwrap())
}

pub fn encrypt_in_chunks<C: Curve, R: Rng>(
    pk: &PublicKey<C>,
    val: &Value<C>,
    chunk_size: usize,
    csprng: &mut R,
) -> Vec<Cipher<C>> {
    let chunks = value_to_chunks::<C>(val, chunk_size);
    pk.encrypt_exponent_vec(csprng, &chunks.as_slice())
}

pub fn encrypt_in_chunks_given_generator<C: Curve, R: Rng>(
    pk: &PublicKey<C>,
    val: &Value<C>,
    chunk_size: usize,
    generator: &C,
    csprng: &mut R,
) -> Vec<Cipher<C>> {
    let chunks = value_to_chunks::<C>(val, chunk_size);
    pk.encrypt_exponent_vec_given_generator(csprng, &chunks.as_slice(), generator)
}

pub fn decrypt_from_chunks<C: Curve>(sk: &SecretKey<C>, cipher: &[Cipher<C>]) -> Value<C> {
    let scalars = cipher.iter().map(|c| sk.decrypt_exponent(c));
    chunks_to_value::<C>(scalars.collect())
}

pub fn decrypt_from_chunks_given_generator<C: Curve>(
    sk: &SecretKey<C>,
    cipher: &[Cipher<C>],
    generator: &C,
    m: usize,
    k: usize,
) -> Value<C> {
    let (table, generator_m_inverse) = baby_step_giant_step_table(generator, m); // Possibly the table could be given as a paramater instead
    let scalars = cipher
        .iter()
        .map(|c| sk.decrypt_exponent_given_generator(c, &generator_m_inverse, m, k, &table));
    chunks_to_value::<C>(scalars.collect())
}

pub fn encrypt_u64_bitwise_iter<C: Curve>(
    pk: PublicKey<C>,
    e: u64,
) -> impl IndexedParallelIterator<Item = Cipher<C>> {
    (0u8..64).into_par_iter().map(move |i| {
        let mut csprng = thread_rng();
        pk.hide_binary_exp(&C::generate_scalar(&mut csprng), (e & (1 << i)) != 0)
    })
}

pub fn encrypt_u64_bitwise<C: Curve>(pk: PublicKey<C>, e: u64) -> Vec<Cipher<C>> {
    encrypt_u64_bitwise_iter(pk, e).collect()
}

// take an array of zero's and ones and returns a u64
pub fn group_bits_to_u64<'a, C, I>(one: &C, v: I) -> u64
where
    C: Curve,
    I: Iterator<Item = &'a C>, {
    let mut r = 0u64;
    for (i, e) in v.enumerate() {
        if e == one {
            r |= 1 << i;
        }
    }
    r
}

pub fn decrypt_u64_bitwise<C: Curve>(sk: &SecretKey<C>, v: &[Cipher<C>]) -> u64 {
    let dr: Vec<C> = v
        .par_iter()
        .map(|x| {
            let m = sk.decrypt(&x);
            m.value
        })
        .collect();
    group_bits_to_u64(&sk.generator, dr.iter())
}

#[cfg(test)]
mod tests {
    use rand::{rngs::ThreadRng, Rng};

    use crate::message::*;
    use pairing::bls12_381::{Fr, G1, G2};

    use super::*;
    use ff::{Field, PrimeField};

    #[test]
    fn test_chunk_enc() {
        let mut csprng = thread_rng();
        // let n = Fr::from_str("18446744073709551616").unwrap();
        // let n = Fr::from_str("4294967295").unwrap();
        // // let mut n2 = n;
        // // n2.mul_assign(&n);
        // let chunks = value_to_chunks::<G1>(&n, 4);
        // println!("{:?}", chunks);
        let sk: SecretKey<G1> = SecretKey::generate_all(&mut csprng);
        let pk = PublicKey::from(&sk);
        let x = Fr::from_str(
            "52435875175126190479447740508185965837690552500527637822603658699938581184512",
        )
        .unwrap();
        // let x = Fr::from_str("7").unwrap();
        let x = Value::new(x);
        let h = G1::generate(&mut csprng);
        let enc = encrypt_in_chunks_given_generator(&pk, &x, 4, &h, &mut csprng);
        println!("{:?}", enc.len());
        let m = 185364;
        let k = 23171;
        let dec = decrypt_from_chunks_given_generator(&sk, &enc, &h, m, k);
        // let hx = h.mul_by_scalar(&x);
        // let dec = baby_step_giant_step(&hx, &h, 65536, 65536);
        println!("{:?}", dec);
    }

    macro_rules! macro_test_encrypt_decrypt_success {
        ($function_name:ident, $curve_type:path) => {
            #[test]
            pub fn $function_name() {
                let mut csprng = thread_rng();
                for _i in 1..10 {
                    let sk: SecretKey<$curve_type> = SecretKey::generate_all(&mut csprng);
                    let pk = PublicKey::from(&sk);
                    let m = Message::generate(&mut csprng);
                    let c = pk.encrypt(&mut csprng, &m);
                    let mm = sk.decrypt(&c);
                    assert_eq!(m, mm);

                    // encrypting again gives a different ciphertext (very likely at least)
                    let canother = pk.encrypt(&mut csprng, &m);
                    assert_ne!(c, canother);
                }
            }
        };
    }

    macro_test_encrypt_decrypt_success!(encrypt_decrypt_success_g1, G1);
    macro_test_encrypt_decrypt_success!(encrypt_decrypt_success_g2, G2);

    macro_rules! macro_test_encrypt_decrypt_exponent_success {
        ($function_name:ident, $curve_type:path) => {
            #[test]
            pub fn $function_name() {
                let mut csprng = thread_rng();
                let sk: SecretKey<$curve_type> = SecretKey::generate_all(&mut csprng);
                let pk = PublicKey::from(&sk);
                for _i in 1..10 {
                    let n = csprng.gen_range(0, 1000);
                    let mut e = <$curve_type as Curve>::Scalar::zero();
                    let one_scalar =
                        Value::<$curve_type>::new(<$curve_type as Curve>::Scalar::one());
                    for _ in 0..n {
                        e.add_assign(&one_scalar);
                    }
                    let c = pk.encrypt_exponent(&mut csprng, &Value::new(e));
                    let e2 = sk.decrypt_exponent(&c);
                    let e = Value::new(e);
                    assert_eq!(e, e2);
                }
            }
        };
    }

    macro_test_encrypt_decrypt_exponent_success!(encrypt_decrypt_exponent_success_g1, G1);
    macro_test_encrypt_decrypt_exponent_success!(encrypt_decrypt_exponent_success_g2, G2);

    macro_rules! macro_test_encrypt_decrypt_bitwise_vec_success {
        ($function_name:ident, $curve_type:path) => {
            #[test]
            pub fn $function_name() {
                let mut csprng = thread_rng();
                let sk: SecretKey<$curve_type> = SecretKey::generate_all(&mut csprng);
                let pk = PublicKey::from(&sk);
                for _i in 1..10 {
                    let n: u64 = csprng.gen();
                    let c = encrypt_u64_bitwise(pk, n);
                    let n2 = decrypt_u64_bitwise(&sk, &c);
                    assert_eq!(n, n2);
                }
            }
        };
    }

    macro_test_encrypt_decrypt_bitwise_vec_success!(encrypt_decrypt_bitwise_vec_success_g1, G1);
    macro_test_encrypt_decrypt_bitwise_vec_success!(encrypt_decrypt_bitwise_vec_success_g2, G2);

    macro_rules! macro_test_chunking {
        ($function_name:ident, $curve_type:path) => {
            #[test]
            pub fn $function_name() {
                let mut csprng = thread_rng();
                let possible_chunk_sizes = [1, 2, 4, 8, 16, 32];
                // let possible_chunk_sizes = [32];

                for _i in 1..10 {
                    let scalar = Value::<$curve_type>::generate(&mut csprng);
                    let chunk_size_index: usize = csprng.gen_range(0, possible_chunk_sizes.len());
                    let chunk_size = possible_chunk_sizes[chunk_size_index];
                    let chunks = value_to_chunks::<$curve_type>(&scalar, chunk_size);
                    let retrieved_scalar = chunks_to_value::<$curve_type>(chunks);
                    // assert!(true);
                    assert_eq!(scalar, retrieved_scalar);
                }
            }
        };
    }

    macro_test_chunking! {
        chunking_test_g1,
        G1
    }

    macro_rules! macro_test_chunked_encrypt_decrypt {
        ($function_name:ident, $curve_type:path) => {
            #[test]
            pub fn $function_name() {
                let mut csprng = thread_rng();
                let sk = SecretKey::<$curve_type>::generate_all(&mut csprng);
                let pk = PublicKey::<$curve_type>::from(&sk);
                // let possible_chunk_sizes = [1, 2, 4];
                let possible_chunk_sizes = [2];

                for _i in 1..2 {
                    let scalar = Value::<$curve_type>::generate(&mut csprng);
                    let chunk_size_index: usize = csprng.gen_range(0, possible_chunk_sizes.len());
                    let chunk_size = possible_chunk_sizes[chunk_size_index];
                    let cipher = encrypt_in_chunks::<$curve_type, ThreadRng>(
                        &pk,
                        &scalar,
                        chunk_size,
                        &mut csprng,
                    );
                    let retrieved_scalar = decrypt_from_chunks::<$curve_type>(&sk, &cipher);
                    // assert!(true);
                    assert_eq!(scalar, retrieved_scalar);
                }
            }
        };
    }

    macro_test_chunked_encrypt_decrypt! {
        chunked_encrypt_decrypt_test_g1,
        G1
    }
}
