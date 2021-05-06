use crate::{cipher::*, public::*, secret::*};
use curve_arithmetic::{Curve, Value};
use ff::{Field, PrimeField};
use rand::*;

/// Possible chunk sizes in bits.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ChunkSize {
    One,
    Two,
    Four,
    Eight,
    Sixteen,
    ThirtyTwo,
    SixtyFour,
}

impl From<ChunkSize> for u8 {
    fn from(c: ChunkSize) -> Self {
        use ChunkSize::*;
        match c {
            One => 1,
            Two => 2,
            Four => 4,
            Eight => 8,
            Sixteen => 16,
            ThirtyTwo => 32,
            SixtyFour => 64,
        }
    }
}

impl ChunkSize {
    /// Compute the "mask" from chunk size. The mask can be used
    /// to obtain the lowest (least significant) bits of a `u64` value.
    ///
    /// Concoretely, if ChunkSize is n, then this function returns
    /// a u64 value whose n least significant bits are 1, and all other bits are
    /// 0.
    pub fn mask(self) -> u64 {
        use ChunkSize::*;
        match self {
            One => 1,
            Two => 0b11,
            Four => 0b1111,
            Eight => (1 << 8) - 1,
            Sixteen => (1 << 16) - 1,
            ThirtyTwo => (1 << 32) - 1,
            SixtyFour => !0,
        }
    }

    /// Return chunks as little-endian limbs.
    pub fn u64_to_chunks(self, x: u64) -> Vec<u64> {
        let mask = self.mask();
        let size = u8::from(self);
        let n = 64 / usize::from(size);
        let mut out = Vec::with_capacity(n);
        let mut tmp = x;
        for _ in 0..n {
            out.push(tmp & mask);
            tmp >>= size;
        }
        out
    }

    /// Reconstruct from little endian limbs, given chunk size.
    pub fn chunks_to_u64(self, xs: impl IntoIterator<Item = u64>) -> u64 {
        let size = u8::from(self);
        let mut factor = 0;
        let mut out = 0;
        for x in xs {
            out += x << factor;
            factor += size;
        }
        out
    }
}

/// Transform a scalar into as many chunks as necessary.
/// The chunks are returned in little-endian order.
pub fn value_to_chunks<C: Curve>(val: &C::Scalar, chunk_size: ChunkSize) -> Vec<Value<C>> {
    // u64 chunks as little-endian limbs
    let size = usize::from(u8::from(chunk_size));
    let n = C::SCALAR_LENGTH / size;
    let mut out = Vec::with_capacity(n);
    let repr = val.into_repr();
    let u64_chunks = repr.as_ref();
    for &chunk in u64_chunks {
        out.extend(
            chunk_size
                .u64_to_chunks(chunk)
                .iter()
                .map(|&x| Value::new(C::scalar_from_u64(x))),
        );
    }
    out
}

/// NB: This function does not ensure there is no overflow.
/// It assumes that the chunks are reasonable and at most 64 bits.
///
/// The chunks are assumed to be in little-endian order.
pub fn chunks_to_value<C: Curve>(chunks: &[Value<C>], chunk_size: ChunkSize) -> Value<C> {
    // 2^64
    let mul = {
        let mut factor = C::scalar_from_u64(1);
        factor.add_assign(&C::scalar_from_u64(!0));
        factor
    };
    let mut factor = C::Scalar::one();
    let mut ret = C::Scalar::zero();
    for chunk_section in chunks.chunks(64 / usize::from(u8::from(chunk_size))) {
        // get the u64 encoded in this chunk section
        let v = chunk_size.chunks_to_u64(chunk_section.iter().map(|chunk| {
            let repr = chunk.into_repr();
            repr.as_ref()[0]
        }));
        let mut val = C::scalar_from_u64(v);
        val.mul_assign(&factor);
        ret.add_assign(&val);
        factor.mul_assign(&mul);
    }
    Value::new(ret)
}

/// Wrapper around `encrypt_in_chunks_given_generator` that uses the generator
/// that is part of the public key.
pub fn encrypt_in_chunks<C: Curve, R: Rng>(
    pk: &PublicKey<C>,
    val: &Value<C>,
    chunk_size: ChunkSize,
    csprng: &mut R,
) -> Vec<(Cipher<C>, Randomness<C>)> {
    encrypt_in_chunks_given_generator(pk, val, chunk_size, &pk.generator, csprng)
}

pub fn encrypt_in_chunks_given_generator<C: Curve, R: Rng>(
    pk: &PublicKey<C>,
    val: &Value<C>,
    chunk_size: ChunkSize,
    generator: &C,
    csprng: &mut R,
) -> Vec<(Cipher<C>, Randomness<C>)> {
    let chunks = value_to_chunks::<C>(val, chunk_size);
    pk.encrypt_exponent_vec_given_generator(&chunks, generator, csprng)
}

/// Encrypt a single `u64` value in chunks in the exponent of the given
/// generator.
pub fn encrypt_u64_in_chunks_given_generator<C: Curve, R: Rng>(
    pk: &PublicKey<C>,
    val: u64,
    chunk_size: ChunkSize,
    generator: &C,
    csprng: &mut R,
) -> Vec<(Cipher<C>, Randomness<C>)> {
    let chunks = chunk_size
        .u64_to_chunks(val)
        .into_iter()
        .map(Value::from)
        .collect::<Vec<_>>();
    pk.encrypt_exponent_vec_given_generator(&chunks, generator, csprng)
}

/// Wrapper around `decrypt_from_chunks_given_generator` that uses the generator
/// that is part of the key.
pub fn decrypt_from_chunks<C: Curve>(
    sk: &SecretKey<C>,
    cipher: &[Cipher<C>],
    m: u64,
    chunk_size: ChunkSize,
) -> Value<C> {
    decrypt_from_chunks_given_generator(sk, cipher, &sk.generator, m, chunk_size)
}

pub fn decrypt_from_chunks_given_generator<C: Curve>(
    sk: &SecretKey<C>,
    cipher: &[Cipher<C>],
    generator: &C,
    m: u64,
    chunk_size: ChunkSize,
) -> Value<C> {
    let bsgs = BabyStepGiantStep::new(generator, m);
    decrypt_from_chunks_given_table(sk, cipher, &bsgs, chunk_size)
}

pub fn decrypt_from_chunks_given_table<C: Curve>(
    sk: &SecretKey<C>,
    ciphers: &[Cipher<C>],
    table: &BabyStepGiantStep<C>,
    chunk_size: ChunkSize,
) -> Value<C> {
    let scalars = ciphers
        .iter()
        .map(|cipher| Value::from(sk.decrypt_exponent(cipher, table)))
        .collect::<Vec<_>>();
    chunks_to_value::<C>(&scalars, chunk_size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::*;
    use ff::Field;
    use pairing::bls12_381::{G1, G2};
    use rand::{rngs::ThreadRng, Rng};

    // This is a generic helper function that tests encryption/decryption in chunks.
    // It is parameterized by a curve, and the intention is that concrete tests are
    // going to use explicit curve instances.
    fn test_encrypt_decrypt_success_generic<C: Curve>() {
        let mut csprng = thread_rng();
        for _i in 1..10 {
            let sk: SecretKey<C> = SecretKey::generate_all(&mut csprng);
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

    #[test]
    fn encrypt_decrypt_success_g1() { test_encrypt_decrypt_success_generic::<G1>() }

    #[test]
    fn encrypt_decrypt_success_g2() { test_encrypt_decrypt_success_generic::<G2>() }

    // This is a generic helper function that tests encryption/decryption in chunks.
    // It is parameterized by a curve, and the intention is that concrete tests are
    // going to use explicit curve instances.
    fn test_encrypt_decrypt_exponent_success_generic<C: Curve>() {
        let mut csprng = thread_rng();
        let sk: SecretKey<C> = SecretKey::generate_all(&mut csprng);
        let pk = PublicKey::from(&sk);
        for _i in 1..10 {
            let n = csprng.gen_range(0, 1000);
            let mut e = <C as Curve>::Scalar::zero();
            let one_scalar = Value::<C>::new(<C as Curve>::Scalar::one());
            for _ in 0..n {
                e.add_assign(&one_scalar);
            }
            let c = pk.encrypt_exponent(&mut csprng, &Value::new(e));
            let e2 = sk.decrypt_exponent_slow(&c);
            let e = Value::new(e);
            assert_eq!(e, e2);
        }
    }

    #[test]
    fn encrypt_decrypt_exponent_success_g1() {
        test_encrypt_decrypt_exponent_success_generic::<G1>()
    }

    #[test]
    fn encrypt_decrypt_exponent_success_g2() {
        test_encrypt_decrypt_exponent_success_generic::<G2>()
    }

    // This is a generic helper function that tests encryption/decryption in chunks.
    // It is parameterized by a curve, and the intention is that concrete tests are
    // going to use explicit curve instances.
    fn test_chunking_generic<C: Curve>() {
        let mut csprng = thread_rng();
        use ChunkSize::*;
        let possible_chunk_sizes = [One, Two, Four, Eight, Sixteen, ThirtyTwo];
        // let possible_chunk_sizes = [32];

        for _i in 1..10 {
            let scalar = Value::<C>::generate(&mut csprng);
            let chunk_size_index: usize = csprng.gen_range(0, possible_chunk_sizes.len());
            let chunk_size = possible_chunk_sizes[chunk_size_index];
            let chunks = value_to_chunks::<C>(&scalar, chunk_size);
            let retrieved_scalar = chunks_to_value::<C>(&chunks, chunk_size);
            // assert!(true);
            assert_eq!(scalar, retrieved_scalar);
        }
    }

    #[test]
    fn chunking_test_g1() { test_chunking_generic::<G1>() }

    // This is a generic helper function that tests encryption/decryption in chunks.
    // It is parameterized by a curve, and the intention is that concrete tests are
    // going to use explicit curve instances.
    fn test_chunked_encrypt_decrypt_generic<C: Curve>() {
        let mut csprng = thread_rng();
        let sk = SecretKey::<C>::generate_all(&mut csprng);
        let pk = PublicKey::<C>::from(&sk);
        // let possible_chunk_sizes = [1, 2, 4];
        let possible_chunk_sizes = [ChunkSize::Two];

        for _i in 1..2 {
            let scalar = Value::<C>::generate(&mut csprng);
            let chunk_size_index: usize = csprng.gen_range(0, possible_chunk_sizes.len());
            let chunk_size = possible_chunk_sizes[chunk_size_index];
            let m = 1 << (u8::from(chunk_size) - 1);
            let cipher_pairs =
                encrypt_in_chunks::<C, ThreadRng>(&pk, &scalar, chunk_size, &mut csprng);
            let cipher = cipher_pairs.into_iter().map(|(x, _)| x).collect::<Vec<_>>();
            let retrieved_scalar = decrypt_from_chunks::<C>(&sk, &cipher, m, chunk_size);
            assert_eq!(
                scalar, retrieved_scalar,
                "Encrypted and retrieved scalars differ."
            );
        }
    }

    #[test]
    fn chunked_encrypt_decrypt_test_g1() { test_chunked_encrypt_decrypt_generic::<G1>() }
}
