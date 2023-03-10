//! A collection of auxiliary functions that don't belong anywhere else.

use crate::{secret_sharing::Threshold, types::*};
use anyhow::bail;
use crypto_common::{
    to_bytes,
    types::{KeyIndex, TransactionTime},
    ParseResult,
};
use curve_arithmetic::{multiexp, Curve, Pairing, Value};
use ed25519_dalek::Verifier;
use either::Either;
use elgamal::*;
use ff::{Field, PrimeField};
use pedersen_scheme::Commitment;
use rand::*;
use sha2::{Digest, Sha256};
use std::collections::{btree_map::BTreeMap, BTreeSet};

/// Given a list of commitments g^{a_i}h^{r_i}
/// and a point x (the share number), compute
/// g^p(x)h^r(x) where
/// p(x) = a_0 + a_1 x + ... + a_n x^n
/// r(x) = r_0 + r_1 x + ... + r_n x^n
pub fn commitment_to_share<C: Curve>(
    share_number: &C::Scalar,
    coeff_commitments: &[Commitment<C>],
) -> Commitment<C> {
    let n = coeff_commitments.len();
    if n == 0 {
        return Commitment(C::zero_point());
    }
    let mut exponents = Vec::with_capacity(n);
    let mut exponent: C::Scalar = C::Scalar::one();
    for _ in 0..n {
        exponents.push(exponent);
        exponent.mul_assign(share_number);
    }
    Commitment(multiexp(coeff_commitments, &exponents))
}

/// Interpret the array as coefficients of a polynomial starting at 0,
/// and evaluate the polynomial at the given point.
pub fn evaluate_poly<F: Field, R: AsRef<F>>(coeffs: &[R], point: &F) -> F {
    let mut eval: F = F::zero();
    // Horner's scheme at point point
    for rand in coeffs.iter().rev() {
        eval.mul_assign(point);
        eval.add_assign(rand.as_ref());
    }
    eval
}

/// This function is used for encryption of the PRF key share in chunks,
/// where the chunks are written in little endian.
/// The arguments are
/// - context - the global context,
/// - pk - the public key for encryption
/// - share - the share we want to encrypt
/// The output is a 3-tuple concisting of
/// 8 Cipher's, 8 Randomness's and 8 scalars.
/// The ciphers and randomnesses come from the
/// encryption in chunks itself.
/// The scalars are the chunks themselves (in little endian).
#[allow(clippy::type_complexity)]
pub fn encrypt_prf_share<C: Curve, R: Rng>(
    context: &GlobalContext<C>,
    pk: &PublicKey<C>,
    share: &Value<C>,
    csprng: &mut R,
) -> ([Cipher<C>; 8], [Randomness<C>; 8], [C::Scalar; 8]) {
    // The generator for encryption in the exponent is the second component of the
    // commitment key, the 'h'.
    let h = context.encryption_in_exponent_generator();
    // let mut ciphers = encrypt_in_chunks_given_generator(pk, share, CHUNK_SIZE, h,
    // csprng);
    let chunks = value_to_chunks::<C>(share, CHUNK_SIZE);
    let mut ciphers = pk.encrypt_exponent_vec_given_generator(&chunks, h, csprng);
    // these are guaranteed to exist because we used `ChunkSize::ThirtyTwo`. The
    // encryptions are in little-endian limbs, so the last one is the encryption
    // of the high bits.
    let (encryption_8, randomness_8) = ciphers.pop().unwrap();
    let (encryption_7, randomness_7) = ciphers.pop().unwrap();
    let (encryption_6, randomness_6) = ciphers.pop().unwrap();
    let (encryption_5, randomness_5) = ciphers.pop().unwrap();
    let (encryption_4, randomness_4) = ciphers.pop().unwrap();
    let (encryption_3, randomness_3) = ciphers.pop().unwrap();
    let (encryption_2, randomness_2) = ciphers.pop().unwrap();
    let (encryption_1, randomness_1) = ciphers.pop().unwrap();

    let enc = [
        encryption_1,
        encryption_2,
        encryption_3,
        encryption_4,
        encryption_5,
        encryption_6,
        encryption_7,
        encryption_8,
    ];
    let rand = [
        randomness_1,
        randomness_2,
        randomness_3,
        randomness_4,
        randomness_5,
        randomness_6,
        randomness_7,
        randomness_8,
    ];
    let chunks = [
        *chunks[0], *chunks[1], *chunks[2], *chunks[3], *chunks[4], *chunks[5], *chunks[6],
        *chunks[7],
    ];
    (enc, rand, chunks)
}

/// Encode attribute tags into a big-integer bits. The tags are encoded from
/// least significant bit up, i.e., LSB of the result is set IFF tag0 is in the
/// list. This function will fail if
/// - there are repeated attributes in the list
/// - there are tags in the list which do not fit into the field capacity
pub fn encode_tags<'a, F: PrimeField, I: std::iter::IntoIterator<Item = &'a AttributeTag>>(
    i: I,
) -> ParseResult<F> {
    // Since F is supposed to be a field, its capacity must be at least 1, hence the
    // next line is safe. Maximum tag that can be stored.
    let max_tag = F::CAPACITY - 1;
    let mut f = F::zero().into_repr();
    let limbs = f.as_mut(); // this is an array of 64 bit limbs, with least significant digit first
    for &AttributeTag(tag) in i.into_iter() {
        let idx = tag / 64;
        let place = tag % 64;
        if u32::from(tag) > max_tag || usize::from(idx) > limbs.len() {
            bail!("Tag out of range: {}", tag)
        }
        let mask: u64 = 1 << place;
        if limbs[usize::from(idx)] & mask != 0 {
            bail!("Duplicate tag {}", tag)
        } else {
            limbs[usize::from(idx)] |= mask;
        }
    }
    // This should not fail (since we check capacity), but in case it does we just
    // propagate the error.
    Ok(F::from_repr(f)?)
}

/// Encode anonymity revokers into a list of scalars.
/// The encoding is as follows.
/// Given a list of identity providers, and a capacity C,
/// we encode it into multiple scalars, in big-endian representation.
/// The encodings are shifted, and the last (least significant) bit
/// of the scalar encodes whether there are more scalars to follow.
/// That is the case if and only if the bit is 1.
/// The field must be big enough to encode u64.
///
/// This function will encode sorted identities
pub fn encode_ars<F: PrimeField>(ars: &BTreeSet<ArIdentity>) -> Option<Vec<F>> {
    let max_bit: usize = (F::CAPACITY - 1) as usize;

    // Collect into an __acending__ vector.
    let ars = ars.iter().copied().collect::<Vec<_>>();

    // NB: This 32 must be the same as the size of the ArIdentity.
    let num_ars_per_element = max_bit / 32;
    let chunks = ars.chunks(num_ars_per_element);
    let num_scalars = chunks.len();
    let mut scalars = Vec::with_capacity(num_scalars);
    let mut two = F::one();
    two.add_assign(&F::one());
    let two = two;

    for chunk in chunks {
        let mut f = F::zero().into_repr();
        for (i, &ar_id) in chunk.iter().enumerate() {
            let ar_id: u32 = ar_id.into();
            let x: u64 = if i % 2 == 0 {
                u64::from(ar_id)
            } else {
                u64::from(ar_id) << 32
            };
            f.as_mut()[i / 2] |= x;
        }
        let mut scalar = F::from_repr(f).ok()?;
        // shift one bit left.
        scalar.mul_assign(&two);
        scalars.push(scalar)
    }
    if num_scalars == 0 {
        scalars.push(F::zero())
    }
    // This should not fail since we've explicitly added an element to
    // make sure we have enough scalars, but we still just propagate the error.
    scalars.last_mut()?.add_assign(&F::one());
    Some(scalars)
}

/// Encode two yearmonth values into a scalar.
/// This encodes them after converting them into u32, first putting created_at,
/// and then valid_to into the scalar. Thus create_at starts at the
/// least-significant bit. The threshold is stored in the next byte.
///
/// NB: The field's capacity must be at least 128 bits.
pub fn encode_public_credential_values<F: PrimeField>(
    created_at: YearMonth,
    valid_to: YearMonth,
    threshold: Threshold,
) -> ParseResult<F> {
    let mut f = F::zero().into_repr();
    let ca: u32 = created_at.into();
    let vt: u32 = valid_to.into();
    let s = u64::from(vt) << 32 | u64::from(ca);
    f.as_mut()[0] = s; // limbs in as_mut are little endian.
    let threshold: u8 = threshold.into();
    f.as_mut()[1] = u64::from(threshold);
    Ok(F::from_repr(f)?)
}

/// This function verifies that the signature inside
/// the AccountOwnershipProof is a signature of the given message.
/// The arguments are
///  - keys - the verification keys
///  - threshold - the signature threshold
///  - proof_acc_sk - the AccountOwnershipProof containing the signature to be
///    verified
///  - msg - the message
pub fn verify_account_ownership_proof(
    keys: &BTreeMap<KeyIndex, VerifyKey>,
    threshold: SignatureThreshold,
    proof_acc_sk: &AccountOwnershipProof,
    msg: &[u8],
) -> bool {
    // we check all the keys that were provided, and check enough were provided
    // compared to the threshold
    // We also make sure that no more than 255 keys are provided, as well as
    // - all keys are distinct
    // - at least one key is provided
    // - there are the same number of proofs and keys
    if proof_acc_sk.num_proofs() < threshold
        || keys.len() > 255
        || keys.is_empty()
        || proof_acc_sk.num_proofs() != SignatureThreshold(keys.len() as u8)
    {
        return false;
    }
    // set of processed keys already
    let mut processed = BTreeSet::new();
    for (idx, key) in keys.iter() {
        // insert returns true if key was __not__ present
        if !processed.insert(key) {
            return false;
        }
        if let Some(sig) = proof_acc_sk.sigs.get(idx) {
            let VerifyKey::Ed25519VerifyKey(ref key) = key;
            if key.verify(msg, sig).is_err() {
                return false;
            }
        } else {
            return false;
        }
    }
    true
}

/// Compute the hash of the credential deployment that should be signed by the
/// account keys for deployment.
/// If `new_or_existing` is `Left` then this credential will create a new
/// account, and the transaction expiry should be signed.
/// otherwise it is going to be deployed to the given account address, and the
/// address should be signed.
pub fn credential_hash_to_sign<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
>(
    values: &CredentialDeploymentValues<C, AttributeType>,
    proofs: &IdOwnershipProofs<P, C>,
    new_or_existing: &Either<TransactionTime, AccountAddress>,
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(&to_bytes(&values));
    hasher.update(&to_bytes(&proofs));
    // the serialization of Either has 0 tag for the left variant, and 1 for the
    // right
    hasher.update(&to_bytes(&new_or_existing));
    let to_sign = &hasher.finalize();
    to_sign.to_vec()
}

/// Given two ordered iterators call the corresponding functions in the
/// increasing order of keys. That is, essentially merge the two iterators into
/// an ordered iterator and then map, but this is all done inline.
pub fn merge_iter<'a, K: Ord + 'a, V1: 'a, V2: 'a, I1, I2, F>(i1: I1, i2: I2, mut f: F)
where
    I1: std::iter::IntoIterator<Item = (&'a K, &'a V1)>,
    I2: std::iter::IntoIterator<Item = (&'a K, &'a V2)>,
    F: FnMut(Either<&'a V1, &'a V2>), {
    let mut iter_1 = i1.into_iter().peekable();
    let mut iter_2 = i2.into_iter().peekable();
    while let (Some(&(tag_1, v_1)), Some(&(tag_2, v_2))) = (iter_1.peek(), iter_2.peek()) {
        if tag_1 < tag_2 {
            f(Either::Left(v_1));
            // advance the first iterator
            let _ = iter_1.next().is_none();
        } else {
            f(Either::Right(v_2));
            // advance the second iterator
            let _ = iter_2.next();
        }
    }
    for (_, v) in iter_1 {
        f(Either::Left(v))
    }
    for (_, v) in iter_2 {
        f(Either::Right(v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_common::to_bytes;
    use pairing::bls12_381::Fr;
    use rand::{thread_rng, Rng};
    use std::collections::BTreeMap;

    #[test]
    pub fn test_last_bit() {
        let ars = (1..10).map(ArIdentity::new).collect::<BTreeSet<_>>();
        let encoded = encode_ars::<Fr>(&ars).expect("Encodign should succeed.");
        // Field size of Fr is 254 bits, so what we expect is to have two scalars
        assert_eq!(encoded.len(), 2, "Encoded ARs should fit into two scalars.");
        let s1 = to_bytes(&encoded[0]);
        let s2 = to_bytes(&encoded[1]);
        // last bit of the first one must be 0
        assert_eq!(s1[31] & 1u8, 0u8, "Last bit of the first scalar must be 0.");
        assert_eq!(
            s2[31] & 1u8,
            1u8,
            "Last bit of the second scalar must be 1."
        );
    }

    #[test]
    // Test that the encoding of anonymity revokers is injective.
    pub fn test_encoding_injective() {
        let mut csprng = thread_rng();
        let mut seen = BTreeMap::new();
        for n in 1..50 {
            let mut xs = vec![ArIdentity::new(1); n];
            for x in xs.iter_mut() {
                *x = ArIdentity::new(csprng.gen_range(1, 100));
            }
            let set = xs.iter().copied().collect::<BTreeSet<_>>();
            let encoded = encode_ars::<Fr>(&set).expect("Encoding should succeed.");
            if let Some(set_ex) = seen.insert(encoded.clone(), set.clone()) {
                assert_eq!(set, set_ex);
            }
        }
    }
}
