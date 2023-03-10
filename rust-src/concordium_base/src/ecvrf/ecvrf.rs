pub use crate::{errors::*, proof::*, public::*, secret::*};
use crypto_common::*;
use rand::{CryptoRng, Rng};

/// An ed25519 keypair.
#[derive(Debug, Serialize)]
pub struct Keypair {
    /// The secret half of this keypair.
    pub secret: SecretKey,
    /// The public half of this keypair.
    pub public: PublicKey,
}

impl Keypair {
    /// Generate an ed25519 keypair.
    pub fn generate<R>(csprng: &mut R) -> Keypair
    where
        R: CryptoRng + Rng, {
        let sk = SecretKey::generate(csprng);
        let pk = PublicKey::from(&sk);

        Keypair {
            public: pk,
            secret: sk,
        }
    }

    /// Construct a VRF proof with this keypair's secret key.
    pub fn prove(&self, message: &[u8]) -> Proof {
        let expanded: ExpandedSecretKey = (&self.secret).into();

        expanded.prove(&self.public, message)
    }
}

#[cfg(feature = "ffi")]
mod expose_ffi {
    use super::*;
    use crypto_common::size_t;
    use ffi_helpers::*;
    use rand::thread_rng;
    use std::{cmp::Ordering, sync::Arc};
    use subtle::ConstantTimeEq;

    // foreign interface

    // Boilerplate serialization functions.
    macro_derive_from_bytes!(Arc ecvrf_proof_from_bytes, Proof);
    macro_derive_from_bytes!(
        Box ecvrf_public_key_from_bytes,
        PublicKey
    );
    macro_derive_from_bytes_no_cursor!(
        Box ecvrf_secret_key_from_bytes,
        SecretKey,
        SecretKey::from_bytes
    );
    macro_derive_to_bytes!(Arc ecvrf_proof_to_bytes, Proof);
    macro_derive_to_bytes!(Box ecvrf_public_key_to_bytes, PublicKey);
    macro_derive_to_bytes!(Box ecvrf_secret_key_to_bytes, SecretKey);
    // Cleanup of allocated structs.
    macro_free_ffi!(Arc ecvrf_proof_free, Proof);
    macro_free_ffi!(Box ecvrf_public_key_free, PublicKey);
    macro_free_ffi!(Box ecvrf_secret_key_free, SecretKey);

    // equality testing
    macro_derive_binary!(Arc ecvrf_proof_eq, Proof, Proof::eq);
    macro_derive_binary!(Box ecvrf_public_key_eq, PublicKey, PublicKey::eq);
    // NB: Using constant time comparison.
    macro_derive_binary!(Box ecvrf_secret_key_eq, SecretKey, |x, y| bool::from(
        SecretKey::ct_eq(x, y)
    ));

    // ord instance for proof

    #[no_mangle]
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    /// Generate a VRF proof. This function assumes the arguments are not
    /// null-pointers and it always returns a non-null pointer.
    extern "C" fn ecvrf_prove(
        public: *mut PublicKey,
        secret: *mut SecretKey,
        message: *const u8,
        len: size_t,
    ) -> *const Proof {
        let sk = from_ptr!(secret);
        let pk = from_ptr!(public);
        let data: &[u8] = slice_from_c_bytes!(message, len);
        let proof = sk.prove(pk, data);
        Arc::into_raw(Arc::new(proof))
    }

    #[no_mangle]
    /// Generate a new secret key using the system random number generator.
    /// The result is always a non-null pointer.
    extern "C" fn ecvrf_priv_key() -> *mut SecretKey {
        let mut csprng = thread_rng();
        let sk = SecretKey::generate(&mut csprng);
        Box::into_raw(Box::new(sk))
    }

    #[no_mangle]
    /// Derive a public key from a secret key.
    /// We assume the secret key pointer is non-null.
    /// The result is always a non-null pointer.
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    extern "C" fn ecvrf_pub_key(secret_key: *mut SecretKey) -> *mut PublicKey {
        let sk = from_ptr!(secret_key);
        let pk = PublicKey::from(sk);
        Box::into_raw(Box::new(pk))
    }

    #[no_mangle]
    /// Compute hash of a proof.
    /// We assume the proof pointer is non-null.
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    extern "C" fn ecvrf_proof_to_hash(hash_ptr: *mut u8, proof_ptr: *const Proof) {
        let hash = mut_slice_from_c_bytes!(hash_ptr, 64);
        let proof = from_ptr!(proof_ptr);
        hash.copy_from_slice(&proof.to_hash())
    }

    #[no_mangle]
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    extern "C" fn ecvrf_verify_key(key_ptr: *mut PublicKey) -> i32 {
        let key = from_ptr!(key_ptr);
        if key.verify_key() {
            1
        } else {
            0
        }
    }

    #[no_mangle]
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    /// Verify. Returns 1 if verification successful and 0 otherwise.
    /// We assume all pointers are non-null.
    extern "C" fn ecvrf_verify(
        public_key_ptr: *mut PublicKey,
        proof_ptr: *const Proof,
        message_ptr: *const u8,
        len: size_t,
    ) -> i32 {
        let pk = from_ptr!(public_key_ptr);
        let proof = from_ptr!(proof_ptr);
        let message: &[u8] = slice_from_c_bytes!(message_ptr, len);

        if pk.verify(proof, message) {
            1
        } else {
            0
        }
    }

    #[no_mangle]
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    // support ord instance needed in Haskell
    extern "C" fn ecvrf_proof_cmp(proof_ptr_1: *const Proof, proof_ptr_2: *const Proof) -> i32 {
        // optimistic check first.
        if proof_ptr_1 == proof_ptr_2 {
            return 0;
        }

        let p1 = from_ptr!(proof_ptr_1);
        let p2 = from_ptr!(proof_ptr_2);
        match p1.2.as_bytes().cmp(p2.2.as_bytes()) {
            Ordering::Less => return -1,
            Ordering::Greater => return 1,
            Ordering::Equal => (),
        }

        // we now have that the last component is equal
        // check the middle scalar
        match p1.1.as_bytes().cmp(p2.1.as_bytes()) {
            Ordering::Less => return -1,
            Ordering::Greater => return 1,
            Ordering::Equal => (),
        }

        // the scalars are equal, need to check the edwards point
        match p1.0.compress().as_bytes().cmp(p2.0.compress().as_bytes()) {
            Ordering::Less => -1,
            Ordering::Equal => 0,
            Ordering::Greater => 1,
        }
    }

    #[no_mangle]
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    // ord instance for public keys
    extern "C" fn ecvrf_public_key_cmp(
        public_key_ptr_1: *mut PublicKey,
        public_key_ptr_2: *mut PublicKey,
    ) -> i32 {
        // optimistic check first.
        if public_key_ptr_1 == public_key_ptr_2 {
            return 0;
        }

        let p1 = from_ptr!(public_key_ptr_1);
        let p2 = from_ptr!(public_key_ptr_2);

        // only compare the compressed point since the
        // decompressed one is derived.
        match p1.0.as_bytes().cmp(p2.0.as_bytes()) {
            Ordering::Less => -1,
            Ordering::Equal => 0,
            Ordering::Greater => 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use curve25519_dalek::scalar::Scalar;

    /// Test against test vectors specified in
    /// https://tools.ietf.org/id/draft-irtf-cfrg-vrf-07.html#rfc.appendix.A.3
    #[test]
    fn test_vrf_proof_and_hash() {
        /// The test vectors specify a secret key, 'SK', and input, 'alpha',
        /// alongside the serialized values of the public key, 'PK',
        /// secret scalar, 'x', proof, 'pi', and hash of proof 'beta'.
        ///
        /// All other values of the test vectors are determined by 'SK' and
        /// 'alpha'.
        ///
        /// All values that could potentially be stored or sent are tested to
        /// ensure that the serialization agrees with the reference
        /// implementation.
        ///
        /// The values of 'H', 'k', 'U', 'V', and 'ctr' on the succesfull
        /// iteration (all of which are specified in the test vectors)
        /// are omitted from this test as they are internal to the
        /// 'ECVRF_prove' implementation and never serialized. The correctness
        /// of these values is implied by the correctness of 'pi' and
        /// 'beta'.
        fn test_example(
            sk_bytes: [u8; 32],   // Secret key - 32 random bytes
            alpha_bytes: Vec<u8>, // The input to the VRF
            pk_bytes: [u8; 32],   // Public key - derived from the secret key
            x_bytes: [u8; 32],    // Secret scalar - derived from the secret key
            pi_bytes: [u8; 80],   // Result of 'ECVRF_prove(SK, alpha)', encoded as bytestring
            beta_bytes: [u8; 64], // Hash of pi
        ) {
            // Test serialization of public key
            let sk = SecretKey(sk_bytes);
            let expanded_sk = ExpandedSecretKey::from(&sk);
            let pk: PublicKey = PublicKey::from(&expanded_sk);
            assert_eq!(pk.as_bytes(), &pk_bytes);

            // Test serialization of generated secret scalar
            let x = expanded_sk.key;
            assert_eq!(x, Scalar::from_bits(x_bytes));

            // Test serialization of proof
            let proof = expanded_sk.prove(&pk, &alpha_bytes);
            let mut proof_bytes: Vec<u8> = Vec::new();
            proof.serial(&mut proof_bytes);
            assert!(proof_bytes.iter().eq(pi_bytes.iter()));

            // Test hash of proof
            let p2h = proof.to_hash();
            assert!(p2h.iter().eq(beta_bytes.iter()));
        }

        {
            // First example from https://tools.ietf.org/id/draft-irtf-cfrg-vrf-07.html#rfc.appendix.A.3:
            // SK = 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
            // PK = d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
            // alpha = (the empty string)
            // x = 307c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de94f
            // ...
            // pi = 8657106690b5526245a92b003bb079ccd1a92130477671f6fc01ad16f26f723f5e8bd1839b414219e8626d393787a192241fc442e6569e96c462f62b8079b9ed83ff2ee21c90c7c398802fdeebea4001
            // beta = 90cf1df3b703cce59e2a35b925d411164068269d7b2d29f3301c03dd757876ff66b71dda49d2de59d03450451af026798e8f81cd2e333de5cdf4f3e140fdd8ae

            let sk_bytes: [u8; 32] = [
                0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
                0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
                0x1c, 0xae, 0x7f, 0x60,
            ];

            let pk_bytes: [u8; 32] = [
                0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
                0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
                0xf7, 0x07, 0x51, 0x1a,
            ];

            let alpha_bytes: Vec<u8> = Vec::new();

            let x_bytes: [u8; 32] = [
                0x30, 0x7c, 0x83, 0x86, 0x4f, 0x28, 0x33, 0xcb, 0x42, 0x7a, 0x2e, 0xf1, 0xc0, 0x0a,
                0x01, 0x3c, 0xfd, 0xff, 0x27, 0x68, 0xd9, 0x80, 0xc0, 0xa3, 0xa5, 0x20, 0xf0, 0x06,
                0x90, 0x4d, 0xe9, 0x4f,
            ];

            // pi
            let pi_bytes: [u8; 80] = [
                0x86, 0x57, 0x10, 0x66, 0x90, 0xb5, 0x52, 0x62, 0x45, 0xa9, 0x2b, 0x00, 0x3b, 0xb0,
                0x79, 0xcc, 0xd1, 0xa9, 0x21, 0x30, 0x47, 0x76, 0x71, 0xf6, 0xfc, 0x01, 0xad, 0x16,
                0xf2, 0x6f, 0x72, 0x3f, 0x5e, 0x8b, 0xd1, 0x83, 0x9b, 0x41, 0x42, 0x19, 0xe8, 0x62,
                0x6d, 0x39, 0x37, 0x87, 0xa1, 0x92, 0x24, 0x1f, 0xc4, 0x42, 0xe6, 0x56, 0x9e, 0x96,
                0xc4, 0x62, 0xf6, 0x2b, 0x80, 0x79, 0xb9, 0xed, 0x83, 0xff, 0x2e, 0xe2, 0x1c, 0x90,
                0xc7, 0xc3, 0x98, 0x80, 0x2f, 0xde, 0xeb, 0xea, 0x40, 0x01,
            ];

            // beta
            let beta_bytes: [u8; 64] = [
                0x90, 0xcf, 0x1d, 0xf3, 0xb7, 0x03, 0xcc, 0xe5, 0x9e, 0x2a, 0x35, 0xb9, 0x25, 0xd4,
                0x11, 0x16, 0x40, 0x68, 0x26, 0x9d, 0x7b, 0x2d, 0x29, 0xf3, 0x30, 0x1c, 0x03, 0xdd,
                0x75, 0x78, 0x76, 0xff, 0x66, 0xb7, 0x1d, 0xda, 0x49, 0xd2, 0xde, 0x59, 0xd0, 0x34,
                0x50, 0x45, 0x1a, 0xf0, 0x26, 0x79, 0x8e, 0x8f, 0x81, 0xcd, 0x2e, 0x33, 0x3d, 0xe5,
                0xcd, 0xf4, 0xf3, 0xe1, 0x40, 0xfd, 0xd8, 0xae,
            ];

            test_example(
                sk_bytes,
                alpha_bytes,
                pk_bytes,
                x_bytes,
                pi_bytes,
                beta_bytes,
            )
        }

        {
            // Second example from https://tools.ietf.org/id/draft-irtf-cfrg-vrf-07.html#rfc.appendix.A.3:
            // SK = 4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb
            // PK = 3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c
            // alpha = 72 (1 byte)
            // x = 68bd9ed75882d52815a97585caf4790a7f6c6b3b7f821c5e259a24b02e502e51
            // ...
            // pi = f3141cd382dc42909d19ec5110469e4feae18300e94f304590abdced48aed593f7eaf3eb2f1a968cba3f6e23b386aeeaab7b1ea44a256e811892e13eeae7c9f6ea8992557453eac11c4d5476b1f35a08
            // beta = eb4440665d3891d668e7e0fcaf587f1b4bd7fbfe99d0eb2211ccec90496310eb5e33821bc613efb94db5e5b54c70a848a0bef4553a41befc57663b56373a5031

            let sk_bytes: [u8; 32] = [
                0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11,
                0x4e, 0x0f, 0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed,
                0x4f, 0xb8, 0xa6, 0xfb,
            ];

            let pk_bytes: [u8; 32] = [
                0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b,
                0x7e, 0xbc, 0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1,
                0x2a, 0xf4, 0x66, 0x0c,
            ];

            let alpha_bytes: Vec<u8> = vec![0x72];

            let x_bytes: [u8; 32] = [
                0x68, 0xbd, 0x9e, 0xd7, 0x58, 0x82, 0xd5, 0x28, 0x15, 0xa9, 0x75, 0x85, 0xca, 0xf4,
                0x79, 0x0a, 0x7f, 0x6c, 0x6b, 0x3b, 0x7f, 0x82, 0x1c, 0x5e, 0x25, 0x9a, 0x24, 0xb0,
                0x2e, 0x50, 0x2e, 0x51,
            ];

            // pi
            let pi_bytes: [u8; 80] = [
                0xf3, 0x14, 0x1c, 0xd3, 0x82, 0xdc, 0x42, 0x90, 0x9d, 0x19, 0xec, 0x51, 0x10, 0x46,
                0x9e, 0x4f, 0xea, 0xe1, 0x83, 0x00, 0xe9, 0x4f, 0x30, 0x45, 0x90, 0xab, 0xdc, 0xed,
                0x48, 0xae, 0xd5, 0x93, 0xf7, 0xea, 0xf3, 0xeb, 0x2f, 0x1a, 0x96, 0x8c, 0xba, 0x3f,
                0x6e, 0x23, 0xb3, 0x86, 0xae, 0xea, 0xab, 0x7b, 0x1e, 0xa4, 0x4a, 0x25, 0x6e, 0x81,
                0x18, 0x92, 0xe1, 0x3e, 0xea, 0xe7, 0xc9, 0xf6, 0xea, 0x89, 0x92, 0x55, 0x74, 0x53,
                0xea, 0xc1, 0x1c, 0x4d, 0x54, 0x76, 0xb1, 0xf3, 0x5a, 0x08,
            ];

            // beta
            let beta_bytes: [u8; 64] = [
                0xeb, 0x44, 0x40, 0x66, 0x5d, 0x38, 0x91, 0xd6, 0x68, 0xe7, 0xe0, 0xfc, 0xaf, 0x58,
                0x7f, 0x1b, 0x4b, 0xd7, 0xfb, 0xfe, 0x99, 0xd0, 0xeb, 0x22, 0x11, 0xcc, 0xec, 0x90,
                0x49, 0x63, 0x10, 0xeb, 0x5e, 0x33, 0x82, 0x1b, 0xc6, 0x13, 0xef, 0xb9, 0x4d, 0xb5,
                0xe5, 0xb5, 0x4c, 0x70, 0xa8, 0x48, 0xa0, 0xbe, 0xf4, 0x55, 0x3a, 0x41, 0xbe, 0xfc,
                0x57, 0x66, 0x3b, 0x56, 0x37, 0x3a, 0x50, 0x31,
            ];

            test_example(
                sk_bytes,
                alpha_bytes,
                pk_bytes,
                x_bytes,
                pi_bytes,
                beta_bytes,
            )
        }

        {
            // Third example from https://tools.ietf.org/id/draft-irtf-cfrg-vrf-07.html#rfc.appendix.A.3:
            // SK = c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7
            // PK = fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025
            // alpha = af82 (2 bytes)
            // x = 909a8b755ed902849023a55b15c23d11ba4d7f4ec5c2f51b1325a181991ea95c
            // ...
            // pi = 9bc0f79119cc5604bf02d23b4caede71393cedfbb191434dd016d30177ccbf80e29dc513c01c3a980e0e545bcd848222d08a6c3e3665ff5a4cab13a643bef812e284c6b2ee063a2cb4f456794723ad0a
            // beta = 645427e5d00c62a23fb703732fa5d892940935942101e456ecca7bb217c61c452118fec1219202a0edcf038bb6373241578be7217ba85a2687f7a0310b2df19f

            let sk_bytes: [u8; 32] = [
                0xc5, 0xaa, 0x8d, 0xf4, 0x3f, 0x9f, 0x83, 0x7b, 0xed, 0xb7, 0x44, 0x2f, 0x31, 0xdc,
                0xb7, 0xb1, 0x66, 0xd3, 0x85, 0x35, 0x07, 0x6f, 0x09, 0x4b, 0x85, 0xce, 0x3a, 0x2e,
                0x0b, 0x44, 0x58, 0xf7,
            ];

            let pk_bytes: [u8; 32] = [
                0xfc, 0x51, 0xcd, 0x8e, 0x62, 0x18, 0xa1, 0xa3, 0x8d, 0xa4, 0x7e, 0xd0, 0x02, 0x30,
                0xf0, 0x58, 0x08, 0x16, 0xed, 0x13, 0xba, 0x33, 0x03, 0xac, 0x5d, 0xeb, 0x91, 0x15,
                0x48, 0x90, 0x80, 0x25,
            ];

            let alpha_bytes: Vec<u8> = vec![0xaf, 0x82];

            let x_bytes: [u8; 32] = [
                0x90, 0x9a, 0x8b, 0x75, 0x5e, 0xd9, 0x02, 0x84, 0x90, 0x23, 0xa5, 0x5b, 0x15, 0xc2,
                0x3d, 0x11, 0xba, 0x4d, 0x7f, 0x4e, 0xc5, 0xc2, 0xf5, 0x1b, 0x13, 0x25, 0xa1, 0x81,
                0x99, 0x1e, 0xa9, 0x5c,
            ];

            // pi
            let pi_bytes: [u8; 80] = [
                0x9b, 0xc0, 0xf7, 0x91, 0x19, 0xcc, 0x56, 0x04, 0xbf, 0x02, 0xd2, 0x3b, 0x4c, 0xae,
                0xde, 0x71, 0x39, 0x3c, 0xed, 0xfb, 0xb1, 0x91, 0x43, 0x4d, 0xd0, 0x16, 0xd3, 0x01,
                0x77, 0xcc, 0xbf, 0x80, 0xe2, 0x9d, 0xc5, 0x13, 0xc0, 0x1c, 0x3a, 0x98, 0x0e, 0x0e,
                0x54, 0x5b, 0xcd, 0x84, 0x82, 0x22, 0xd0, 0x8a, 0x6c, 0x3e, 0x36, 0x65, 0xff, 0x5a,
                0x4c, 0xab, 0x13, 0xa6, 0x43, 0xbe, 0xf8, 0x12, 0xe2, 0x84, 0xc6, 0xb2, 0xee, 0x06,
                0x3a, 0x2c, 0xb4, 0xf4, 0x56, 0x79, 0x47, 0x23, 0xad, 0x0a,
            ];

            // beta
            let beta_bytes: [u8; 64] = [
                0x64, 0x54, 0x27, 0xe5, 0xd0, 0x0c, 0x62, 0xa2, 0x3f, 0xb7, 0x03, 0x73, 0x2f, 0xa5,
                0xd8, 0x92, 0x94, 0x09, 0x35, 0x94, 0x21, 0x01, 0xe4, 0x56, 0xec, 0xca, 0x7b, 0xb2,
                0x17, 0xc6, 0x1c, 0x45, 0x21, 0x18, 0xfe, 0xc1, 0x21, 0x92, 0x02, 0xa0, 0xed, 0xcf,
                0x03, 0x8b, 0xb6, 0x37, 0x32, 0x41, 0x57, 0x8b, 0xe7, 0x21, 0x7b, 0xa8, 0x5a, 0x26,
                0x87, 0xf7, 0xa0, 0x31, 0x0b, 0x2d, 0xf1, 0x9f,
            ];

            test_example(
                sk_bytes,
                alpha_bytes,
                pk_bytes,
                x_bytes,
                pi_bytes,
                beta_bytes,
            )
        }
    }
}
