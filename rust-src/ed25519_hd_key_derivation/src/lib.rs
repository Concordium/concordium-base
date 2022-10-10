use hmac::{Hmac, Mac};
use regex::Regex;
use sha2::Sha512;
use thiserror::Error;

const ED25519_CURVE: &[u8; 12] = b"ed25519 seed";
const HARDENED_OFFSET: u32 = 0x80000000;

/// Harden a u32 value such that it can appear in a hardened path.
/// Note that if the index is already hardened this function does nothing.
/// See also [`checked_harden`] for a version which checks whether the value is
/// not hardened.
pub fn harden(index: u32) -> u32 { index | HARDENED_OFFSET }

/// Check that the value is not yet hardened, and harden it.
pub fn checked_harden(index: u32) -> Result<u32, DeriveError> {
    if index & HARDENED_OFFSET == 0 {
        Ok(index | HARDENED_OFFSET)
    } else {
        Err(DeriveError::InvalidPath)
    }
}

#[derive(Debug, Error, PartialEq)]
pub enum DeriveError {
    #[error("Invalid derivation path.")]
    InvalidPath,
    #[error("Seed must be between 128 and 512 bits.")]
    InvalidSeed,
}

/// An extended private key, e.g. the private key and its corresponding chain
/// code.
pub struct HdKeys {
    /// The private key part of the hierarchical deterministic key derivation.
    /// This will contain the private key material to be consumed.
    pub private_key: [u8; 32],
    /// The chain code part of the hierarchical deterministic key derivation.
    /// This is only used internally in the algorithm.
    chain_code:      [u8; 32],
}

fn get_master_key_from_seed(seed: &[u8]) -> HdKeys {
    let mut mac = Hmac::<Sha512>::new_from_slice(ED25519_CURVE).unwrap();
    mac.update(seed);
    let i = mac.finalize().into_bytes();
    let mut il = [0u8; 32];
    il.copy_from_slice(&i[0..32]);
    let mut ir = [0u8; 32];
    ir.copy_from_slice(&i[32..64]);

    HdKeys {
        private_key: il,
        chain_code:  ir,
    }
}

/// Derives a child extended key from a parent extended key and an index.
fn ckd_priv(parent_keys: HdKeys, index: u32) -> Result<HdKeys, DeriveError> {
    if index & HARDENED_OFFSET == 0 {
        return Err(DeriveError::InvalidPath);
    }

    let mut data = vec![0u8];
    data.extend_from_slice(&parent_keys.private_key);
    data.extend_from_slice(&index.to_be_bytes());

    let mut mac = Hmac::<Sha512>::new_from_slice(&parent_keys.chain_code).unwrap();
    mac.update(&data);
    let i = mac.finalize().into_bytes();
    let mut il = [0u8; 32];
    il.copy_from_slice(&i[0..32]);
    let mut ir = [0u8; 32];
    ir.copy_from_slice(&i[32..64]);

    Ok(HdKeys {
        private_key: il,
        chain_code:  ir,
    })
}

/// Attempt to parse a given key derivation path as a path path for the ed25519
/// SLIP0010 standard. If the path is valid return the indices on the path with
/// with the hardening offset applied.
///
/// A valid path is of the form
///
/// * `m/x_0'/.../x_n'`
///
/// where `x_i < 2^31 (2147483648)` and `n >= 0`.
///
/// Note that the `'` after each integer value means that the path is hardened,
/// which is a requirement for key derivation paths for ed25519. Hardening
/// ensures that the highest-order bit of each u32 value in the path is set to
/// `1` so that all values in the path are `>= 2^31`. A path with a non-hardened
/// value will not validate.
///
/// # Examples
/// ```
/// use ed25519_hd_key_derivation::parse_path;
///
/// let path = "m/44'/919'/0'/0'";
/// let valid_path_indices: Vec<u32> = match parse_path(&path) {
///     Ok(s) => s,
///     Err(e) => panic!("The path was invalid"),
/// };
/// ```
pub fn parse_path(path: &str) -> Result<Vec<u32>, DeriveError> {
    let path_regex = Regex::new("^m((/0')|(/[1-9]([0-9])*'))+$").unwrap();
    if !path_regex.is_match(path) {
        return Err(DeriveError::InvalidPath);
    }

    let mut parsed_path = Vec::new();
    for segment in path.split('/').skip(1) {
        let without_hardening_char = segment.replace('\'', "");
        match without_hardening_char.parse::<u32>() {
            Ok(s) => {
                if s >= 2147483648 {
                    return Err(DeriveError::InvalidPath);
                }
                parsed_path.push(s + HARDENED_OFFSET)
            }
            Err(_) => return Err(DeriveError::InvalidPath),
        }
    }
    Ok(parsed_path)
}

/// Derives hierarchical deterministic keys for ed25519 according to the SLIP0010 (https://github.com/satoshilabs/slips/blob/master/slip-0010.md)
/// specification.
///
/// # Arguments
/// * `path` - A string slice that holds the key derivation path
/// * `seed` - A byte array slice of length between 16 and 64 bytes that holds
///   the seed to derive keys from
///
/// # Examples
/// ```
/// use ed25519_hd_key_derivation::derive;
///
/// let seed = [0u8; 64];
/// let keys = derive("m/44'/919'/0'/0'", &seed);
/// ```
pub fn derive(path: &str, seed: &[u8]) -> Result<HdKeys, DeriveError> {
    let parsed_path = parse_path(path)?;
    derive_from_parsed_path(&parsed_path, seed)
}

/// Derives hierarchical deterministic keys for ed25519 according to the SLIP0010 (https://github.com/satoshilabs/slips/blob/master/slip-0010.md)
/// specification.
///
/// # Arguments
/// * `path` - An array of indices. **They must all be hardened.** For example
///   this path could be obtained using [`parse_path`].
/// * `seed` - A byte array slice of length between 16 and 64 bytes that holds
///   the seed to derive keys from
///
/// # Examples
/// ```
/// use ed25519_hd_key_derivation::{derive_from_parsed_path, harden};
///
/// let seed = [0u8; 64];
/// let keys = derive_from_parsed_path(&[harden(44), harden(919), harden(0), harden(0)], &seed);
/// ```
pub fn derive_from_parsed_path(parsed_path: &[u32], seed: &[u8]) -> Result<HdKeys, DeriveError> {
    if seed.len() < 16 || seed.len() > 64 {
        return Err(DeriveError::InvalidSeed);
    }
    let master_key = get_master_key_from_seed(seed);
    let mut current_key = master_key;
    for &index in parsed_path {
        current_key = ckd_priv(current_key, index)?;
    }
    Ok(current_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_VECTOR_1_SEED: &str = "000102030405060708090a0b0c0d0e0f";
    const TEST_VECTOR_2_SEED: &str = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542";

    fn assert_keys(seed: &str, path: &str, chain_code: &str, private_key: &str, public_key: &str) {
        let seed = hex::decode(seed).unwrap();
        let keys = derive(path, &seed).unwrap();
        let secret_key = ed25519_dalek::SecretKey::from_bytes(&keys.private_key).unwrap();
        let public_key_derived = ed25519_dalek::PublicKey::from(&secret_key).to_bytes();
        assert_eq!(
            keys.chain_code.to_vec(),
            hex::decode(chain_code).unwrap(),
            "The two chain codes have to be equal"
        );
        assert_eq!(
            keys.private_key.to_vec(),
            hex::decode(private_key).unwrap(),
            "The two private keys have to be equal"
        );
        assert_eq!(
            public_key_derived.to_vec(),
            hex::decode(public_key).unwrap(),
            "The two public keys have to be equal"
        );
    }

    #[test]
    pub fn test_invalid_seed_small() {
        let valid_path = "m/44'/919'";
        let invalid_seed_small = hex::decode("ababababababababababababababab").unwrap();
        let result = derive(valid_path, &invalid_seed_small);
        assert_eq!(
            result.err().unwrap(),
            DeriveError::InvalidSeed,
            "Seed {:?} with length {} should be invalid",
            invalid_seed_small,
            invalid_seed_small.len()
        );
    }

    #[test]
    pub fn test_invalid_seed_large() {
        let valid_path = "m/44'/919'";
        let invalid_seed_large = hex::decode("abababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab12").unwrap();
        let result = derive(valid_path, &invalid_seed_large);
        assert_eq!(
            result.err().unwrap(),
            DeriveError::InvalidSeed,
            "Seed {:?} with length {} should be invalid",
            invalid_seed_large,
            invalid_seed_large.len()
        );
    }

    #[test]
    pub fn test_valid_path() {
        let valid_path = "m/44'/919'/0'/1'/0'";
        assert!(
            parse_path(valid_path).is_ok(),
            "Path {} should be valid.",
            valid_path
        );
    }

    #[test]
    pub fn test_0_prefixed_path_is_invalid() {
        let valid_path = "m/44'/919'/0315'";
        assert!(
            parse_path(valid_path).is_err(),
            "Path {} should be invalid.",
            valid_path
        );
    }

    #[test]
    pub fn test_non_hardened_path() {
        let non_hardened_path = "m/44'/919'/53100'/581";
        assert!(
            parse_path(non_hardened_path).is_err(),
            "Path {} should be invalid as it contains an un-hardened index",
            non_hardened_path
        );
    }

    #[test]
    pub fn test_out_of_bounds_path() {
        let out_of_bounds_index_path = "m/44'/919'/2147483648'";
        assert!(
            parse_path(out_of_bounds_index_path).is_err(),
            "Path {} should be invalid as an index is out of bounds",
            out_of_bounds_index_path
        );
    }

    #[test]
    pub fn test_derive_invalid_path() {
        let invalid_path = "m/4//146";
        let seed = hex::decode("123456").unwrap();
        assert!(
            derive(invalid_path, &seed).is_err(),
            "Path {} should be invalid as it is malformed",
            invalid_path
        );
    }

    #[test]
    pub fn test_vector_1_m() {
        let seed = hex::decode(TEST_VECTOR_1_SEED).unwrap();
        let master_key = get_master_key_from_seed(&seed);
        assert_eq!(
            master_key.chain_code.to_vec(),
            hex::decode("90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb")
                .unwrap()
        );
        assert_eq!(
            master_key.private_key.to_vec(),
            hex::decode("2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7")
                .unwrap()
        );
    }

    #[test]
    pub fn test_vector_1_m_0() {
        assert_keys(
            TEST_VECTOR_1_SEED,
            "m/0'",
            "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69",
            "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3",
            "8c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c",
        );
    }

    #[test]
    pub fn test_vector_1_m_0_1() {
        assert_keys(
            TEST_VECTOR_1_SEED,
            "m/0'/1'",
            "a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14",
            "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2",
            "1932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187",
        );
    }

    #[test]
    pub fn test_vector_1_m_0_1_2() {
        assert_keys(
            TEST_VECTOR_1_SEED,
            "m/0'/1'/2'",
            "2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c",
            "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9",
            "ae98736566d30ed0e9d2f4486a64bc95740d89c7db33f52121f8ea8f76ff0fc1",
        );
    }

    #[test]
    pub fn test_vector_1_m_0_1_2_2() {
        assert_keys(
            TEST_VECTOR_1_SEED,
            "m/0'/1'/2'/2'",
            "8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc",
            "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662",
            "8abae2d66361c879b900d204ad2cc4984fa2aa344dd7ddc46007329ac76c429c",
        );
    }

    #[test]
    pub fn test_vector_1_m_0_1_2_2_1000000000() {
        assert_keys(
            TEST_VECTOR_1_SEED,
            "m/0'/1'/2'/2'/1000000000'",
            "68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230",
            "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793",
            "3c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a",
        );
    }

    #[test]
    pub fn test_vector_2_m() {
        let seed = hex::decode(TEST_VECTOR_2_SEED).unwrap();
        let master_key = get_master_key_from_seed(&seed);
        assert_eq!(
            master_key.chain_code.to_vec(),
            hex::decode("ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b")
                .unwrap()
        );
        assert_eq!(
            master_key.private_key.to_vec(),
            hex::decode("171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012")
                .unwrap()
        );
    }

    #[test]
    pub fn test_vector_2_m_0() {
        assert_keys(
            TEST_VECTOR_2_SEED,
            "m/0'",
            "0b78a3226f915c082bf118f83618a618ab6dec793752624cbeb622acb562862d",
            "1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635",
            "86fab68dcb57aa196c77c5f264f215a112c22a912c10d123b0d03c3c28ef1037",
        );
    }

    #[test]
    pub fn test_vector_2_m_0_2147483647() {
        assert_keys(
            TEST_VECTOR_2_SEED,
            "m/0'/2147483647'",
            "138f0b2551bcafeca6ff2aa88ba8ed0ed8de070841f0c4ef0165df8181eaad7f",
            "ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4",
            "5ba3b9ac6e90e83effcd25ac4e58a1365a9e35a3d3ae5eb07b9e4d90bcf7506d",
        );
    }

    #[test]
    pub fn test_vector_2_m_0_2147483647_1() {
        assert_keys(
            TEST_VECTOR_2_SEED,
            "m/0'/2147483647'/1'",
            "73bd9fff1cfbde33a1b846c27085f711c0fe2d66fd32e139d3ebc28e5a4a6b90",
            "3757c7577170179c7868353ada796c839135b3d30554bbb74a4b1e4a5a58505c",
            "2e66aa57069c86cc18249aecf5cb5a9cebbfd6fadeab056254763874a9352b45",
        );
    }

    #[test]
    pub fn test_vector_2_m_0_2147483647_1_2147483646() {
        assert_keys(
            TEST_VECTOR_2_SEED,
            "m/0'/2147483647'/1'/2147483646'",
            "0902fe8a29f9140480a00ef244bd183e8a13288e4412d8389d140aac1794825a",
            "5837736c89570de861ebc173b1086da4f505d4adb387c6a1b1342d5e4ac9ec72",
            "e33c0f7d81d843c572275f287498e8d408654fdf0d1e065b84e2e6f157aab09b",
        );
    }

    #[test]
    pub fn test_vector_2_m_0_2147483647_1_2147483646_2() {
        assert_keys(
            TEST_VECTOR_2_SEED,
            "m/0'/2147483647'/1'/2147483646'/2'",
            "5d70af781f3a37b829f0d060924d5e960bdc02e85423494afc0b1a41bbe196d4",
            "551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d",
            "47150c75db263559a70d5778bf36abbab30fb061ad69f69ece61a72b0cfa4fc0",
        );
    }
}
