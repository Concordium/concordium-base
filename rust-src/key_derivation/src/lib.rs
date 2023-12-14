use concordium_base::{
    common::{base16_decode, base16_encode, SerdeDeserialize, SerdeSerialize},
    contracts_common::ContractAddress,
    id::{
        constants::{ArCurve, IpPairing},
        curve_arithmetic::Curve,
        pedersen_commitment::Randomness as CommitmentRandomness,
        types::{AttributeTag, HasAttributeRandomness, IpIdentity},
    },
    ps_sig::SigRetrievalRandomness,
};
use ed25519_dalek::{PublicKey, SecretKey};
use ed25519_hd_key_derivation::{checked_harden, derive_from_parsed_path, harden, DeriveError};
use hmac::Hmac;
use keygen_bls::keygen_bls;
use sha2::Sha512;
use std::{fmt, str::FromStr};
use thiserror::Error;

#[derive(Copy, Clone, Debug, SerdeSerialize, SerdeDeserialize, PartialEq)]
pub enum Net {
    Mainnet,
    Testnet,
}

impl Net {
    /// Get
    pub fn net_code(self) -> u32 {
        match self {
            Net::Mainnet => 919,
            Net::Testnet => 1,
        }
    }
}

#[derive(Debug, Error)]
#[error("{value} is not a valid value for Net")]
pub struct NetFromStrError {
    value: String,
}

impl FromStr for Net {
    type Err = NetFromStrError;

    fn from_str(input: &str) -> Result<Net, Self::Err> {
        match input {
            "Mainnet" => Ok(Net::Mainnet),
            "mainnet" => Ok(Net::Mainnet),
            "Testnet" => Ok(Net::Testnet),
            "testnet" => Ok(Net::Testnet),
            _ => Err(NetFromStrError {
                value: input.to_string(),
            }),
        }
    }
}

impl fmt::Display for Net {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "{}", self.net_code()) }
}

#[derive(Debug, Error)]
#[error("Invalid mnemonic length. The length must be 12, 15, 18, 21 or 24.")]
pub struct MnemonicLengthError;

fn bls_key_bytes_from_seed(key_seed: [u8; 32]) -> <ArCurve as Curve>::Scalar {
    keygen_bls(&key_seed, b"").expect("All the inputs are of the correct length, this cannot fail.")
}

/// Convert 12, 15, 18, 21 or 24 BIP-39 words to a 64 bytes seed.
/// As described in <https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki>,
/// but with an empty passphrase.
pub fn words_to_seed(words: &str) -> Result<[u8; 64], MnemonicLengthError> {
    words_to_seed_with_passphrase(words, "")
}

/// Convert 12, 15, 18, 21 or 24 BIP-39 words to a 64 bytes seed.
/// As described in <https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki>.
pub fn words_to_seed_with_passphrase(
    words: &str,
    passphrase: &str,
) -> Result<[u8; 64], MnemonicLengthError> {
    let words_count = words.split(' ').collect::<Vec<&str>>().len();
    let allowed_word_counts: [usize; 5] = [12, 15, 18, 21, 24];
    if !allowed_word_counts.contains(&words_count) {
        return Err(MnemonicLengthError);
    }

    let mut salt_string: String = "mnemonic".to_owned();
    salt_string.push_str(passphrase);
    let salt = salt_string.as_bytes();

    let mut seed = [0u8; 64];
    pbkdf2::pbkdf2::<Hmac<Sha512>>(words.as_bytes(), salt, 2048, &mut seed);
    Ok(seed)
}

/// A structure that is used to derive private key material and randomness
/// for identities and accounts.
///
/// The wallet should be used as a single point for deriving all required keys
/// and randomness when creating identities and accounts, as it will allow for
/// recovering the key material and randomness from just the seed.
#[derive(Clone, Debug, SerdeSerialize, SerdeDeserialize)]
pub struct ConcordiumHdWallet {
    /// The seed used as the basis for deriving keys. As all private keys are
    /// derived from this seed it means that it should be considered private
    /// and kept secret. The size is 64 bytes.
    #[serde(
        rename = "seed",
        serialize_with = "base16_encode",
        deserialize_with = "base16_decode"
    )]
    pub seed: [u8; 64],
    /// The type of blockchain network to derive keys for. Different key
    /// derivation paths are used depending on the chosen network to avoid
    /// collisions between a Testnet and Mainnet.
    #[serde(rename = "net")]
    pub net:  Net,
}

pub type CredId = <ArCurve as Curve>::Scalar;
pub type PrfKey = concordium_base::dodis_yampolskiy_prf::SecretKey<ArCurve>;

impl ConcordiumHdWallet {
    fn make_path(&self, path: &[u32]) -> Result<Vec<u32>, DeriveError> {
        let root_path: Vec<u32> = vec![harden(44), harden(self.net.net_code())];
        let mut derivation_path = root_path;
        for &index in path {
            derivation_path.push(checked_harden(index)?)
        }
        Ok(derivation_path)
    }

    fn make_verifiable_credential_path(&self, path: &[u32]) -> Result<Vec<u32>, DeriveError> {
        let root_path: Vec<u32> = vec![harden(1958950021), harden(self.net.net_code())];
        let mut derivation_path = root_path;
        for &index in path {
            derivation_path.push(checked_harden(index)?)
        }
        Ok(derivation_path)
    }

    /// Construct [`ConcordiumHdWallet`](Self) from a seed phrase. The intention
    /// is that the `phrase` is a single-space separated list of words.
    ///
    /// See also [`from_words`](Self::from_words) which ensures a canonical
    /// representation of the list of words, and is thus less error prone.
    pub fn from_seed_phrase(phrase: &str, net: Net) -> Result<Self, MnemonicLengthError> {
        let seed = words_to_seed(phrase)?;
        Ok(Self { seed, net })
    }

    /// Construct [`ConcordiumHdWallet`](Self) from a list of words.
    pub fn from_words(words: &[&str], net: Net) -> Result<Self, MnemonicLengthError> {
        Self::from_seed_phrase(&words.join(" "), net)
    }

    /// Get the account signing key for the identity provider
    /// `identity_provider_index`, identity `identity_index` and credential
    /// `credential_counter`.
    pub fn get_account_signing_key(
        &self,
        identity_provider_index: u32,
        identity_index: u32,
        credential_counter: u32,
    ) -> Result<SecretKey, DeriveError> {
        let path = self.make_path(&[
            identity_provider_index,
            identity_index,
            0,
            credential_counter,
        ])?;
        let keys = derive_from_parsed_path(&path, &self.seed)?;
        Ok(SecretKey::from_bytes(&keys.private_key)
            .expect("The byte array has correct length, so this cannot fail."))
    }

    /// Get the public key corresponding for the identity provider
    /// `identity_provider_index`, identity `identity_index` and credential
    /// `credential_counter`. Note that this is just a convenience
    /// wrapper. The same can be achieved by using [`PublicKey::from`] on
    /// the result of
    /// [`get_account_signing_key`](Self::get_account_signing_key).
    pub fn get_account_public_key(
        &self,
        identity_provider_index: u32,
        identity_index: u32,
        credential_counter: u32,
    ) -> Result<PublicKey, DeriveError> {
        let secret_key = self.get_account_signing_key(
            identity_provider_index,
            identity_index,
            credential_counter,
        )?;
        let public_key = PublicKey::from(&secret_key);
        Ok(public_key)
    }

    /// Compute the `idCredSec` for the given identity provider and identity
    /// index.
    pub fn get_id_cred_sec(
        &self,
        identity_provider_index: u32,
        identity_index: u32,
    ) -> Result<CredId, DeriveError> {
        let path = self.make_path(&[identity_provider_index, identity_index, 2])?;
        let id_cred_sec_seed = derive_from_parsed_path(&path, &self.seed)?.private_key;
        Ok(bls_key_bytes_from_seed(id_cred_sec_seed))
    }

    /// Compute the `prfKey` for the given identity provider and identity index.
    pub fn get_prf_key(
        &self,
        identity_provider_index: u32,
        identity_index: u32,
    ) -> Result<PrfKey, DeriveError> {
        let path = self.make_path(&[identity_provider_index, identity_index, 3])?;
        let prf_key_seed = derive_from_parsed_path(&path, &self.seed)?.private_key;
        Ok(PrfKey::new(bls_key_bytes_from_seed(prf_key_seed)))
    }

    /// Compute the randomness that can be used to retrieve the signature from
    /// the blinded signature on the attribute list that is received from the
    /// identity provider.
    pub fn get_blinding_randomness(
        &self,
        identity_provider_index: u32,
        identity_index: u32,
    ) -> Result<SigRetrievalRandomness<IpPairing>, DeriveError> {
        let path = self.make_path(&[identity_provider_index, identity_index, 4])?;
        let blinding_randomness_seed = derive_from_parsed_path(&path, &self.seed)?.private_key;
        Ok(SigRetrievalRandomness::new(bls_key_bytes_from_seed(
            blinding_randomness_seed,
        )))
    }

    /// Get the randomness for the specific identity provider index, identity,
    /// credential, and attribute.
    /// This randomness is used to make a commitment to the attribute when the
    /// credential is deployed to the chain, and may later be used to open the
    /// commitment, or prove certain other properties about the values contained
    /// in the commitment.
    pub fn get_attribute_commitment_randomness(
        &self,
        identity_provider_index: u32,
        identity_index: u32,
        credential_counter: u32,
        attribute_tag: AttributeTag,
    ) -> Result<CommitmentRandomness<ArCurve>, DeriveError> {
        let path = self.make_path(&[
            identity_provider_index,
            identity_index,
            5,
            credential_counter,
            attribute_tag.0.into(),
        ])?;
        let attribute_commitment_randomness_seed =
            derive_from_parsed_path(&path, &self.seed)?.private_key;
        Ok(CommitmentRandomness::new(bls_key_bytes_from_seed(
            attribute_commitment_randomness_seed,
        )))
    }

    /// Get the signing key for the verifiable credential with the given index.
    /// The signing key is used to sign the encrypted verifiable credential,
    /// which is necessary for it to be submitted to the storage contract.
    pub fn get_verifiable_credential_signing_key(
        &self,
        issuer: ContractAddress,
        verifiable_credential_index: u32,
    ) -> Result<SecretKey, DeriveError> {
        let [i1, i2, i3, i4] = split_u64_into_chunks(issuer.index);
        let [si1, si2, si3, si4] = split_u64_into_chunks(issuer.subindex);
        let path = self.make_verifiable_credential_path(&[
            0,
            i1,
            i2,
            i3,
            i4,
            si1,
            si2,
            si3,
            si4,
            verifiable_credential_index,
            0,
        ])?;
        let keys = derive_from_parsed_path(&path, &self.seed)?;
        Ok(SecretKey::from_bytes(&keys.private_key)
            .expect("The byte array has correct length, so this cannot fail."))
    }

    /// Get the public key for the verifiable credential with the given index.
    /// The public key is used to identify the specific verifiable credential
    /// within the registry contract.
    /// Note that this is just a convenience wrapper. The same can be achieved
    /// by using [`PublicKey::from`] on the result of
    /// [`get_verifiable_credential_signing_key`](Self::get_verifiable_credential_signing_key)
    pub fn get_verifiable_credential_public_key(
        &self,
        issuer: ContractAddress,
        verifiable_credential_index: u32,
    ) -> Result<PublicKey, DeriveError> {
        let signing_key =
            self.get_verifiable_credential_signing_key(issuer, verifiable_credential_index)?;
        let public_key = PublicKey::from(&signing_key);
        Ok(public_key)
    }

    /// Get the encryption key for the verifiable credential backup.
    /// The key is used to encrypt and decrypt the backup file of verifiable
    /// credentials. The backup is encrypted using `AES-256-GCM`, with this
    /// key acting as the password in the `PBKDF2WithHmacSHA256` key derivation.
    pub fn get_verifiable_credential_backup_encryption_key(
        &self,
    ) -> Result<SecretKey, DeriveError> {
        let path = self.make_verifiable_credential_path(&[1])?;
        let keys = derive_from_parsed_path(&path, &self.seed)?;
        Ok(SecretKey::from_bytes(&keys.private_key)
            .expect("The byte array has correct length, so this cannot fail."))
    }
}

fn split_u64_into_chunks(x: u64) -> [u32; 4] {
    let [b0, b1, b2, b3, b4, b5, b6, b7] = x.to_be_bytes();
    let x0 = [b0, b1];
    let x1 = [b2, b3];
    let x2 = [b4, b5];
    let x3 = [b6, b7];
    [
        u16::from_be_bytes(x0).into(),
        u16::from_be_bytes(x1).into(),
        u16::from_be_bytes(x2).into(),
        u16::from_be_bytes(x3).into(),
    ]
}

/// The [`ConcordiumHdWallet`] together indices that uniquely determine the
/// account.
pub struct CredentialContext {
    pub wallet:                  ConcordiumHdWallet,
    /// Index of the identity provider on the network.
    pub identity_provider_index: IpIdentity,
    /// Index of the identity. This is used to distinguish different identity
    /// objects for the same identity provider.
    pub identity_index:          u32,
    /// Index of a credential. This is used to generate credentials from an
    /// identity object.
    pub credential_index:        u8,
}

impl CredentialContext {
    /// Get the exponent used to determine credential registration id. This is
    /// derived from the PRF key and the credential index. This function returns
    /// an `Err` if the PRF key cannot be derived. It returns `Ok(None)` in the
    /// unlikely case the PRF key and the credential index add up to 0.
    pub fn get_cred_id_exponent(&self) -> Result<Option<<ArCurve as Curve>::Scalar>, DeriveError> {
        let prf_key = self
            .wallet
            .get_prf_key(self.identity_provider_index.0, self.identity_index)?;
        match prf_key.prf_exponent(self.credential_index) {
            Ok(exp) => Ok(Some(exp)),
            Err(_) => Ok(None),
        }
    }
}

impl HasAttributeRandomness<ArCurve> for CredentialContext {
    type ErrorType = DeriveError;

    fn get_attribute_commitment_randomness(
        &self,
        attribute_tag: &AttributeTag,
    ) -> Result<CommitmentRandomness<ArCurve>, Self::ErrorType> {
        self.wallet.get_attribute_commitment_randomness(
            self.identity_provider_index.0,
            self.identity_index,
            self.credential_index.into(),
            *attribute_tag,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use concordium_base::common::base16_encode_string;
    use ed25519_dalek::*;
    use std::convert::TryInto;

    const TEST_SEED_1: &str = "efa5e27326f8fa0902e647b52449bf335b7b605adc387015ec903f41d95080eb71361cbc7fb78721dcd4f3926a337340aa1406df83332c44c1cdcfe100603860";
    const PASSPHRASE: &str = "TREZOR";

    fn create_wallet(net: Net, seed: &str) -> ConcordiumHdWallet {
        ConcordiumHdWallet {
            seed: hex::decode(seed).unwrap().try_into().unwrap(),
            net,
        }
    }

    /// Used to verify test vectors from https://github.com/trezor/python-mnemonic/blob/master/vectors.json.
    fn check_seed_vector(words: &str, expected_seed: &str) {
        let seed = words_to_seed_with_passphrase(words, PASSPHRASE)
            .expect("Will not fail on proper word length input.");
        assert_eq!(hex::encode(seed), expected_seed);
    }

    #[test]
    pub fn account_signing_key() {
        let signing_key = create_wallet(Net::Mainnet, TEST_SEED_1)
            .get_account_signing_key(0, 55, 7)
            .unwrap();
        assert_eq!(
            hex::encode(&signing_key),
            "e4d1693c86eb9438feb9cbc3d561fbd9299e3a8b3a676eb2483b135f8dbf6eb1"
        );
    }

    #[test]
    pub fn account_public_key() {
        let public_key = create_wallet(Net::Mainnet, TEST_SEED_1)
            .get_account_public_key(1, 341, 9)
            .unwrap();
        assert_eq!(
            hex::encode(public_key),
            "d54aab7218fc683cbd4d822f7c2b4e7406c41ae08913012fab0fa992fa008e98"
        );
    }

    #[test]
    pub fn account_signing_key_matches_public_key() {
        let pk = create_wallet(Net::Mainnet, TEST_SEED_1)
            .get_account_public_key(0, 0, 0)
            .unwrap();
        let signing_key = create_wallet(Net::Mainnet, TEST_SEED_1)
            .get_account_signing_key(0, 0, 0)
            .unwrap();
        let expanded_sk = ExpandedSecretKey::from(&signing_key);

        let data_to_sign = hex::decode("abcd1234abcd5678").unwrap();
        let signature = expanded_sk.sign(&data_to_sign, &pk);

        pk.verify(&data_to_sign, &signature).expect(
            "The public key should be able to verify the signature, otherwise the keys do not \
             match.",
        );
    }

    #[test]
    pub fn id_cred_sec() {
        let id_cred_sec = create_wallet(Net::Mainnet, TEST_SEED_1)
            .get_id_cred_sec(2, 115)
            .unwrap();
        assert_eq!(
            base16_encode_string(&id_cred_sec),
            "33b9d19b2496f59ed853eb93b9d374482d2e03dd0a12e7807929d6ee54781bb1"
        );
    }

    #[test]
    pub fn prf_key() {
        let prf_key = create_wallet(Net::Mainnet, TEST_SEED_1)
            .get_prf_key(3, 35)
            .unwrap();
        assert_eq!(
            base16_encode_string(&prf_key),
            "4409e2e4acffeae641456b5f7406ecf3e1e8bd3472e2df67a9f1e8574f211bc5"
        );
    }

    #[test]
    pub fn blinding_randomness() {
        let blinding_randomness = create_wallet(Net::Mainnet, TEST_SEED_1)
            .get_blinding_randomness(4, 5713)
            .unwrap();
        assert_eq!(
            base16_encode_string(&blinding_randomness),
            "1e3633af2b1dbe5600becfea0324bae1f4fa29f90bdf419f6fba1ff520cb3167"
        );
    }

    #[test]
    pub fn attribute_commitment_randomness() {
        let attribute_commitment_randomness = create_wallet(Net::Mainnet, TEST_SEED_1)
            .get_attribute_commitment_randomness(5, 0, 4, AttributeTag(0))
            .unwrap();
        assert_eq!(
            base16_encode_string(&attribute_commitment_randomness),
            "6ef6ba6490fa37cd517d2b89a12b77edf756f89df5e6f5597440630cd4580b8f"
        );
    }

    #[test]
    pub fn testnet_account_signing_key() {
        let signing_key = create_wallet(Net::Testnet, TEST_SEED_1)
            .get_account_signing_key(0, 55, 7)
            .unwrap();
        assert_eq!(
            base16_encode_string(&signing_key),
            "aff97882c6df085e91ae2695a32d39dccb8f4b8d68d2f0db9637c3a95f845e3c"
        );
    }

    #[test]
    pub fn testnet_account_public_key() {
        let public_key = create_wallet(Net::Testnet, TEST_SEED_1)
            .get_account_public_key(1, 341, 9)
            .unwrap();
        assert_eq!(
            base16_encode_string(&public_key),
            "ef6fd561ca0291a57cdfee896245db9803a86da74c9a6c1bf0252b18f8033003"
        );
    }

    #[test]
    pub fn testnet_account_signing_key_matches_public_key() {
        let pk = create_wallet(Net::Testnet, TEST_SEED_1)
            .get_account_public_key(0, 0, 0)
            .unwrap();
        let signing_key = create_wallet(Net::Testnet, TEST_SEED_1)
            .get_account_signing_key(0, 0, 0)
            .unwrap();

        let expanded_sk = ExpandedSecretKey::from(&signing_key);

        let data_to_sign = hex::decode("abcd1234abcd5678").unwrap();
        let signature = expanded_sk.sign(&data_to_sign, &pk);

        pk.verify(&data_to_sign, &signature).expect(
            "The public key should be able to verify the signature, otherwise the keys do not \
             match.",
        );
    }

    #[test]
    pub fn testnet_id_cred_sec() {
        let id_cred_sec = create_wallet(Net::Testnet, TEST_SEED_1)
            .get_id_cred_sec(2, 115)
            .unwrap();
        assert_eq!(
            base16_encode_string(&id_cred_sec),
            "33c9c538e362c5ac836afc08210f4b5d881ba65a0a45b7e353586dad0a0f56df"
        );
    }

    #[test]
    pub fn testnet_prf_key() {
        let prf_key = create_wallet(Net::Testnet, TEST_SEED_1)
            .get_prf_key(3, 35)
            .unwrap();
        assert_eq!(
            base16_encode_string(&prf_key),
            "41d794d0b06a7a31fb79bb76c44e6b87c63e78f9afe8a772fc64d20f3d9e8e82"
        );
    }

    #[test]
    pub fn testnet_blinding_randomness() {
        let blinding_randomness = create_wallet(Net::Testnet, TEST_SEED_1)
            .get_blinding_randomness(4, 5713)
            .unwrap();
        assert_eq!(
            base16_encode_string(&blinding_randomness),
            "079eb7fe4a2e89007f411ede031543bd7f687d50341a5596e015c9f2f4c1f39b"
        );
    }

    #[test]
    pub fn testnet_attribute_commitment_randomness() {
        let attribute_commitment_randomness = create_wallet(Net::Testnet, TEST_SEED_1)
            .get_attribute_commitment_randomness(5, 0, 4, AttributeTag(0))
            .unwrap();
        assert_eq!(
            base16_encode_string(&attribute_commitment_randomness),
            "409fa90314ec8fb4a2ae812fd77fe58bfac81765cad3990478ff7a73ba6d88ae"
        );
    }

    #[test]
    pub fn words_to_seed_less_than_12_words_fail() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                        abandon abandon";
        let seed = words_to_seed_with_passphrase(mnemonic, PASSPHRASE);
        assert_eq!(seed.is_err(), true);
    }

    #[test]
    pub fn words_to_seed_more_than_24_words_fail() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon abandon abandon";
        let seed = words_to_seed_with_passphrase(mnemonic, PASSPHRASE);
        assert_eq!(seed.is_err(), true);
    }

    #[test]
    pub fn words_to_seed_13_words_fail() {
        let mnemonic_13_words = "abandon abandon abandon abandon abandon abandon abandon abandon \
                                 abandon abandon abandon abandon abandon";
        assert_eq!(
            words_to_seed_with_passphrase(mnemonic_13_words, PASSPHRASE).is_err(),
            true
        );
    }

    #[test]
    pub fn words_to_seed_14_words_fail() {
        let mnemonic_14_words = "abandon abandon abandon abandon abandon abandon abandon abandon \
                                 abandon abandon abandon abandon abandon abandon";
        assert_eq!(
            words_to_seed_with_passphrase(mnemonic_14_words, PASSPHRASE).is_err(),
            true
        );
    }

    #[test]
    pub fn words_to_seed_16_words_fail() {
        let mnemonic_16_words = "abandon abandon abandon abandon abandon abandon abandon abandon \
                                 abandon abandon abandon abandon abandon abandon abandon abandon";
        assert_eq!(
            words_to_seed_with_passphrase(mnemonic_16_words, PASSPHRASE).is_err(),
            true
        );
    }

    #[test]
    pub fn words_to_seed_17_words_fail() {
        let mnemonic_17_words = "abandon abandon abandon abandon abandon abandon abandon abandon \
                                 abandon abandon abandon abandon abandon abandon abandon abandon \
                                 abandon";
        assert_eq!(
            words_to_seed_with_passphrase(mnemonic_17_words, PASSPHRASE).is_err(),
            true
        );
    }

    #[test]
    pub fn words_to_seed_19_words_fail() {
        let mnemonic_19_words = "abandon abandon abandon abandon abandon abandon abandon abandon \
                                 abandon abandon abandon abandon abandon abandon abandon abandon \
                                 abandon abandon abandon";
        assert_eq!(
            words_to_seed_with_passphrase(mnemonic_19_words, PASSPHRASE).is_err(),
            true
        );
    }

    #[test]
    pub fn words_to_seed_20_words_fail() {
        let mnemonic_20_words = "abandon abandon abandon abandon abandon abandon abandon abandon \
                                 abandon abandon abandon abandon abandon abandon abandon abandon \
                                 abandon abandon abandon abandon";
        assert_eq!(
            words_to_seed_with_passphrase(mnemonic_20_words, PASSPHRASE).is_err(),
            true
        );
    }

    #[test]
    pub fn words_to_seed_22_words_fail() {
        let mnemonic_22_words = "abandon abandon abandon abandon abandon abandon abandon abandon \
                                 abandon abandon abandon abandon abandon abandon abandon abandon \
                                 abandon abandon abandon abandon abandon abandon";
        assert_eq!(
            words_to_seed_with_passphrase(mnemonic_22_words, PASSPHRASE).is_err(),
            true
        );
    }

    #[test]
    pub fn words_to_seed_23_words_fail() {
        let mnemonic_23_words = "abandon abandon abandon abandon abandon abandon abandon abandon \
                                 abandon abandon abandon abandon abandon abandon abandon abandon \
                                 abandon abandon abandon abandon abandon abandon abandon";
        assert_eq!(
            words_to_seed_with_passphrase(mnemonic_23_words, PASSPHRASE).is_err(),
            true
        );
    }

    #[test]
    pub fn words_to_seed_12_words_vector_1() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                        abandon abandon about";
        check_seed_vector(mnemonic, "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04");
    }

    #[test]
    pub fn words_to_seed_12_words_vector_2() {
        let mnemonic =
            "legal winner thank year wave sausage worth useful legal winner thank yellow";
        check_seed_vector(mnemonic, "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607");
    }

    #[test]
    pub fn words_to_seed_12_words_vector_3() {
        let mnemonic =
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage above";
        check_seed_vector(mnemonic, "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8");
    }

    #[test]
    pub fn words_to_seed_12_words_vector_4() {
        let mnemonic = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";
        check_seed_vector(mnemonic, "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069");
    }

    #[test]
    pub fn words_to_seed_12_words_vector_5() {
        let mnemonic =
            "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic";
        check_seed_vector(mnemonic, "274ddc525802f7c828d8ef7ddbcdc5304e87ac3535913611fbbfa986d0c9e5476c91689f9c8a54fd55bd38606aa6a8595ad213d4c9c9f9aca3fb217069a41028");
    }

    #[test]
    pub fn words_to_seed_12_words_vector_6() {
        let mnemonic = "scheme spot photo card baby mountain device kick cradle pact join borrow";
        check_seed_vector(mnemonic, "ea725895aaae8d4c1cf682c1bfd2d358d52ed9f0f0591131b559e2724bb234fca05aa9c02c57407e04ee9dc3b454aa63fbff483a8b11de949624b9f1831a9612");
    }

    #[test]
    pub fn words_to_seed_12_words_vector_7() {
        let mnemonic = "cat swing flag economy stadium alone churn speed unique patch report train";
        check_seed_vector(mnemonic, "deb5f45449e615feff5640f2e49f933ff51895de3b4381832b3139941c57b59205a42480c52175b6efcffaa58a2503887c1e8b363a707256bdd2b587b46541f5");
    }

    #[test]
    pub fn words_to_seed_12_words_vector_8() {
        let mnemonic =
            "vessel ladder alter error federal sibling chat ability sun glass valve picture";
        check_seed_vector(mnemonic, "2aaa9242daafcee6aa9d7269f17d4efe271e1b9a529178d7dc139cd18747090bf9d60295d0ce74309a78852a9caadf0af48aae1c6253839624076224374bc63f");
    }

    #[test]
    pub fn words_to_seed_15_words() {
        let mnemonic = "impose cliff file course grab shift accuse feel head butter link trim \
                        wine convince entire";
        check_seed_vector(mnemonic, "b3b42d645dab8feda3a00c0f726b872c8f97d43066e32c7ee5fa0f04390ef4f3de038e3024c6d8460d4b3085292daaa86bcd6f121e7fe2470a6b7eeb41e35c64");
    }

    #[test]
    pub fn words_to_seed_18_words_vector_1() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon abandon abandon abandon agent";
        check_seed_vector(mnemonic, "035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca06da5a9a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa");
    }

    #[test]
    pub fn words_to_seed_18_words_vector_2() {
        let mnemonic = "legal winner thank year wave sausage worth useful legal winner thank year \
                        wave sausage worth useful legal will";
        check_seed_vector(mnemonic, "f2b94508732bcbacbcc020faefecfc89feafa6649a5491b8c952cede496c214a0c7b3c392d168748f2d4a612bada0753b52a1c7ac53c1e93abd5c6320b9e95dd");
    }

    #[test]
    pub fn words_to_seed_18_words_vector_3() {
        let mnemonic = "letter advice cage absurd amount doctor acoustic avoid letter advice cage \
                        absurd amount doctor acoustic avoid letter always";
        check_seed_vector(mnemonic, "107d7c02a5aa6f38c58083ff74f04c607c2d2c0ecc55501dadd72d025b751bc27fe913ffb796f841c49b1d33b610cf0e91d3aa239027f5e99fe4ce9e5088cd65");
    }

    #[test]
    pub fn words_to_seed_18_words_vector_4() {
        let mnemonic = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when";
        check_seed_vector(mnemonic, "0cd6e5d827bb62eb8fc1e262254223817fd068a74b5b449cc2f667c3f1f985a76379b43348d952e2265b4cd129090758b3e3c2c49103b5051aac2eaeb890a528");
    }

    #[test]
    pub fn words_to_seed_18_words_vector_5() {
        let mnemonic = "gravity machine north sort system female filter attitude volume fold club \
                        stay feature office ecology stable narrow fog";
        check_seed_vector(mnemonic, "628c3827a8823298ee685db84f55caa34b5cc195a778e52d45f59bcf75aba68e4d7590e101dc414bc1bbd5737666fbbef35d1f1903953b66624f910feef245ac");
    }

    #[test]
    pub fn words_to_seed_18_words_vector_6() {
        let mnemonic = "horn tenant knee talent sponsor spell gate clip pulse soap slush warm \
                        silver nephew swap uncle crack brave";
        check_seed_vector(mnemonic, "fd579828af3da1d32544ce4db5c73d53fc8acc4ddb1e3b251a31179cdb71e853c56d2fcb11aed39898ce6c34b10b5382772db8796e52837b54468aeb312cfc3d");
    }

    #[test]
    pub fn words_to_seed_18_words_vector_7() {
        let mnemonic = "light rule cinnamon wrap drastic word pride squirrel upgrade then income \
                        fatal apart sustain crack supply proud access";
        check_seed_vector(mnemonic, "4cbdff1ca2db800fd61cae72a57475fdc6bab03e441fd63f96dabd1f183ef5b782925f00105f318309a7e9c3ea6967c7801e46c8a58082674c860a37b93eda02");
    }

    #[test]
    pub fn words_to_seed_18_words_vector_8() {
        let mnemonic = "scissors invite lock maple supreme raw rapid void congress muscle digital \
                        elegant little brisk hair mango congress clump";
        check_seed_vector(mnemonic, "7b4a10be9d98e6cba265566db7f136718e1398c71cb581e1b2f464cac1ceedf4f3e274dc270003c670ad8d02c4558b2f8e39edea2775c9e232c7cb798b069e88");
    }

    #[test]
    pub fn words_to_seed_21_words() {
        let mnemonic = "half scissors snack noble such gasp fiscal oxygen news mention twenty \
                        record vault novel race chunk junior leisure stamp novel must";
        check_seed_vector(mnemonic, "63ade55fc2d4b76b439b57cbb575a81daec28f210599ff3c624fb02239f8f36a4dbeeb03e3d89b9e7a0b2b114ef4e579b77a6d8bd86030b9a22e45b86cca09a6");
    }

    #[test]
    pub fn words_to_seed_24_words_vector_1() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon art";
        check_seed_vector(mnemonic, "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8");
    }

    #[test]
    pub fn words_to_seed_24_words_vector_2() {
        let mnemonic = "legal winner thank year wave sausage worth useful legal winner thank year \
                        wave sausage worth useful legal winner thank year wave sausage worth title";
        check_seed_vector(mnemonic, "bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87");
    }

    #[test]
    pub fn words_to_seed_24_words_vector_3() {
        let mnemonic = "letter advice cage absurd amount doctor acoustic avoid letter advice cage \
                        absurd amount doctor acoustic avoid letter advice cage absurd amount \
                        doctor acoustic bless";
        check_seed_vector(mnemonic, "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f");
    }

    #[test]
    pub fn words_to_seed_24_words_vector_4() {
        let mnemonic = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo \
                        zoo zoo zoo zoo zoo vote";
        check_seed_vector(mnemonic, "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad");
    }

    #[test]
    pub fn words_to_seed_24_words_vector_5() {
        let mnemonic = "hamster diagram private dutch cause delay private meat slide toddler \
                        razor book happy fancy gospel tennis maple dilemma loan word shrug \
                        inflict delay length";
        check_seed_vector(mnemonic, "64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d20b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440");
    }

    #[test]
    pub fn words_to_seed_24_words_vector_6() {
        let mnemonic = "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft \
                        ostrich alcohol speed nation flash devote level hobby quick inner drive \
                        ghost inside";
        check_seed_vector(mnemonic, "72be8e052fc4919d2adf28d5306b5474b0069df35b02303de8c1729c9538dbb6fc2d731d5f832193cd9fb6aeecbc469594a70e3dd50811b5067f3b88b28c3e8d");
    }

    #[test]
    pub fn words_to_seed_24_words_vector_7() {
        let mnemonic = "all hour make first leader extend hole alien behind guard gospel lava \
                        path output census museum junior mass reopen famous sing advance salt \
                        reform";
        check_seed_vector(mnemonic, "26e975ec644423f4a4c4f4215ef09b4bd7ef924e85d1d17c4cf3f136c2863cf6df0a475045652c57eb5fb41513ca2a2d67722b77e954b4b3fc11f7590449191d");
    }

    #[test]
    pub fn words_to_seed_24_words_vector_8() {
        let mnemonic = "void come effort suffer camp survey warrior heavy shoot primary clutch \
                        crush open amazing screen patrol group space point ten exist slush \
                        involve unfold";
        check_seed_vector(mnemonic, "01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998");
    }

    #[test]
    pub fn mainnet_verifiable_credential_signing_key() {
        let signing_key = create_wallet(Net::Mainnet, TEST_SEED_1)
            .get_verifiable_credential_signing_key(ContractAddress::new(1, 2), 1)
            .unwrap();
        assert_eq!(
            hex::encode(&signing_key),
            "670d904509ce09372deb784e702d4951d4e24437ad3879188d71ae6db51f3301"
        );
    }

    #[test]
    pub fn mainnet_verifiable_credential_public_key() {
        let public_key = create_wallet(Net::Mainnet, TEST_SEED_1)
            .get_verifiable_credential_public_key(ContractAddress::new(3, 1232), 341)
            .unwrap();
        assert_eq!(
            hex::encode(public_key),
            "16afdb3cb3568b5ad8f9a0fa3c741b065642de8c53e58f7920bf449e63ff2bf9"
        );
    }

    #[test]
    pub fn mainnet_verifiable_credential_signing_key_matches_public_key() {
        let wallet = create_wallet(Net::Mainnet, TEST_SEED_1);

        let public_key = wallet
            .get_verifiable_credential_public_key(ContractAddress::new(1337, 0), 0)
            .unwrap();
        let signing_key = wallet
            .get_verifiable_credential_signing_key(ContractAddress::new(1337, 0), 0)
            .unwrap();
        let expanded_sk = ExpandedSecretKey::from(&signing_key);

        let data_to_sign = hex::decode("abcd1234abcd5678").unwrap();
        let signature = expanded_sk.sign(&data_to_sign, &public_key);

        public_key.verify(&data_to_sign, &signature).expect(
            "The public key should be able to verify the signature, otherwise the keys do not \
             match.",
        );
    }

    #[test]
    pub fn mainnet_verifiable_credential_backup_encryption_key() {
        let key = create_wallet(Net::Mainnet, TEST_SEED_1)
            .get_verifiable_credential_backup_encryption_key()
            .unwrap();
        assert_eq!(
            hex::encode(key),
            "5032086037b639f116642752460bf2e2b89d7278fe55511c028b194ba77192a1"
        );
    }

    #[test]
    pub fn testnet_verifiable_credential_signing_key() {
        let signing_key = create_wallet(Net::Testnet, TEST_SEED_1)
            .get_verifiable_credential_signing_key(ContractAddress::new(13, 0), 1)
            .unwrap();
        assert_eq!(
            hex::encode(&signing_key),
            "c75a161b97a1e204d9f31202308958e541e14f0b14903bd220df883bd06702bb"
        );
    }

    #[test]
    pub fn testnet_verifiable_credential_public_key() {
        let public_key = create_wallet(Net::Testnet, TEST_SEED_1)
            .get_verifiable_credential_public_key(ContractAddress::new(17, 0), 341)
            .unwrap();
        assert_eq!(
            hex::encode(public_key),
            "c52a30475bac88da9e65471cf9cf59f99dcce22ce31de580b3066597746b394a"
        );
    }

    #[test]
    pub fn testnet_verifiable_credential_backup_encryption_key() {
        let key = create_wallet(Net::Testnet, TEST_SEED_1)
            .get_verifiable_credential_backup_encryption_key()
            .unwrap();
        assert_eq!(
            hex::encode(key),
            "10f85290e33b1a79a0330180c4b6c67fd9ad1a1dd3d0f918ab1cbcf8787fc3ca"
        );
    }

    #[test]
    pub fn testnet_verifiable_credential_signing_key_matches_public_key() {
        let wallet = create_wallet(Net::Testnet, TEST_SEED_1);

        let public_key = wallet
            .get_verifiable_credential_public_key(ContractAddress::new(13, 0), 0)
            .unwrap();
        let signing_key = wallet
            .get_verifiable_credential_signing_key(ContractAddress::new(13, 0), 0)
            .unwrap();
        let expanded_sk = ExpandedSecretKey::from(&signing_key);

        let data_to_sign = hex::decode("abcd1234abcd5678").unwrap();
        let signature = expanded_sk.sign(&data_to_sign, &public_key);

        public_key.verify(&data_to_sign, &signature).expect(
            "The public key should be able to verify the signature, otherwise the keys do not \
             match.",
        );
    }

    #[test]
    fn capitalized_mainnet_net_mapped_correctly() {
        let result = Net::from_str(&"Mainnet").expect("Should not fail on valid input");
        assert_eq!(result, Net::Mainnet);
    }

    #[test]
    fn capitalized_testnet_net_mapped_correctly() {
        let result = Net::from_str(&"Testnet").expect("Should not fail on valid input");
        assert_eq!(result, Net::Testnet);
    }

    #[test]
    fn mainnet_net_mapped_correctly() {
        let result = Net::from_str(&"mainnet").expect("Should not fail on valid input");
        assert_eq!(result, Net::Mainnet);
    }

    #[test]
    fn testnet_net_mapped_correctly() {
        let result = Net::from_str(&"testnet").expect("Should not fail on valid input");
        assert_eq!(result, Net::Testnet);
    }

    #[test]
    fn invalid_net_input_fails() {
        let result = Net::from_str(&"Stagenet");
        assert_eq!(result.is_err(), true);
    }
}
