use crypto_common::{base16_decode, base16_encode};
use ed25519_dalek::{PublicKey, SecretKey};
use ed25519_hd_key_derivation::{checked_harden, derive_from_parsed_path, harden, DeriveError};
use hmac::Hmac;
use id::{
    curve_arithmetic::Curve, pedersen_commitment::Randomness as CommitmentRandomness,
    types::AttributeTag,
};
use keygen_bls::keygen_bls;
use pairing::bls12_381::{Bls12, G1};
use ps_sig::SigRetrievalRandomness;
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use std::fmt;

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
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

impl fmt::Display for Net {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "{}", self.net_code()) }
}

fn bls_key_bytes_from_seed(key_seed: [u8; 32]) -> <G1 as Curve>::Scalar {
    keygen_bls(&key_seed, b"").expect("All the inputs are of the correct length, this cannot fail.")
}

/// Convert 24 BIP-39 words to a 64 bytes seed.
/// As described in https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki,
/// but with an empty passphrase.
pub fn words_to_seed(words: &str) -> [u8; 64] { words_to_seed_with_passphrase(words, "") }

/// Convert 24 BIP-39 words to a 64 bytes seed.
/// As described in https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
pub fn words_to_seed_with_passphrase(words: &str, passphrase: &str) -> [u8; 64] {
    let mut salt_string: String = "mnemonic".to_owned();
    salt_string.push_str(passphrase);
    let salt = salt_string.as_bytes();

    let mut seed = [0u8; 64];
    pbkdf2::pbkdf2::<Hmac<Sha512>>(words.as_bytes(), salt, 2048, &mut seed);
    seed
}

/// A structure that is used to derive private key material and randomness
/// for identities and accounts.
///
/// The wallet should be used as a single point for deriving all required keys
/// and randomness when creating identities and accounts, as it will allow for
/// recovering the key material and randomness from just the seed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConcordiumHdWallet {
    /// The seed used as the basis for deriving keys. As all private keys are
    /// derived from this seed it means that it should be considered private
    /// and kept secret. The size is 64 bytes which corresponds to the seed
    /// that is given by a 24-word BIP39 seed phrase.
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

pub type CredId = <G1 as Curve>::Scalar;
pub type PrfKey = dodis_yampolskiy_prf::SecretKey<G1>;

impl ConcordiumHdWallet {
    fn make_path(&self, path: &[u32]) -> Result<Vec<u32>, DeriveError> {
        let root_path: Vec<u32> = vec![harden(44), harden(self.net.net_code())];
        let mut derivation_path = root_path;
        for &index in path {
            derivation_path.push(checked_harden(index)?)
        }
        Ok(derivation_path)
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
    ) -> Result<SigRetrievalRandomness<Bls12>, DeriveError> {
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
    ) -> Result<CommitmentRandomness<G1>, DeriveError> {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_common::base16_encode_string;
    use ed25519_dalek::*;
    use std::convert::TryInto;

    const TEST_SEED_1: &str = "efa5e27326f8fa0902e647b52449bf335b7b605adc387015ec903f41d95080eb71361cbc7fb78721dcd4f3926a337340aa1406df83332c44c1cdcfe100603860";
    const PASSPHRASE: &str = "TREZOR";

    fn create_wallet(net: Net, seed: &str) -> ConcordiumHdWallet {
        let wallet = ConcordiumHdWallet {
            seed: hex::decode(&seed).unwrap().try_into().unwrap(),
            net,
        };
        wallet
    }

    /// Used to verify test vectors from https://github.com/trezor/python-mnemonic/blob/master/vectors.json.
    fn check_seed_vector(words: &str, expected_seed: &str) {
        let seed = words_to_seed_with_passphrase(words, PASSPHRASE);
        assert_eq!(hex::encode(&seed), expected_seed);
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
            hex::encode(&public_key),
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

        let sk = ed25519_dalek::SecretKey::from(signing_key);
        let expanded_sk = ExpandedSecretKey::from(&sk);

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
}
