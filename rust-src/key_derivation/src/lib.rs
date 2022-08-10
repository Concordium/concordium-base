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
use crypto_common::{base16_decode, base16_encode};

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
pub fn words_to_seed(words: &str) -> [u8; 64] {
    // As described in https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki

    let salt = b"mnemonic";

    let mut seed = [0u8; 64];
    pbkdf2::pbkdf2::<Hmac<Sha512>>(words.as_bytes(), &salt[..], 2048, &mut seed);
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

    /// Get the account signing key for the identity `identity_index` and
    /// credential `credential_counter`.
    pub fn get_account_signing_key(
        &self,
        identity_index: u32,
        credential_counter: u32,
    ) -> Result<SecretKey, DeriveError> {
        let path = self.make_path(&[identity_index, 0, credential_counter])?;
        let keys = derive_from_parsed_path(&path, &self.seed)?;
        Ok(SecretKey::from_bytes(&keys.private_key)
            .expect("The byte array has correct length, so this cannot fail."))
    }

    /// Get the public key corresponding for the identity `identity_index` and
    /// credential `credential_counter`. Note that this is just a convenience
    /// wrapper. The same can be achieved by using [`PublicKey::from`] on
    /// the result of
    /// [`get_account_signing_key`](Self::get_account_signing_key).
    pub fn get_account_public_key(
        &self,
        identity_index: u32,
        credential_counter: u32,
    ) -> Result<PublicKey, DeriveError> {
        let secret_key = self.get_account_signing_key(identity_index, credential_counter)?;
        let public_key = PublicKey::from(&secret_key);
        Ok(public_key)
    }

    /// Compute the `idCredSec` for the given identity index.
    pub fn get_id_cred_sec(&self, identity_index: u32) -> Result<CredId, DeriveError> {
        let path = self.make_path(&[identity_index, 2])?;
        let id_cred_sec_seed = derive_from_parsed_path(&path, &self.seed)?.private_key;
        Ok(bls_key_bytes_from_seed(id_cred_sec_seed))
    }

    /// Compute the `prfKey` for the given identity index.
    pub fn get_prf_key(&self, identity_index: u32) -> Result<PrfKey, DeriveError> {
        let path = self.make_path(&[identity_index, 3])?;
        let prf_key_seed = derive_from_parsed_path(&path, &self.seed)?.private_key;
        Ok(PrfKey::new(bls_key_bytes_from_seed(prf_key_seed)))
    }

    /// Compute the randomness that can be used to retrieve the signature from
    /// the blinded signature on the attribute list that is received from the
    /// identity provider.
    pub fn get_blinding_randomness(
        &self,
        identity_index: u32,
    ) -> Result<SigRetrievalRandomness<Bls12>, DeriveError> {
        let path = self.make_path(&[identity_index, 4])?;
        let blinding_randomness_seed = derive_from_parsed_path(&path, &self.seed)?.private_key;
        Ok(SigRetrievalRandomness::new(bls_key_bytes_from_seed(
            blinding_randomness_seed,
        )))
    }

    /// Get the randomness for the specific identity, credential, and attribute.
    /// This randomness is used to make a commitment to the attribute when the
    /// credential is deployed to the chain, and may later be used to open the
    /// commitment, or prove certain other properties about the values contained
    /// in the commitment.
    pub fn get_attribute_commitment_randomness(
        &self,
        identity_index: u32,
        credential_counter: u32,
        attribute_tag: AttributeTag,
    ) -> Result<CommitmentRandomness<G1>, DeriveError> {
        let path = self.make_path(&[
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
    use hex;
    use std::convert::TryInto;

    const TEST_SEED_1: &str = "efa5e27326f8fa0902e647b52449bf335b7b605adc387015ec903f41d95080eb71361cbc7fb78721dcd4f3926a337340aa1406df83332c44c1cdcfe100603860";

    fn create_wallet(net: Net, seed: &str) -> ConcordiumHdWallet {
        let wallet = ConcordiumHdWallet {
            seed: hex::decode(&seed).unwrap().try_into().unwrap(),
            net,
        };
        wallet
    }

    #[test]
    pub fn account_signing_key() {
        let signing_key = create_wallet(Net::Mainnet, TEST_SEED_1)
            .get_account_signing_key(55, 7)
            .unwrap();
        assert_eq!(
            hex::encode(&signing_key),
            "b44f7320f156971927596f471a2302e5be8d3717a85bedfc5a0e2994615eea7d"
        );
    }

    #[test]
    pub fn account_public_key() {
        let public_key = create_wallet(Net::Mainnet, TEST_SEED_1)
            .get_account_public_key(341, 9)
            .unwrap();
        assert_eq!(
            hex::encode(&public_key),
            "cc2f4d34bdd0d8e206cf1704516d7ce533f83773492f670144fcbeda33774c5c"
        );
    }

    #[test]
    pub fn account_signing_key_matches_public_key() {
        let pk = create_wallet(Net::Mainnet, TEST_SEED_1)
            .get_account_public_key(0, 0)
            .unwrap();
        let signing_key = create_wallet(Net::Mainnet, TEST_SEED_1)
            .get_account_signing_key(0, 0)
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
    pub fn id_cred_sec() {
        let id_cred_sec = create_wallet(Net::Mainnet, TEST_SEED_1)
            .get_id_cred_sec(115)
            .unwrap();
        assert_eq!(
            base16_encode_string(&id_cred_sec),
            "27db5d5c1e346670bd2d9b4235a180629c750b067a83942e55fc43303531c1aa"
        );
    }

    #[test]
    pub fn prf_key() {
        let prf_key = create_wallet(Net::Mainnet, TEST_SEED_1)
            .get_prf_key(35)
            .unwrap();
        assert_eq!(
            base16_encode_string(&prf_key),
            "1c8a30e2136dcc5e4f8b6fa359e908718d65ea2c2638d8fa6ff72c24d8ed3d68"
        );
    }

    #[test]
    pub fn blinding_randomness() {
        let blinding_randomness = create_wallet(Net::Mainnet, TEST_SEED_1)
            .get_blinding_randomness(5713)
            .unwrap();
        assert_eq!(
            base16_encode_string(&blinding_randomness),
            "2924d5bc605cc06632e061cec491c1f6b476b3abe51e526f641bcea355cd8bf6"
        );
    }

    #[test]
    pub fn attribute_commitment_randomness() {
        let attribute_commitment_randomness = create_wallet(Net::Mainnet, TEST_SEED_1)
            .get_attribute_commitment_randomness(0, 4, AttributeTag(0))
            .unwrap();
        assert_eq!(
            base16_encode_string(&attribute_commitment_randomness),
            "462e12bbda5b58ac6e3be920d41adce8b9d0779c13c34913b1f61748f0bbf051"
        );
    }

    #[test]
    pub fn testnet_account_signing_key() {
        let signing_key = create_wallet(Net::Testnet, TEST_SEED_1)
            .get_account_signing_key(55, 7)
            .unwrap();
        assert_eq!(
            base16_encode_string(&signing_key),
            "67a5619aaa5d67b548f83c857c92024f57a9d902f273a62f283f2536fcb203aa"
        );
    }

    #[test]
    pub fn testnet_account_public_key() {
        let public_key = create_wallet(Net::Testnet, TEST_SEED_1)
            .get_account_public_key(341, 9)
            .unwrap();
        assert_eq!(
            base16_encode_string(&public_key),
            "b90e8e5f45c1181e93d5cad6ad7414036538c6c806140cb4bf7957d8ff350004"
        );
    }

    #[test]
    pub fn testnet_account_signing_key_matches_public_key() {
        let pk = create_wallet(Net::Testnet, TEST_SEED_1)
            .get_account_public_key(0, 0)
            .unwrap();
        let signing_key = create_wallet(Net::Testnet, TEST_SEED_1)
            .get_account_signing_key(0, 0)
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
            .get_id_cred_sec(115)
            .unwrap();
        assert_eq!(
            base16_encode_string(&id_cred_sec),
            "719130a7429a69d1f673a7d051043e63ab237098928ffa2066bdddbc3f93bdb1"
        );
    }

    #[test]
    pub fn testnet_prf_key() {
        let prf_key = create_wallet(Net::Testnet, TEST_SEED_1)
            .get_prf_key(35)
            .unwrap();
        assert_eq!(
            base16_encode_string(&prf_key),
            "623cc233afcdf8063800615d7b52aa535533f0ab054891b4f821e2912018a2fb"
        );
    }

    #[test]
    pub fn testnet_blinding_randomness() {
        let blinding_randomness = create_wallet(Net::Testnet, TEST_SEED_1)
            .get_blinding_randomness(5713)
            .unwrap();
        assert_eq!(
            base16_encode_string(&blinding_randomness),
            "2d6093f16ce3cc2d1d7eca2c7c4c7a80449980b10baf0b3366dc70ba2564c7aa"
        );
    }

    #[test]
    pub fn testnet_attribute_commitment_randomness() {
        let attribute_commitment_randomness = create_wallet(Net::Testnet, TEST_SEED_1)
            .get_attribute_commitment_randomness(0, 4, AttributeTag(0))
            .unwrap();
        assert_eq!(
            base16_encode_string(&attribute_commitment_randomness),
            "50cb39a9009b36c8ce21fdedab9db520de300a6405e5ffe4786c3c75b09f9ae0"
        );
    }
}
