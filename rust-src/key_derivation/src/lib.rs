use ed25519_hd_key_derivation::derive;
use keygen_bls::keygen_bls;
use pairing::bls12_381::FrRepr;
use std::fmt;

pub enum Net {
    Mainnet,
    Testnet,
}

impl fmt::Display for Net {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Net::Mainnet => write!(f, "919"),
            Net::Testnet => write!(f, "1"),
        }
    }
}

fn bls_key_bytes_from_seed(key_seed: [u8; 32]) -> [u8; 32] {
    let bls_key_fr = keygen_bls(&key_seed, b"").unwrap();
    let fr_repr = FrRepr::from(bls_key_fr);
    let fr_repr_ref = fr_repr.as_ref();
    let key_bytes: Vec<u8> = fr_repr_ref
        .iter()
        .rev()
        .flat_map(|val| val.to_be_bytes())
        .collect();
    let mut bls_key = [0u8; 32];
    bls_key.clone_from_slice(&key_bytes[0..32]);
    bls_key
}

pub struct ConcordiumHdWallet {
    seed: Vec<u8>,
    net:  Net,
}

impl ConcordiumHdWallet {
    fn make_path(&self, path: &str) -> String {
        let root_path: &str = "m/44'";
        let derivation_path = format!("{}/{}'/{}", root_path, &self.net, path);
        derivation_path
    }

    pub fn get_account_signing_key(&self, identity_index: u32, credential_index: u32) -> [u8; 32] {
        let path = self.make_path(&format!("{}'/0'/{}'", identity_index, credential_index));
        derive(&path, &self.seed).unwrap().key
    }

    pub fn get_account_public_key(&self, identity_index: u32, credential_index: u32) -> [u8; 32] {
        let account_signing_key = self.get_account_signing_key(identity_index, credential_index);
        let secret_key = ed25519_dalek::SecretKey::from_bytes(&account_signing_key).unwrap();
        let public_key = ed25519_dalek::PublicKey::from(&secret_key);
        public_key.to_bytes()
    }

    pub fn get_id_cred_sec(&self, identity_index: u32) -> [u8; 32] {
        let path = self.make_path(&format!("{}'/2'", identity_index));
        let id_cred_sec_seed = derive(&path, &self.seed).unwrap().key;
        bls_key_bytes_from_seed(id_cred_sec_seed)
    }

    pub fn get_prf_key(&self, identity_index: u32) -> [u8; 32] {
        let path = self.make_path(&format!("{}'/3'", identity_index));
        let prf_key_seed = derive(&path, &self.seed).unwrap().key;
        bls_key_bytes_from_seed(prf_key_seed)
    }

    pub fn get_blinding_randomness(&self, identity_index: u32) -> [u8; 32] {
        let path = self.make_path(&format!("{}'/4'", identity_index));
        let blinding_randomness_seed = derive(&path, &self.seed).unwrap().key;
        bls_key_bytes_from_seed(blinding_randomness_seed)
    }

    pub fn get_attribute_commitment_randomness(
        &self,
        identity_index: u32,
        credential_index: u32,
        attribute_index: u32,
    ) -> [u8; 32] {
        let path = self.make_path(&format!(
            "{}'/5'/{}'/{}'",
            identity_index, credential_index, attribute_index
        ));
        let attribute_commitment_randomness_seed = derive(&path, &self.seed).unwrap().key;
        bls_key_bytes_from_seed(attribute_commitment_randomness_seed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::*;
    use hex;

    const TEST_SEED_1: &str = "efa5e27326f8fa0902e647b52449bf335b7b605adc387015ec903f41d95080eb71361cbc7fb78721dcd4f3926a337340aa1406df83332c44c1cdcfe100603860";

    fn create_wallet(net: Net, seed: &str) -> ConcordiumHdWallet {
        let wallet = ConcordiumHdWallet {
            seed: hex::decode(&seed).unwrap(),
            net,
        };
        wallet
    }

    #[test]
    pub fn account_signing_key() {
        let id_cred_sec = create_wallet(Net::Mainnet, TEST_SEED_1).get_account_signing_key(55, 7);
        assert_eq!(
            hex::encode(&id_cred_sec),
            "b44f7320f156971927596f471a2302e5be8d3717a85bedfc5a0e2994615eea7d"
        );
    }

    #[test]
    pub fn account_public_key() {
        let public_key = create_wallet(Net::Mainnet, TEST_SEED_1).get_account_public_key(341, 9);
        assert_eq!(
            hex::encode(&public_key),
            "cc2f4d34bdd0d8e206cf1704516d7ce533f83773492f670144fcbeda33774c5c"
        );
    }

    #[test]
    pub fn account_signing_key_matches_public_key() {
        let public_key = create_wallet(Net::Mainnet, TEST_SEED_1).get_account_public_key(0, 0);
        let signing_key = create_wallet(Net::Mainnet, TEST_SEED_1).get_account_signing_key(0, 0);

        let sk = ed25519_dalek::SecretKey::from_bytes(&signing_key).unwrap();
        let expanded_sk = ExpandedSecretKey::from(&sk);
        let pk = ed25519_dalek::PublicKey::from_bytes(&public_key).unwrap();

        let data_to_sign = hex::decode("abcd1234abcd5678").unwrap();
        let signature = expanded_sk.sign(&data_to_sign, &pk);

        pk.verify(&data_to_sign, &signature).expect(
            "The public key should be able to verify the signature, otherwise the keys do not \
             match.",
        );
    }

    #[test]
    pub fn id_cred_sec() {
        let id_cred_sec = create_wallet(Net::Mainnet, TEST_SEED_1).get_id_cred_sec(115);
        assert_eq!(
            hex::encode(&id_cred_sec),
            "27db5d5c1e346670bd2d9b4235a180629c750b067a83942e55fc43303531c1aa"
        );
    }

    #[test]
    pub fn prf_key() {
        let prf_key = create_wallet(Net::Mainnet, TEST_SEED_1).get_prf_key(35);
        assert_eq!(
            hex::encode(&prf_key),
            "1c8a30e2136dcc5e4f8b6fa359e908718d65ea2c2638d8fa6ff72c24d8ed3d68"
        );
    }

    #[test]
    pub fn blinding_randomness() {
        let blinding_randomness =
            create_wallet(Net::Mainnet, TEST_SEED_1).get_blinding_randomness(5713);
        assert_eq!(
            hex::encode(&blinding_randomness),
            "2924d5bc605cc06632e061cec491c1f6b476b3abe51e526f641bcea355cd8bf6"
        );
    }

    #[test]
    pub fn attribute_commitment_randomness() {
        let attribute_commitment_randomness =
            create_wallet(Net::Mainnet, TEST_SEED_1).get_attribute_commitment_randomness(0, 4, 0);
        assert_eq!(
            hex::encode(&attribute_commitment_randomness),
            "462e12bbda5b58ac6e3be920d41adce8b9d0779c13c34913b1f61748f0bbf051"
        );
    }

    #[test]
    pub fn testnet_account_signing_key() {
        let id_cred_sec = create_wallet(Net::Testnet, TEST_SEED_1).get_account_signing_key(55, 7);
        assert_eq!(
            hex::encode(&id_cred_sec),
            "67a5619aaa5d67b548f83c857c92024f57a9d902f273a62f283f2536fcb203aa"
        );
    }

    #[test]
    pub fn testnet_account_public_key() {
        let public_key = create_wallet(Net::Testnet, TEST_SEED_1).get_account_public_key(341, 9);
        assert_eq!(
            hex::encode(&public_key),
            "b90e8e5f45c1181e93d5cad6ad7414036538c6c806140cb4bf7957d8ff350004"
        );
    }

    #[test]
    pub fn testnet_account_signing_key_matches_public_key() {
        let public_key = create_wallet(Net::Testnet, TEST_SEED_1).get_account_public_key(0, 0);
        let signing_key = create_wallet(Net::Testnet, TEST_SEED_1).get_account_signing_key(0, 0);

        let sk = ed25519_dalek::SecretKey::from_bytes(&signing_key).unwrap();
        let expanded_sk = ExpandedSecretKey::from(&sk);
        let pk = ed25519_dalek::PublicKey::from_bytes(&public_key).unwrap();

        let data_to_sign = hex::decode("abcd1234abcd5678").unwrap();
        let signature = expanded_sk.sign(&data_to_sign, &pk);

        pk.verify(&data_to_sign, &signature).expect(
            "The public key should be able to verify the signature, otherwise the keys do not \
             match.",
        );
    }

    #[test]
    pub fn testnet_id_cred_sec() {
        let id_cred_sec = create_wallet(Net::Testnet, TEST_SEED_1).get_id_cred_sec(115);
        assert_eq!(
            hex::encode(&id_cred_sec),
            "719130a7429a69d1f673a7d051043e63ab237098928ffa2066bdddbc3f93bdb1"
        );
    }

    #[test]
    pub fn testnet_prf_key() {
        let prf_key = create_wallet(Net::Testnet, TEST_SEED_1).get_prf_key(35);
        assert_eq!(
            hex::encode(&prf_key),
            "623cc233afcdf8063800615d7b52aa535533f0ab054891b4f821e2912018a2fb"
        );
    }

    #[test]
    pub fn testnet_blinding_randomness() {
        let blinding_randomness =
            create_wallet(Net::Testnet, TEST_SEED_1).get_blinding_randomness(5713);
        assert_eq!(
            hex::encode(&blinding_randomness),
            "2d6093f16ce3cc2d1d7eca2c7c4c7a80449980b10baf0b3366dc70ba2564c7aa"
        );
    }

    #[test]
    pub fn testnet_attribute_commitment_randomness() {
        let attribute_commitment_randomness =
            create_wallet(Net::Testnet, TEST_SEED_1).get_attribute_commitment_randomness(0, 4, 0);
        assert_eq!(
            hex::encode(&attribute_commitment_randomness),
            "50cb39a9009b36c8ce21fdedab9db520de300a6405e5ffe4786c3c75b09f9ae0"
        );
    }
}
