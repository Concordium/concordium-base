use anyhow::{bail, Error, Result};
use concordium_base::{
    common::{base16_decode_string, base16_encode_string},
    contracts_common::ContractAddress,
    id::{constants, types::AttributeTag},
    pedersen_commitment::{CommitmentKey as PedersenKey, Randomness as PedersenRandomness, Value},
};
use key_derivation::{ConcordiumHdWallet, Net};
use std::convert::TryInto;

type HexString = String;

/// Helper function for constructing a [`ConcordiumHdWallet`] from a
/// seed encoded as hex and a supplied [`Net`].
/// ### Errors
/// - Will fail if the provided seed is not hex, or is not representing exactly
///   64 bytes.
pub fn get_wallet(seed_as_hex: HexString, net: Net) -> Result<ConcordiumHdWallet, Error> {
    let seed_decoded = hex::decode(&seed_as_hex)?;
    let seed: [u8; 64] = match seed_decoded.try_into() {
        Ok(s) => s,
        Err(_) => bail!("The provided seed {} was not 64 bytes", seed_as_hex),
    };

    Ok(ConcordiumHdWallet { seed, net })
}

fn get_net(net_as_str: &str) -> Result<Net> {
    match net_as_str.parse() {
        Ok(n) => Ok(n),
        Err(e) => bail!(e),
    }
}

/// Get the hex encoded account signing key for the seed `seed_as_hex`, the net
/// `net`, identity provider `identity_provider_index`, identity
/// `identity_index` and credential `credential_counter`.
pub fn get_account_signing_key_aux(
    seed_as_hex: HexString,
    net_as_str: &str,
    identity_provider_index: u32,
    identity_index: u32,
    credential_counter: u32,
) -> Result<String> {
    let net = get_net(net_as_str)?;
    let wallet = get_wallet(seed_as_hex, net)?;
    let key = wallet.get_account_signing_key(
        identity_provider_index,
        identity_index,
        credential_counter,
    )?;
    Ok(base16_encode_string(&key))
}

/// Get the hex encoded account public key for the seed `seed_as_hex`, the net
/// `net`, identity provider `identity_provider_index`, identity
/// `identity_index` and credential `credential_counter`.
pub fn get_account_public_key_aux(
    seed_as_hex: HexString,
    net_as_str: &str,
    identity_provider_index: u32,
    identity_index: u32,
    credential_counter: u32,
) -> Result<HexString> {
    let net = get_net(net_as_str)?;
    let wallet = get_wallet(seed_as_hex, net)?;
    let key = wallet.get_account_public_key(
        identity_provider_index,
        identity_index,
        credential_counter,
    )?;
    Ok(base16_encode_string(&key))
}

/// Get the hex encoded PRF-key for the seed `seed_as_hex`, the net `net`,
/// identity provider `identity_provider_index` and identity `identity_index`.
pub fn get_prf_key_aux(
    seed_as_hex: HexString,
    net_as_str: &str,
    identity_provider_index: u32,
    identity_index: u32,
) -> Result<HexString> {
    let net = get_net(net_as_str)?;
    let wallet = get_wallet(seed_as_hex, net)?;
    let key = wallet.get_prf_key(identity_provider_index, identity_index)?;
    Ok(base16_encode_string(&key))
}

/// Get the hex encoded IdCredSec for the seed `seed_as_hex`, the net `net`,
/// identity provider `identity_provider_index` and identity `identity_index`.
pub fn get_id_cred_sec_aux(
    seed_as_hex: HexString,
    net_as_str: &str,
    identity_provider_index: u32,
    identity_index: u32,
) -> Result<HexString> {
    let net = get_net(net_as_str)?;
    let wallet = get_wallet(seed_as_hex, net)?;
    let key = wallet.get_id_cred_sec(identity_provider_index, identity_index)?;
    Ok(base16_encode_string(&key))
}

/// Get the hex encoded signature blinding randomness for the seed
/// `seed_as_hex`, the net `net`, identity provider `identity_provider_index`
/// and identity `identity_index`.
pub fn get_signature_blinding_randomness_aux(
    seed_as_hex: HexString,
    net_as_str: &str,
    identity_provider_index: u32,
    identity_index: u32,
) -> Result<HexString> {
    let net: Net = get_net(net_as_str)?;
    let wallet = get_wallet(seed_as_hex, net)?;
    let key = wallet.get_blinding_randomness(identity_provider_index, identity_index)?;
    Ok(base16_encode_string(&key))
}

/// Get the hex encoded attribute commitment randomness for the seed
/// `seed_as_hex`, the net `net`, identity provider `identity_provider_index`,
/// identity `identity_index`, credential counter `credential_counter` and the
/// provided attribute `attribute`.
pub fn get_attribute_commitment_randomness_aux(
    seed_as_hex: HexString,
    net_as_str: &str,
    identity_provider_index: u32,
    identity_index: u32,
    credential_counter: u32,
    attribute: u8,
) -> Result<HexString> {
    let net: Net = get_net(net_as_str)?;
    let wallet = get_wallet(seed_as_hex, net)?;
    let key = wallet.get_attribute_commitment_randomness(
        identity_provider_index,
        identity_index,
        credential_counter,
        AttributeTag(attribute),
    )?;
    Ok(base16_encode_string(&key))
}

/// Get the hex encoded verifiable credential signing key for seed
/// `seed_as_hex`, net `net`, issuer index `issuer_index`, issuer subindex
/// `issuer_subindex` and verifiable credential
/// index `verifiable_credential_index`.
pub fn get_verifiable_credential_signing_key_aux(
    seed_as_hex: HexString,
    net_as_str: &str,
    issuer_index: u64,
    issuer_subindex: u64,
    verifiable_credential_index: u32,
) -> Result<HexString> {
    let net = get_net(net_as_str)?;
    let issuer: ContractAddress = ContractAddress::new(issuer_index, issuer_subindex);
    let wallet = get_wallet(seed_as_hex, net)?;
    let key = wallet.get_verifiable_credential_signing_key(issuer, verifiable_credential_index)?;
    Ok(base16_encode_string(&key))
}

/// Get the hex encoded verifiable credential public key for seed `seed_as_hex`,
/// net `net`, issuer index `issuer_index`, issuer subindex `issuer_subindex`
/// and verifiable credential index `verifiable_credential_index`.
pub fn get_verifiable_credential_public_key_aux(
    seed_as_hex: HexString,
    net_as_str: &str,
    issuer_index: u64,
    issuer_subindex: u64,
    verifiable_credential_index: u32,
) -> Result<HexString> {
    let net = get_net(net_as_str)?;
    let issuer: ContractAddress = ContractAddress::new(issuer_index, issuer_subindex);
    let wallet = get_wallet(seed_as_hex, net)?;
    let key = wallet.get_verifiable_credential_public_key(issuer, verifiable_credential_index)?;
    Ok(base16_encode_string(&key))
}

/// Get the hex encoded verifiable credential backup encryption key for
/// seed `seed_as_hex` and net `net`.
pub fn get_verifiable_credential_backup_encryption_key_aux(
    seed_as_hex: HexString,
    net_as_str: &str,
) -> Result<HexString> {
    let net = get_net(net_as_str)?;
    let wallet = get_wallet(seed_as_hex, net)?;
    let key = wallet.get_verifiable_credential_backup_encryption_key()?;
    Ok(base16_encode_string(&key))
}

/// Get the hex encoded credential id for seed `seed_as_hex`, net `net`,
/// identity provider index `identity_provider_index`, identity index
/// `identity_index`, credential `credential_counter` and the on chain
/// commitment key `raw_on_chain_commitment_key`.
pub fn get_credential_id_aux(
    seed_as_hex: HexString,
    net_as_str: &str,
    identity_provider_index: u32,
    identity_index: u32,
    credential_counter: u8,
    raw_on_chain_commitment_key: &str,
) -> Result<HexString> {
    let net = get_net(net_as_str)?;
    let wallet = get_wallet(seed_as_hex, net)?;
    let prf_key = wallet.get_prf_key(identity_provider_index, identity_index)?;

    let cred_id_exponent = prf_key.prf_exponent(credential_counter)?;
    let on_chain_commitment_key: PedersenKey<constants::ArCurve> =
        base16_decode_string(raw_on_chain_commitment_key)?;
    let cred_id = on_chain_commitment_key
        .hide(
            &Value::<constants::ArCurve>::new(cred_id_exponent),
            &PedersenRandomness::zero(),
        )
        .0;
    Ok(base16_encode_string(&cred_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SEED_1: &str = "efa5e27326f8fa0902e647b52449bf335b7b605adc387015ec903f41d95080eb71361cbc7fb78721dcd4f3926a337340aa1406df83332c44c1cdcfe100603860";
    const MAINNET: &str = "Mainnet";

    #[test]
    pub fn mainnet_credential_id() {
        let credential_id = get_credential_id_aux(TEST_SEED_1.to_string(), MAINNET, 10, 50, 5, "b14cbfe44a02c6b1f78711176d5f437295367aa4f2a8c2551ee10d25a03adc69d61a332a058971919dad7312e1fc94c5a8d45e64b6f917c540eee16c970c3d4b7f3caf48a7746284878e2ace21c82ea44bf84609834625be1f309988ac523fac").unwrap();
        assert_eq!(credential_id, "8a3a87f3f38a7a507d1e85dc02a92b8bcaa859f5cf56accb3c1bc7c40e1789b4933875a38dd4c0646ca3e940a02c42d8");
    }

    #[test]
    pub fn mainnet_verifiable_credential_backup_encryption_key() {
        let key =
            get_verifiable_credential_backup_encryption_key_aux(TEST_SEED_1.to_string(), MAINNET)
                .unwrap();
        assert_eq!(
            key,
            "5032086037b639f116642752460bf2e2b89d7278fe55511c028b194ba77192a1"
        );
    }

    #[test]
    pub fn mainnet_verifiable_credential_public_key() {
        let public_key = get_verifiable_credential_public_key_aux(
            TEST_SEED_1.to_string(),
            MAINNET,
            3,
            1232,
            341,
        )
        .unwrap();
        assert_eq!(
            public_key,
            "16afdb3cb3568b5ad8f9a0fa3c741b065642de8c53e58f7920bf449e63ff2bf9"
        );
    }

    #[test]
    pub fn mainnet_verifiable_credential_signing_key() {
        let signing_key =
            get_verifiable_credential_signing_key_aux(TEST_SEED_1.to_string(), MAINNET, 1, 2, 1)
                .unwrap();
        assert_eq!(
            &signing_key,
            "670d904509ce09372deb784e702d4951d4e24437ad3879188d71ae6db51f3301"
        );
    }

    #[test]
    pub fn attribute_commitment_randomness() {
        let attribute_commitment_randomness =
            get_attribute_commitment_randomness_aux(TEST_SEED_1.to_string(), MAINNET, 5, 0, 4, 0)
                .unwrap();
        assert_eq!(
            attribute_commitment_randomness,
            "6ef6ba6490fa37cd517d2b89a12b77edf756f89df5e6f5597440630cd4580b8f"
        );
    }

    #[test]
    pub fn blinding_randomness() {
        let blinding_randomness =
            get_signature_blinding_randomness_aux(TEST_SEED_1.to_string(), MAINNET, 4, 5713)
                .unwrap();
        assert_eq!(
            blinding_randomness,
            "1e3633af2b1dbe5600becfea0324bae1f4fa29f90bdf419f6fba1ff520cb3167"
        );
    }

    #[test]
    pub fn id_cred_sec() {
        let id_cred_sec = get_id_cred_sec_aux(TEST_SEED_1.to_string(), MAINNET, 2, 115).unwrap();
        assert_eq!(
            &id_cred_sec,
            "33b9d19b2496f59ed853eb93b9d374482d2e03dd0a12e7807929d6ee54781bb1"
        );
    }

    #[test]
    pub fn prf_key() {
        let prf_key = get_prf_key_aux(TEST_SEED_1.to_string(), MAINNET, 3, 35).unwrap();
        assert_eq!(
            &prf_key,
            "4409e2e4acffeae641456b5f7406ecf3e1e8bd3472e2df67a9f1e8574f211bc5"
        );
    }

    #[test]
    pub fn account_public_key() {
        let public_key =
            get_account_public_key_aux(TEST_SEED_1.to_string(), MAINNET, 1, 341, 9).unwrap();
        assert_eq!(
            &public_key,
            "d54aab7218fc683cbd4d822f7c2b4e7406c41ae08913012fab0fa992fa008e98"
        );
    }

    #[test]
    pub fn account_signing_key() {
        let signing_key =
            get_account_signing_key_aux(TEST_SEED_1.to_string(), MAINNET, 0, 55, 7).unwrap();
        assert_eq!(
            &signing_key,
            "e4d1693c86eb9438feb9cbc3d561fbd9299e3a8b3a676eb2483b135f8dbf6eb1"
        );
    }

    #[test]
    fn get_wallet_on_invalid_seed_fails() {
        let invalid_seed_hex = "5269005c740e9eb598ea734b2d74a8e9";

        let wallet = get_wallet(invalid_seed_hex.to_string(), Net::Mainnet);

        assert_eq!(
            wallet.unwrap_err().to_string(),
            format!("The provided seed {} was not 64 bytes", invalid_seed_hex)
        );
    }
}
