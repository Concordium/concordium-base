use anyhow::{bail, ensure, Context};
use concordium_base::{
    base::{self, Energy, Nonce},
    cis2_types::{self, AdditionalData},
    common::{
        self, c_char,
        types::{Amount, KeyIndex, KeyPair, TransactionSignature, TransactionTime},
        Deserial,
    },
    contracts_common::{self, schema::VersionedModuleSchema, AccountAddress, Address, Cursor},
    encrypted_transfers,
    hashes::{HashBytes, TransactionSignHash},
    id::{
        self, account_holder,
        constants::{ArCurve, AttributeKind},
        id_proof_types::{Statement, StatementWithContext},
        pedersen_commitment::{Randomness as PedersenRandomness, Value as PedersenValue},
        ps_sig,
        secret_sharing::Threshold,
        types::*,
    },
    smart_contracts::{OwnedReceiveName, Parameter},
    transactions::{
        self,
        construct::{GivenEnergy, PreAccountTransaction},
        ConfigureBakerKeysPayload, ConfigureBakerPayload, ConfigureDelegationPayload,
        ExactSizeTransactionSigner, InitContractPayload, Memo, TransactionSigner,
        UpdateContractPayload,
    },
};
use dodis_yampolskiy_prf as prf;
use ed25519_hd_key_derivation::DeriveError;
use either::Either::{Left, Right};
use elgamal::BabyStepGiantStep;
use key_derivation::{ConcordiumHdWallet, Net};
use pairing::bls12_381::Bls12;
use rand::thread_rng;
use serde_json::{from_str, from_value, to_string, Value};
use sha2::{Digest, Sha256};
use std::{
    cmp::max,
    collections::{BTreeMap, HashMap},
    convert::TryInto,
    ffi::{CStr, CString},
    str::FromStr,
};

/// A ConcordiumHdWallet together with an identity provider index, an identity
/// index and a credential index for the credential to be created. A
/// CredentialContext can then be parsed to the `create_credential` function due
/// to the implementation of `HasAttributeRandomness` below.
struct CredentialContext {
    wallet:                  ConcordiumHdWallet,
    identity_provider_index: u32,
    identity_index:          u32,
    credential_index:        u32,
}

impl HasAttributeRandomness<ArCurve> for CredentialContext {
    type ErrorType = DeriveError;

    fn get_attribute_commitment_randomness(
        &self,
        attribute_tag: AttributeTag,
    ) -> Result<PedersenRandomness<ArCurve>, Self::ErrorType> {
        self.wallet.get_attribute_commitment_randomness(
            self.identity_provider_index,
            self.identity_index,
            self.credential_index,
            attribute_tag,
        )
    }
}

/// Context for a transaction to send.
#[derive(common::SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
struct TransferContext {
    pub from:   AccountAddress,
    pub to:     Option<AccountAddress>,
    pub expiry: TransactionTime,
    pub nonce:  Nonce,
    pub keys:   AccountKeys,
    #[allow(dead_code)] // this is no longer used since
    // the library knows about energy costs.
    pub energy: Energy,
}

/// Sign the given pre-transaction and return the signature and serialized body.
fn make_signatures(
    keys: &AccountKeys,
    pre_tx: PreAccountTransaction,
) -> (TransactionSignature, Vec<u8>) {
    let body = common::to_bytes(&pre_tx);
    let tx = pre_tx.sign(keys);
    (tx.signature, body)
}

/// Compute the message digest for some message and an account. The message
/// digest is constructed so that it cannot be the prefix of an actual
/// account transaction.
fn get_message_digest(account_address: [u8; 32], message: String) -> TransactionSignHash {
    let prepend_bytes = [0_u8; 8];
    let message_as_bytes = message.as_bytes();

    let mut hasher = Sha256::new();
    hasher.update(account_address);
    hasher.update(prepend_bytes);
    hasher.update(message_as_bytes);
    let hash: [u8; 32] = hasher.finalize().into();
    HashBytes::new(hash)
}

fn sign_message_with_keys(
    keys: &AccountKeys,
    msg: String,
    account_address: [u8; 32],
) -> TransactionSignature {
    let hash_to_sign = get_message_digest(account_address, msg);
    keys.sign_transaction_hash(&hash_to_sign)
}

/// Create a JSON encoding of an encrypted transfer transaction.
fn create_encrypted_transfer_aux(input: &str) -> anyhow::Result<String> {
    let v: Value = from_str(input)?;
    let ctx: TransferContext = from_value(v.clone())?;
    let ctx_to = match ctx.to {
        Some(to) => to,
        None => bail!("to account should be present"),
    };

    // context with parameters
    let global_context: GlobalContext<ArCurve> = try_get(&v, "global")?;

    // plaintext amount to transfer
    let amount: Amount = try_get(&v, "amount")?;

    let maybe_memo: Option<Memo> = match v.get("memo") {
        Some(m) => from_value(m.clone())?,
        None => None,
    };

    let sender_sk: elgamal::SecretKey<ArCurve> = try_get(&v, "senderSecretKey")?;

    let receiver_pk = try_get(&v, "receiverPublicKey")?;

    let input_amount = try_get(&v, "inputEncryptedAmount")?;

    // Should be safe on iOS and Android, by calling SecRandomCopyBytes/getrandom,
    // respectively.
    let mut csprng = thread_rng();

    let payload = encrypted_transfers::make_transfer_data(
        &global_context,
        &receiver_pk,
        &sender_sk,
        &input_amount,
        amount,
        &mut csprng,
    );
    let payload = match payload {
        Some(payload) => payload,
        None => bail!("Could not produce payload."),
    };

    let remaining_amount = payload.remaining_amount.clone();
    let pre_tx = match maybe_memo {
        Some(memo) => transactions::construct::encrypted_transfer_with_memo(
            ctx.keys.num_keys(),
            ctx.from,
            ctx.nonce,
            ctx.expiry,
            ctx_to,
            payload,
            memo,
        ),
        None => transactions::construct::encrypted_transfer(
            ctx.keys.num_keys(),
            ctx.from,
            ctx.nonce,
            ctx.expiry,
            ctx_to,
            payload,
        ),
    };

    let (signatures, body) = make_signatures(&ctx.keys, pre_tx);

    let response = serde_json::json!({
        "signatures": signatures,
        "transaction": hex::encode(&body),
        "remaining": remaining_amount,
    });

    Ok(to_string(&response)?)
}

fn get_parameter_as_json(
    parameter: Parameter,
    receive_name: &OwnedReceiveName,
    schema: &str,
    schema_version: &Option<u8>,
) -> anyhow::Result<Value> {
    let schema_bytes = base64::decode(schema)?;

    let contract_name = receive_name.as_receive_name().contract_name();
    let entrypoint_name = &receive_name.as_receive_name().entrypoint_name().to_string();

    let module_schema = VersionedModuleSchema::new(&schema_bytes, schema_version)?;
    let receive_schema = module_schema.get_receive_param_schema(contract_name, entrypoint_name)?;

    let mut parameter_cursor = Cursor::new(parameter.as_ref());
    match receive_schema.to_json(&mut parameter_cursor) {
        Ok(schema) => Ok(schema),
        Err(e) => Err(anyhow::anyhow!(
            "Unable to parse parameter to JSON: {:?}",
            e
        )),
    }
}

fn parameter_to_json_aux(input: &str) -> anyhow::Result<String> {
    let v: Value = from_str(input)?;
    let serialized_parameter: String = try_get(&v, "parameter")?;
    let receive_name: OwnedReceiveName = try_get(&v, "receiveName")?;
    let parameter: Parameter = Parameter::new_unchecked(hex::decode(serialized_parameter)?);
    let schema: String = try_get(&v, "schema")?;
    let schema_version: Option<u8> = maybe_get(&v, "schemaVersion")?;
    let parameter_as_json =
        get_parameter_as_json(parameter, &receive_name, &schema, &schema_version)?;

    Ok(to_string(&parameter_as_json)?)
}

fn sign_message_aux(input: &str) -> anyhow::Result<String> {
    let v: Value = from_str(input)?;
    let message: String = try_get(&v, "message")?;
    let address: String = try_get(&v, "address")?;
    let account_address = address.parse::<AccountAddress>()?.0;
    let keys: AccountKeys = try_get(&v, "keys")?;
    Ok(to_string(&sign_message_with_keys(
        &keys,
        message,
        account_address,
    ))?)
}

#[derive(common::SerdeDeserialize)]
/// Either total energy that can be spent by the transaction, or just the energy
/// for execution. Which one is more suitable to specify depenends a bit on the
/// context, so we support both.
enum SpecifiedEnergy {
    #[serde(rename = "maxContractExecutionEnergy")]
    ExecutionOnly(Energy),
    #[serde(rename = "maxEnergy")]
    Total(Energy),
}

#[derive(common::SerdeDeserialize)]
#[serde(tag = "type", content = "payload")]
enum JSONPayload {
    InitContract {
        #[serde(flatten)]
        payload: InitContractPayload,
        #[serde(flatten)]
        energy:  SpecifiedEnergy,
    },
    Update {
        #[serde(flatten)]
        payload: UpdateContractPayload,
        #[serde(flatten)]
        energy:  SpecifiedEnergy,
    },
    Transfer {
        amount: Amount,
        to:     AccountAddress,
    },
}

/// Context to create an unsigned transaction.
#[derive(common::SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
struct TransactionContext {
    pub from:    AccountAddress,
    pub expiry:  TransactionTime,
    pub nonce:   Nonce,
    #[serde(flatten)]
    pub payload: JSONPayload,
    pub keys:    AccountKeys,
}

fn create_account_transaction_aux(input: &str) -> anyhow::Result<String> {
    let v: Value = from_str(input)?;
    let ctx: TransactionContext = from_value(v)?;
    let pre_tx = match ctx.payload {
        JSONPayload::Update { payload, energy } => {
            let energy = match energy {
                SpecifiedEnergy::ExecutionOnly(energy) => GivenEnergy::Add {
                    energy,
                    num_sigs: ctx.keys.num_keys(),
                },
                SpecifiedEnergy::Total(e) => GivenEnergy::Absolute(e),
            };
            let payload = transactions::Payload::Update { payload };
            transactions::construct::make_transaction(
                ctx.from, ctx.nonce, ctx.expiry, energy, payload,
            )
        }
        JSONPayload::InitContract { payload, energy } => {
            let energy = match energy {
                SpecifiedEnergy::ExecutionOnly(energy) => GivenEnergy::Add {
                    energy,
                    num_sigs: ctx.keys.num_keys(),
                },
                SpecifiedEnergy::Total(e) => GivenEnergy::Absolute(e),
            };
            let payload = transactions::Payload::InitContract { payload };
            transactions::construct::make_transaction(
                ctx.from, ctx.nonce, ctx.expiry, energy, payload,
            )
        }
        JSONPayload::Transfer { amount, to } => transactions::construct::transfer(
            ctx.keys.num_keys(),
            ctx.from,
            ctx.nonce,
            ctx.expiry,
            to,
            amount,
        ),
    };
    let (signatures, body) = make_signatures(&ctx.keys, pre_tx);

    let response = serde_json::json!({
        "signatures": signatures,
        "transaction": hex::encode(&body),
    });

    Ok(to_string(&response)?)
}

/// Context to create parameters for a token transfer (smart contract update).
#[derive(common::SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
struct TokenTransferContext {
    pub from:     AccountAddress,
    pub to:       AccountAddress,
    pub amount:   cis2_types::TokenAmount,
    pub token_id: cis2_types::TokenId,
}

fn serialize_token_transfer_parameters_aux(input: &str) -> anyhow::Result<String> {
    let v: Value = from_str(input)?;
    let ctx: TokenTransferContext = from_value(v)?;

    let params = cis2_types::TransferParams::new_unchecked(
        [cis2_types::Transfer {
            token_id: ctx.token_id,
            amount:   ctx.amount,
            from:     Address::Account(ctx.from),
            to:       cis2_types::Receiver::Account(ctx.to),
            data:     AdditionalData::default(),
        }]
        .to_vec(),
    );

    let response = serde_json::json!({
        "parameter": hex::encode(contracts_common::to_bytes(&params)),
    });

    Ok(to_string(&response)?)
}

fn create_transfer_aux(input: &str) -> anyhow::Result<String> {
    let v: Value = from_str(input)?;

    let ctx: TransferContext = from_value(v.clone())?;
    let ctx_to = match ctx.to {
        Some(to) => to,
        None => bail!("to account should be present"),
    };

    let amount: Amount = try_get(&v, "amount")?;
    let maybe_memo: Option<Memo> = match v.get("memo") {
        Some(m) => Some(from_value(m.clone())?),
        None => None,
    };

    let pre_tx = match maybe_memo {
        Some(memo) => transactions::construct::transfer_with_memo(
            ctx.keys.num_keys(),
            ctx.from,
            ctx.nonce,
            ctx.expiry,
            ctx_to,
            amount,
            memo,
        ),
        None => transactions::construct::transfer(
            ctx.keys.num_keys(),
            ctx.from,
            ctx.nonce,
            ctx.expiry,
            ctx_to,
            amount,
        ),
    };

    let (signatures, body) = make_signatures(&ctx.keys, pre_tx);

    let response = serde_json::json!({
        "signatures": signatures,
        "transaction": hex::encode(&body),
    });

    Ok(to_string(&response)?)
}

fn create_configure_delegation_transaction_aux(input: &str) -> anyhow::Result<String> {
    let v: Value = from_str(input)?;

    let ctx: TransferContext = from_value(v.clone())?;
    let payload: ConfigureDelegationPayload = from_value(v)?;

    let pre_tx = transactions::construct::configure_delegation(
        ctx.keys.num_keys(),
        ctx.from,
        ctx.nonce,
        ctx.expiry,
        payload,
    );
    let (signatures, body) = make_signatures(&ctx.keys, pre_tx);

    let response = serde_json::json!({
        "signatures": signatures,
        "transaction": hex::encode(&body),
    });

    Ok(to_string(&response)?)
}

fn generate_baker_keys_aux() -> anyhow::Result<String> {
    let mut csprng = thread_rng();
    let keys = base::BakerKeyPairs::generate(&mut csprng);
    Ok(to_string(&keys)?)
}

fn create_configure_baker_transaction_aux(input: &str) -> anyhow::Result<String> {
    let v: Value = from_str(input)?;

    let ctx: TransferContext = from_value(v.clone())?;

    let capital: Option<Amount> = maybe_get(&v, "capital")?;
    let restake_earnings: Option<bool> = maybe_get(&v, "restakeEarnings")?;
    let open_for_delegation: Option<base::OpenStatus> = maybe_get(&v, "openStatus")?;
    let metadata_url: Option<base::UrlText> = maybe_get(&v, "metadataUrl")?;
    let transaction_fee_commission: Option<base::AmountFraction> =
        maybe_get(&v, "transactionFeeCommission")?;
    let baking_reward_commission: Option<base::AmountFraction> =
        maybe_get(&v, "bakingRewardCommission")?;
    let finalization_reward_commission: Option<base::AmountFraction> =
        maybe_get(&v, "finalizationRewardCommission")?;
    let maybe_baker_keys: Option<base::BakerKeyPairs> = maybe_get(&v, "bakerKeys")?;

    let keys_with_proofs = match maybe_baker_keys {
        Some(ref keys) => {
            let mut csprng = thread_rng();
            Some(ConfigureBakerKeysPayload::new(keys, ctx.from, &mut csprng))
        }
        None => None,
    };

    let configure_baker_payload = ConfigureBakerPayload {
        capital,
        restake_earnings,
        open_for_delegation,
        keys_with_proofs,
        metadata_url,
        transaction_fee_commission,
        baking_reward_commission,
        finalization_reward_commission,
    };

    let pre_tx = transactions::construct::configure_baker(
        ctx.keys.num_keys(),
        ctx.from,
        ctx.nonce,
        ctx.expiry,
        configure_baker_payload,
    );

    let (signatures, body) = make_signatures(&ctx.keys, pre_tx);
    let response = serde_json::json!({
        "signatures": signatures,
        "transaction": hex::encode(&body),
    });

    Ok(to_string(&response)?)
}

fn create_pub_to_sec_transfer_aux(input: &str) -> anyhow::Result<String> {
    let v: Value = from_str(input)?;

    let ctx: TransferContext = from_value(v.clone())?;

    let amount: Amount = try_get(&v, "amount")?;

    // context with parameters
    let global_context: GlobalContext<ArCurve> = try_get(&v, "global")?;

    let encryption =
        encrypted_transfers::encrypt_amount_with_fixed_randomness(&global_context, amount);
    let pre_tx = transactions::construct::transfer_to_encrypted(
        ctx.keys.num_keys(),
        ctx.from,
        ctx.nonce,
        ctx.expiry,
        amount,
    );

    let (signatures, body) = make_signatures(&ctx.keys, pre_tx);
    let response = serde_json::json!({
        "signatures": signatures,
        "transaction": hex::encode(&body),
        "addedSelfEncryptedAmount": encryption
    });

    Ok(to_string(&response)?)
}

/// Create a JSON encoding of a secret to public amount transaction.
fn create_sec_to_pub_transfer_aux(input: &str) -> anyhow::Result<String> {
    let v: Value = from_str(input)?;
    let ctx: TransferContext = from_value(v.clone())?;

    // context with parameters
    let global_context: GlobalContext<ArCurve> = try_get(&v, "global")?;

    // plaintext amount to transfer
    let amount: Amount = try_get(&v, "amount")?;

    let sender_sk: elgamal::SecretKey<ArCurve> = try_get(&v, "senderSecretKey")?;

    let input_amount = try_get(&v, "inputEncryptedAmount")?;

    // Should be safe on iOS and Android, by calling SecRandomCopyBytes/getrandom,
    // respectively.
    let mut csprng = thread_rng();

    let payload = encrypted_transfers::make_sec_to_pub_transfer_data(
        &global_context,
        &sender_sk,
        &input_amount,
        amount,
        &mut csprng,
    );
    let payload = match payload {
        Some(payload) => payload,
        None => bail!("Could not produce payload."),
    };

    let remaining_amount = payload.remaining_amount.clone();

    let pre_tx = transactions::construct::transfer_to_public(
        ctx.keys.num_keys(),
        ctx.from,
        ctx.nonce,
        ctx.expiry,
        payload,
    );

    let (signatures, body) = make_signatures(&ctx.keys, pre_tx);

    let response = serde_json::json!({
        "signatures": signatures,
        "transaction": hex::encode(&body),
        "remaining": remaining_amount,
    });

    Ok(to_string(&response)?)
}

fn check_account_address_aux(input: &str) -> bool { input.parse::<AccountAddress>().is_ok() }

/// Aggregate two encrypted amounts together into one.
fn combine_encrypted_amounts_aux(left: &str, right: &str) -> anyhow::Result<String> {
    let left = from_str(left)?;
    let right = from_str(right)?;
    Ok(to_string(&encrypted_transfers::aggregate::<ArCurve>(
        &left, &right,
    ))?)
}

/// Try to extract a field with a given name from the JSON value.
fn try_get<A: serde::de::DeserializeOwned>(v: &Value, fname: &str) -> anyhow::Result<A> {
    match v.get(fname) {
        Some(v) => Ok(from_value(v.clone())?),
        None => bail!(format!("Field {} not present, but should be.", fname)),
    }
}

/// Extract a field with a given name from the JSON value if it exists.
fn maybe_get<A: serde::de::DeserializeOwned>(v: &Value, fname: &str) -> anyhow::Result<Option<A>> {
    match v.get(fname) {
        Some(v) => Ok(Some(from_value(v.clone())?)),
        None => Ok(None),
    }
}

/// This function creates the identity object request
fn create_id_request_and_private_data_aux(input: &str) -> anyhow::Result<String> {
    let v: Value = from_str(input)?;

    let ip_info: IpInfo<Bls12> = try_get(&v, "ipInfo")?;
    let global_context: GlobalContext<ArCurve> = try_get(&v, "global")?;

    let ars_infos: BTreeMap<ArIdentity, ArInfo<ArCurve>> = try_get(&v, "arsInfos")?;

    let num_of_ars = ars_infos.len();
    let threshold = match v.get("arThreshold") {
        Some(v) => {
            let threshold: u8 = from_value(v.clone())?;
            ensure!(threshold > 0, "arThreshold must be at least 1.");
            ensure!(
                num_of_ars >= usize::from(threshold),
                "Number of anonymity revokers in arsInfos should be at least arThreshold."
            );
            Threshold(threshold)
        }
        None => {
            // arThreshold not specified, use `number of anonymity revokers` - 1 or 1 in the
            // case of only a single anonymity revoker.
            ensure!(
                num_of_ars > 0,
                "arsInfos should have at least 1 anonymity revoker."
            );
            Threshold(max((num_of_ars - 1).try_into().unwrap_or(255), 1))
        }
    };

    // Should be safe on iOS and Android, by calling SecRandomCopyBytes/getrandom,
    // respectively.
    let mut csprng = thread_rng();

    let prf_key = prf::SecretKey::generate(&mut csprng);

    let chi = CredentialHolderInfo::<ArCurve> {
        id_cred: IdCredentials::generate(&mut csprng),
    };

    let aci = AccCredentialInfo {
        cred_holder_info: chi,
        prf_key,
    };
    let randomness = ps_sig::SigRetrievalRandomness::generate_non_zero(&mut csprng);
    let id_use_data = IdObjectUseData { aci, randomness };

    // Choice of anonymity revokers, all of them in this implementation.
    let context = IpContext::new(&ip_info, &ars_infos, &global_context);

    // Generating account data for the initial account
    let mut keys = std::collections::BTreeMap::new();
    let mut csprng = thread_rng();
    keys.insert(
        KeyIndex(0),
        concordium_base::common::types::KeyPair::from(ed25519_dalek::Keypair::generate(
            &mut csprng,
        )),
    );

    let initial_acc_data = InitialAccountData {
        keys,
        threshold: SignatureThreshold(1),
    };
    let (pio, _) = {
        match account_holder::generate_pio(&context, threshold, &id_use_data, &initial_acc_data) {
            Some(x) => x,
            None => bail!("Generating the pre-identity object failed."),
        }
    };

    let acc_keys = AccountKeys::from(initial_acc_data);

    let reg_id = &pio.pub_info_for_ip.reg_id;
    let address = account_address_from_registration_id(reg_id);
    let secret_key = elgamal::SecretKey {
        generator: *global_context.elgamal_generator(),
        // the unwrap is safe since we've generated the RegID successfully above.
        scalar:    id_use_data.aci.prf_key.prf_exponent(0).unwrap(),
    };

    let response = serde_json::json!({
        "idObjectRequest": common::Versioned::new(common::VERSION_0, pio),
        "privateIdObjectData": common::Versioned::new(common::VERSION_0, id_use_data),
        "initialAccountData": serde_json::json!({
            "accountKeys": acc_keys,
            "encryptionSecretKey": secret_key,
            "encryptionPublicKey": elgamal::PublicKey::from(&secret_key),
            "accountAddress": address,
        })
    });

    Ok(to_string(&response)?)
}

/// This function creates the identity object request, version 1,
/// i.e., no initial account creation involved.
/// The prf key, id cred sec, and the blinding randomness are deterministically
/// generated.
fn create_id_request_and_private_data_v1_aux(input: &str) -> anyhow::Result<String> {
    let v: Value = from_str(input)?;

    let ip_info: IpInfo<Bls12> = try_get(&v, "ipInfo")?;
    let global_context: GlobalContext<ArCurve> = try_get(&v, "global")?;

    let ars_infos: BTreeMap<ArIdentity, ArInfo<ArCurve>> = try_get(&v, "arsInfos")?;

    let wallet = parse_wallet_input(&v)?;
    let identity_provider_index = ip_info.ip_identity.0;
    let identity_index: u32 = try_get(&v, "identityIndex")?;

    let prf_key: prf::SecretKey<ArCurve> =
        wallet.get_prf_key(identity_provider_index, identity_index)?;

    let id_cred_sec: PedersenValue<ArCurve> =
        PedersenValue::new(wallet.get_id_cred_sec(identity_provider_index, identity_index)?);
    let id_cred: IdCredentials<ArCurve> = IdCredentials { id_cred_sec };

    let sig_retrievel_randomness: ps_sig::SigRetrievalRandomness<Bls12> =
        wallet.get_blinding_randomness(identity_provider_index, identity_index)?;

    let num_of_ars = ars_infos.len();
    let threshold = match v.get("arThreshold") {
        Some(v) => {
            let threshold: u8 = from_value(v.clone())?;
            ensure!(threshold > 0, "arThreshold must be at least 1.");
            ensure!(
                num_of_ars >= usize::from(threshold),
                "Number of anonymity revokers in arsInfos should be at least arThreshold."
            );
            Threshold(threshold)
        }
        None => {
            // arThreshold not specified, use `number of anonymity revokers` - 1 or 1 in the
            // case of only a single anonymity revoker.
            ensure!(
                num_of_ars > 0,
                "arsInfos should have at least 1 anonymity revoker."
            );
            Threshold(max((num_of_ars - 1).try_into().unwrap_or(255), 1))
        }
    };

    let chi = CredentialHolderInfo::<ArCurve> { id_cred };

    let aci = AccCredentialInfo {
        cred_holder_info: chi,
        prf_key,
    };

    // Choice of anonymity revokers, all of them in this implementation.
    let context = IpContext::new(&ip_info, &ars_infos, &global_context);

    let id_use_data = IdObjectUseData {
        aci,
        randomness: sig_retrievel_randomness,
    };
    let (pio, _) = {
        match account_holder::generate_pio_v1(&context, threshold, &id_use_data) {
            Some(x) => x,
            None => bail!("Generating the pre-identity object failed."),
        }
    };

    let response =
        serde_json::json!({ "idObjectRequest": common::Versioned::new(common::VERSION_0, pio) });

    Ok(to_string(&response)?)
}

fn create_credential_aux(input: &str) -> anyhow::Result<String> {
    let v: Value = from_str(input)?;
    let expiry = try_get(&v, "expiry")?;
    let ip_info: IpInfo<Bls12> = try_get(&v, "ipInfo")?;

    let ars_infos: BTreeMap<ArIdentity, ArInfo<ArCurve>> = try_get(&v, "arsInfos")?;

    let global_context: GlobalContext<ArCurve> = try_get(&v, "global")?;

    let id_object: IdentityObject<Bls12, ArCurve, AttributeKind> = try_get(&v, "identityObject")?;

    let id_use_data: IdObjectUseData<Bls12, ArCurve> = try_get(&v, "privateIdObjectData")?;

    let tags: Vec<AttributeTag> = try_get(&v, "revealedAttributes")?;

    let acc_num: u8 = try_get(&v, "accountNumber")?;

    // The mobile wallet for now only creates new accounts and does not support
    // adding credentials onto existing ones. Once that is supported the address
    // should be coming from the input data.
    let new_or_existing = Left(expiry);

    // The mobile wallet can only create new accounts, which means new credential
    // data will be generated.
    let cred_data = {
        let mut keys = std::collections::BTreeMap::new();
        let mut csprng = thread_rng();
        keys.insert(KeyIndex(0), KeyPair::generate(&mut csprng));

        CredentialData {
            keys,
            threshold: SignatureThreshold(1),
        }
    };

    let mut policy_vec = std::collections::BTreeMap::new();
    for tag in tags {
        if let Some(att) = id_object.alist.alist.get(&tag) {
            if policy_vec.insert(tag, att.clone()).is_some() {
                bail!("Cannot reveal an attribute more than once.")
            }
        } else {
            bail!("Cannot reveal an attribute which is not part of the attribute list.")
        }
    }

    let policy = Policy {
        valid_to: id_object.alist.valid_to,
        created_at: id_object.alist.created_at,
        policy_vec,
        _phantom: Default::default(),
    };

    let context = IpContext::new(&ip_info, &ars_infos, &global_context);

    let (cdi, randomness) = account_holder::create_credential(
        context,
        &id_object,
        &id_use_data,
        acc_num,
        policy,
        &cred_data,
        &SystemAttributeRandomness {},
        &new_or_existing,
    )?;

    let address = match new_or_existing {
        Left(_) => account_address_from_registration_id(&cdi.values.cred_id),
        Right(address) => address,
    };

    // unwrap is safe here since we've generated the credential already, and that
    // does the same computation.
    let enc_key = id_use_data.aci.prf_key.prf_exponent(acc_num).unwrap();
    let secret_key = elgamal::SecretKey {
        generator: *global_context.elgamal_generator(),
        scalar:    enc_key,
    };

    let credential_message = AccountCredentialMessage {
        message_expiry: expiry,
        credential:     AccountCredential::Normal { cdi },
    };

    let response = serde_json::json!({
        "credential": common::Versioned::new(common::VERSION_0, credential_message),
        "commitmentsRandomness": randomness,
        "accountKeys": AccountKeys::from(cred_data),
        "encryptionSecretKey": secret_key,
        "encryptionPublicKey": elgamal::PublicKey::from(&secret_key),
        "accountAddress": address,
    });
    Ok(to_string(&response)?)
}

/// For deterministic credential creation using an identity object containing a
/// version 1 pre-identity object, i.e., no initial account involved.
fn create_credential_v1_aux(input: &str) -> anyhow::Result<String> {
    let v: Value = from_str(input)?;
    let expiry = try_get(&v, "expiry")?;
    let ip_info: IpInfo<Bls12> = try_get(&v, "ipInfo")?;

    let ars_infos: BTreeMap<ArIdentity, ArInfo<ArCurve>> = try_get(&v, "arsInfos")?;

    let global_context: GlobalContext<ArCurve> = try_get(&v, "global")?;

    let id_object: IdentityObjectV1<Bls12, ArCurve, AttributeKind> = try_get(&v, "identityObject")?;

    let tags: Vec<AttributeTag> = try_get(&v, "revealedAttributes")?;

    let wallet = parse_wallet_input(&v)?;
    let identity_provider_index = ip_info.ip_identity.0;
    let identity_index: u32 = try_get(&v, "identityIndex")?;
    let acc_num: u8 = try_get(&v, "accountNumber")?;

    let sig_retrievel_randomness: ps_sig::SigRetrievalRandomness<Bls12> =
        wallet.get_blinding_randomness(identity_provider_index, identity_index)?;
    let id_cred_sec: PedersenValue<ArCurve> =
        PedersenValue::new(wallet.get_id_cred_sec(identity_provider_index, identity_index)?);
    let id_cred: IdCredentials<ArCurve> = IdCredentials { id_cred_sec };
    let chi = CredentialHolderInfo::<ArCurve> { id_cred };
    let prf_key: prf::SecretKey<ArCurve> =
        wallet.get_prf_key(identity_provider_index, identity_index)?;
    let aci = AccCredentialInfo {
        cred_holder_info: chi,
        prf_key,
    };
    let id_use_data = IdObjectUseData {
        aci,
        randomness: sig_retrievel_randomness,
    };

    // The mobile wallet for now only creates new accounts and does not support
    // adding credentials onto existing ones. Once that is supported the address
    // should be coming from the input data.
    let new_or_existing = Left(expiry);

    // Create the keys for the new credential.
    let cred_data = {
        let mut keys = std::collections::BTreeMap::new();
        let secret = wallet.get_account_signing_key(
            identity_provider_index,
            identity_index,
            u32::from(acc_num),
        )?;
        let public = ed25519_dalek::PublicKey::from(&secret);
        keys.insert(KeyIndex(0), KeyPair { secret, public });

        CredentialData {
            keys,
            threshold: SignatureThreshold(1),
        }
    };

    // And a policy.
    let mut policy_vec = std::collections::BTreeMap::new();
    for tag in tags {
        if let Some(att) = id_object.alist.alist.get(&tag) {
            if policy_vec.insert(tag, att.clone()).is_some() {
                bail!("Cannot reveal an attribute more than once.")
            }
        } else {
            bail!("Cannot reveal an attribute which is not part of the attribute list.")
        }
    }

    let policy = Policy {
        valid_to: id_object.alist.valid_to,
        created_at: id_object.alist.created_at,
        policy_vec,
        _phantom: Default::default(),
    };

    let context = IpContext::new(&ip_info, &ars_infos, &global_context);

    let credential_context = CredentialContext {
        wallet,
        identity_provider_index,
        identity_index,
        credential_index: u32::from(acc_num),
    };
    let (cdi, randomness) = account_holder::create_credential(
        context,
        &id_object,
        &id_use_data,
        acc_num,
        policy,
        &cred_data,
        &credential_context,
        &new_or_existing,
    )?;

    let address = match new_or_existing {
        Left(_) => account_address_from_registration_id(&cdi.values.cred_id),
        Right(address) => address,
    };

    // unwrap is safe here since we've generated the credential already, and that
    // does the same computation.
    let enc_key = id_use_data.aci.prf_key.prf_exponent(acc_num).unwrap();
    let secret_key = elgamal::SecretKey {
        generator: *global_context.elgamal_generator(),
        scalar:    enc_key,
    };

    let credential_message = AccountCredentialMessage {
        message_expiry: expiry,
        credential:     AccountCredential::Normal { cdi },
    };

    let response = serde_json::json!({
        "credential": common::Versioned::new(common::VERSION_0, credential_message),
        "commitmentsRandomness": randomness,
        "accountKeys": AccountKeys::from(cred_data),
        "encryptionSecretKey": secret_key,
        "encryptionPublicKey": elgamal::PublicKey::from(&secret_key),
        "accountAddress": address,
    });
    Ok(to_string(&response)?)
}

/// For generating identity recovery requests
fn generate_recovery_request_aux(input: &str) -> anyhow::Result<String> {
    let v: Value = from_str(input)?;
    let ip_info: IpInfo<Bls12> = try_get(&v, "ipInfo")?;

    let global_context: GlobalContext<ArCurve> = try_get(&v, "global")?;

    let wallet = parse_wallet_input(&v)?;
    let identity_provider_index = ip_info.ip_identity.0;
    let identity_index: u32 = try_get(&v, "identityIndex")?;
    let id_cred_sec: PedersenValue<ArCurve> =
        PedersenValue::new(wallet.get_id_cred_sec(identity_provider_index, identity_index)?);

    let timestamp: u64 = try_get(&v, "timestamp")?;

    let request = account_holder::generate_id_recovery_request(
        &ip_info,
        &global_context,
        &id_cred_sec,
        timestamp,
    );

    let response = serde_json::json!({
        "idRecoveryRequest": common::Versioned::new(common::VERSION_0, request),
    });
    Ok(to_string(&response)?)
}

/// For proving statements about id attributes. Given a list of statements to be
/// proved, it extracts the relevant attribute values from the user's identity
/// object and calculates the commitment randomness deterministically from the
/// hd wallet seed. Upon success it outputs a proof of the statements.
fn prove_id_statement_aux(input: &str) -> anyhow::Result<String> {
    let v: Value = from_str(input)?;
    let global: GlobalContext<ArCurve> = try_get(&v, "global")?;
    let ip_info: IpInfo<Bls12> = try_get(&v, "ipInfo")?;

    let wallet = parse_wallet_input(&v)?;
    let identity_provider_index = ip_info.ip_identity.0;
    let identity_index: u32 = try_get(&v, "identityIndex")?;
    let acc_num: u8 = try_get(&v, "accountNumber")?;
    let credential_context = CredentialContext {
        wallet,
        identity_provider_index,
        identity_index,
        credential_index: u32::from(acc_num),
    };

    let cred_id = credential_context
        .wallet
        .get_prf_key(identity_provider_index, identity_index)?
        .prf(&global.on_chain_commitment_key.g, acc_num)?;

    let statement: Statement<ArCurve, AttributeKind> = try_get(&v, "statements")?;
    let statement = StatementWithContext {
        credential: cred_id,
        statement,
    };
    let id_object: IdentityObjectV1<Bls12, ArCurve, AttributeKind> = try_get(&v, "identityObject")?;
    let challenge: [u8; 32] = try_get(&v, "challenge")?;
    let proof = statement
        .prove(&global, &challenge, &id_object.alist, &credential_context)
        .context("Could not produce proof.")?;
    let response = serde_json::json!({
        "idProof": common::Versioned::new(common::VERSION_0, proof),
    });
    Ok(to_string(&response)?)
}

fn generate_accounts_aux(input: &str) -> anyhow::Result<String> {
    let v: Value = from_str(input)?;

    let global_context: GlobalContext<ArCurve> = try_get(&v, "global")?;

    let id_object: IdentityObject<Bls12, ArCurve, AttributeKind> = try_get(&v, "identityObject")?;

    let id_use_data: IdObjectUseData<Bls12, ArCurve> = try_get(&v, "privateIdObjectData")?;

    let start: u8 = try_get(&v, "start").unwrap_or(0);

    let mut response = Vec::with_capacity(256);

    for acc_num in start..id_object.alist.max_accounts {
        if let Ok(reg_id) = id_use_data
            .aci
            .prf_key
            .prf(global_context.elgamal_generator(), acc_num)
        {
            let enc_key = id_use_data.aci.prf_key.prf_exponent(acc_num).unwrap();
            let secret_key = elgamal::SecretKey {
                generator: *global_context.elgamal_generator(),
                scalar:    enc_key,
            };
            let address = account_address_from_registration_id(&reg_id);
            response.push(serde_json::json!({
                "encryptionSecretKey": secret_key,
                "encryptionPublicKey": elgamal::PublicKey::from(&secret_key),
                "accountAddress": address,
            }));
        }
    }
    Ok(to_string(&response)?)
}

/// Embed the precomputed table for decryption.
/// It is unfortunate that this is pure bytes, but not enough of data is marked
/// as const, and in any case a HashMap relies on an allocator, so will never be
/// const.
static TABLE_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/table_bytes.bin"));

fn decrypt_encrypted_amount_aux(input: &str) -> anyhow::Result<Amount> {
    let v: Value = from_str(input)?;
    let encrypted_amount = try_get(&v, "encryptedAmount")?;
    let secret = try_get(&v, "encryptionSecretKey")?;

    let table = BabyStepGiantStep::deserial(&mut std::io::Cursor::new(TABLE_BYTES))?;
    Ok(
        encrypted_transfers::decrypt_amount::<id::constants::ArCurve>(
            &table,
            &secret,
            &encrypted_amount,
        ),
    )
}

fn parse_wallet_input(v: &Value) -> anyhow::Result<ConcordiumHdWallet> {
    let seed_hex: String = try_get(v, "seed")?;
    let seed_decoded = hex::decode(&seed_hex)?;
    let seed: [u8; 64] = match seed_decoded.try_into() {
        Ok(s) => s,
        Err(_) => bail!("The provided seed {} was not 64 bytes", seed_hex),
    };

    let net: Net = try_get(v, "net")?;
    let wallet = ConcordiumHdWallet { seed, net };
    Ok(wallet)
}

fn get_identity_keys_and_randomness_aux(input: &str) -> anyhow::Result<String> {
    let v: Value = from_str(input)?;
    let wallet = parse_wallet_input(&v)?;
    let identity_provider_index = try_get(&v, "identityProviderIndex")?;
    let identity_index = try_get(&v, "identityIndex")?;

    let id_cred_sec = wallet.get_id_cred_sec(identity_provider_index, identity_index)?;

    let prf_key = wallet.get_prf_key(identity_provider_index, identity_index)?;

    let blinding_randomness =
        wallet.get_blinding_randomness(identity_provider_index, identity_index)?;

    let response = serde_json::json!({
        "idCredSec": common::base16_encode_string(&id_cred_sec),
        "prfKey": common::base16_encode_string(&prf_key),
        "blindingRandomness": common::base16_encode_string(&blinding_randomness)
    });
    Ok(to_string(&response)?)
}

fn get_account_keys_and_randomness_aux(input: &str) -> anyhow::Result<String> {
    let v: Value = from_str(input)?;
    let wallet = parse_wallet_input(&v)?;
    let identity_provider_index = try_get(&v, "identityProviderIndex")?;
    let identity_index = try_get(&v, "identityIndex")?;
    let account_credential_index = try_get(&v, "accountCredentialIndex")?;

    let account_signing_key = wallet.get_account_signing_key(
        identity_provider_index,
        identity_index,
        account_credential_index,
    )?;
    let account_signing_key_hex = hex::encode(account_signing_key);

    let account_verify_key = wallet.get_account_public_key(
        identity_provider_index,
        identity_index,
        account_credential_index,
    )?;
    let account_verify_key_hex = hex::encode(account_verify_key);

    let mut attribute_commitment_randomness = HashMap::new();

    for attribute_name in ATTRIBUTE_NAMES {
        let attribute_tag = AttributeTag::from_str(attribute_name)?;
        let commitment_randomness = wallet.get_attribute_commitment_randomness(
            identity_provider_index,
            identity_index,
            account_credential_index,
            attribute_tag,
        )?;
        let commitment_randomness_hex = common::base16_encode_string(&commitment_randomness);
        attribute_commitment_randomness.insert(attribute_tag.0, commitment_randomness_hex);
    }

    let response = serde_json::json!({
        "signKey": account_signing_key_hex,
        "verifyKey": account_verify_key_hex,
        "attributeCommitmentRandomness": attribute_commitment_randomness
    });
    Ok(to_string(&response)?)
}

/// Set the flag to 0, and return a newly allocated string containing
/// the error message. The returned string is NUL terminated.
///
/// # Safety
/// This function does not check that the flag pointer is not null.
unsafe fn signal_error(flag: *mut u8, err_msg: String) -> *mut c_char {
    *flag = 0;
    CString::new(err_msg)
        .expect("Error message string should be non-zero and utf8.")
        .into_raw()
}

unsafe fn encode_response(response: anyhow::Result<String>, success: *mut u8) -> *mut c_char {
    match response {
        Ok(s) => {
            let cstr: CString = {
                match CString::new(s) {
                    Ok(s) => s,
                    Err(e) => {
                        return signal_error(success, format!("Could not encode response: {}", e))
                    }
                }
            };
            *success = 1;
            cstr.into_raw()
        }
        Err(e) => signal_error(success, format!("Could not produce response: {}", e)),
    }
}

/// Try to get a normal string from a `*const c_char`.
///
/// This needs to be a macro due to early return.
macro_rules! get_string {
    ($input_ptr:expr, $success:expr) => {{
        if $input_ptr.is_null() {
            return signal_error($success, "Null pointer input.".to_owned());
        }
        match CStr::from_ptr($input_ptr).to_str() {
            Ok(s) => s,
            Err(e) => {
                return signal_error($success, format!("Could not decode input string: {}", e))
            }
        }
    }};
}

/// Make a wrapper for functions of the form
/// ```
///    f(success: *mut u8) -> *mut c_char
/// ```
/// or
/// ```
///    f(input_ptr: *const c_char, success: *mut u8) -> *mut c_char
/// ```
/// or
/// ```
///    f(input_ptr_1: *const c_char, input_ptr_2: *const c_char, success: *mut u8) -> *mut c_char
/// ```
macro_rules! make_wrapper {
    ($(#[$attr:meta])* => $f:ident > $call:expr) => {
        $(#[$attr])*
        #[no_mangle]
        pub unsafe fn $f(success: *mut u8) -> *mut c_char {
            let response = $call();
            encode_response(response, success)
        }
    };
    ($(#[$attr:meta])* => $f:ident -> $call:expr) => {
        $(#[$attr])*
        #[no_mangle]
        pub unsafe fn $f(input_ptr: *const c_char, success: *mut u8) -> *mut c_char {
            let input_str = get_string!(input_ptr, success);
            let response = $call(input_str);
            encode_response(response, success)
        }
    };
    ($(#[$attr:meta])* => $f:ident --> $call:expr) => {
        $(#[$attr])*
        #[no_mangle]
        pub unsafe fn $f(input_ptr_1: *const c_char, input_ptr_2: *const c_char, success: *mut u8) -> *mut c_char {
            let input_str_1 = get_string!(input_ptr_1, success);
            let input_str_2 = get_string!(input_ptr_2, success);
            let response = $call(input_str_1, input_str_2);
            encode_response(response, success)
        }
    };
}

// Make external wrappers that can be used in android and iOS libraries.
make_wrapper!(
    /// Take a pointer to a NUL-terminated UTF8-string and return a NUL-terminated
    /// UTF8-encoded string. The returned string must be freed by the caller by
    /// calling the function 'free_response_string'. In case of failure the function
    /// returns an error message as the response, and sets the 'success' flag to 0.
    ///
    /// See rust-bins/wallet-notes/README.md for the description of input and output
    /// formats.
    ///
    /// # Safety
    /// The input pointer must point to a null-terminated buffer, otherwise this
    /// function will fail in unspecified ways.
    => create_transfer -> create_transfer_aux);

make_wrapper!(
    /// Take a pointer to a NUL-terminated UTF8-string and return a NUL-terminated
    /// UTF8-encoded string. The returned string must be freed by the caller by
    /// calling the function 'free_response_string'. In case of failure the function
    /// returns an error message as the response, and sets the 'success' flag to 0.
    ///
    /// See rust-bins/wallet-notes/README.md for the description of input and output
    /// formats.
    ///
    /// # Safety
    /// The input pointer must point to a null-terminated buffer, otherwise this
    /// function will fail in unspecified ways.
    => create_configure_delegation_transaction -> create_configure_delegation_transaction_aux);

make_wrapper!(
    /// Take a pointer to a NUL-terminated UTF8-string and return a NUL-terminated
    /// UTF8-encoded string. The returned string must be freed by the caller by
    /// calling the function 'free_response_string'. In case of failure the function
    /// returns an error message as the response, and sets the 'success' flag to 0.
    ///
    /// See rust-bins/wallet-notes/README.md for the description of input and output
    /// formats.
    ///
    /// # Safety
    /// The input pointer must point to a null-terminated buffer, otherwise this
    /// function will fail in unspecified ways.
    => create_configure_baker_transaction -> create_configure_baker_transaction_aux);

make_wrapper!(
    /// Return a NUL-terminated UTF8-encoded string. The returned string must be freed
    /// by the caller by calling the function 'free_response_string'. In case of
    /// failure the function returns an error message as the response, and sets the
    /// 'success' flag to 0.
    ///
    /// See rust-bins/wallet-notes/README.md for the description of input and output
    /// formats.
    => generate_baker_keys > generate_baker_keys_aux);

make_wrapper!(
    /// Take a pointer to a NUL-terminated UTF8-string and return a NUL-terminated
    /// UTF8-encoded string. The input string should contain the JSON payload of an
    /// attribute list, name of id object, and the identity provider public
    /// information.
    ///
    /// The return value contains a JSON object with two values, one is
    /// the request for the identity object that is public, and the other is the
    /// private keys and other secret values that must be kept by the user.
    /// These secret values will be needed later to use the identity object.
    ///
    /// The returned string must be freed by the caller by calling the function
    /// 'free_response_string'. In case of failure the function returns an error
    /// message as the response, and sets the 'success' flag to 0.
    ///
    /// # Safety
    /// The input pointer must point to a null-terminated buffer, otherwise this
    /// function will fail in unspecified ways.
    => create_id_request_and_private_data -> create_id_request_and_private_data_aux);

make_wrapper!(
    /// Take a pointer to a NUL-terminated UTF8-string and return a NUL-terminated
    /// UTF8-encoded string. The input string should contain the JSON payload of an
    /// attribute list, name of id object, and the identity provider public
    /// information.
    ///
    /// The return value contains a JSON object with two values, one is
    /// the request for the identity object that is public, and the other is the
    /// private keys and other secret values that must be kept by the user.
    /// These secret values will be needed later to use the identity object.
    ///
    /// The returned string must be freed by the caller by calling the function
    /// 'free_response_string'. In case of failure the function returns an error
    /// message as the response, and sets the 'success' flag to 0.
    ///
    /// # Safety
    /// The input pointer must point to a null-terminated buffer, otherwise this
    /// function will fail in unspecified ways.
    => create_id_request_and_private_data_v1 -> create_id_request_and_private_data_v1_aux);

make_wrapper!(
    /// Take a pointer to a NUL-terminated UTF8-string and return a NUL-terminated
    /// UTF8-encoded string. The returned string must be freed by the caller by
    /// calling the function 'free_response_string'. In case of failure the function
    /// returns an error message as the response, and sets the 'success' flag to 0.
    ///
    /// See rust-bins/wallet-notes/README.md for the description of input and output
    /// formats.
    ///
    /// # Safety
    /// The input pointer must point to a null-terminated buffer, otherwise this
    /// function will fail in unspecified ways.
    => create_credential -> create_credential_aux);

make_wrapper!(
    /// Take a pointer to a NUL-terminated UTF8-string and return a NUL-terminated
    /// UTF8-encoded string. The returned string must be freed by the caller by
    /// calling the function 'free_response_string'. In case of failure the function
    /// returns an error message as the response, and sets the 'success' flag to 0.
    ///
    /// See rust-bins/wallet-notes/README.md for the description of input and output
    /// formats.
    ///
    /// # Safety
    /// The input pointer must point to a null-terminated buffer, otherwise this
    /// function will fail in unspecified ways.
    => create_credential_v1 -> create_credential_v1_aux);

make_wrapper!(
    /// Take a pointer to a NUL-terminated UTF8-string and return a NUL-terminated
    /// UTF8-encoded string. The returned string must be freed by the caller by
    /// calling the function 'free_response_string'. In case of failure the function
    /// returns an error message as the response, and sets the 'success' flag to 0.
    ///
    /// See rust-bins/wallet-notes/README.md for the description of input and output
    /// formats.
    ///
    /// # Safety
    /// The input pointer must point to a null-terminated buffer, otherwise this
    /// function will fail in unspecified ways.
    => generate_recovery_request -> generate_recovery_request_aux);

make_wrapper!(
    /// Take a pointer to a NUL-terminated UTF8-string and return a NUL-terminated
    /// UTF8-encoded string. The returned string must be freed by the caller by
    /// calling the function 'free_response_string'. In case of failure the function
    /// returns an error message as the response, and sets the 'success' flag to 0.
    ///
    /// See rust-bins/wallet-notes/README.md for the description of input and output
    /// formats.
    ///
    /// # Safety
    /// The input pointer must point to a null-terminated buffer, otherwise this
    /// function will fail in unspecified ways.
    => prove_id_statement -> prove_id_statement_aux);

make_wrapper!(
    /// Take a pointer to a NUL-terminated UTF8-string and return a NUL-terminated
    /// UTF8-encoded string. The returned string must be freed by the caller by
    /// calling the function 'free_response_string'. In case of failure the function
    /// returns an error message as the response, and sets the 'success' flag to 0.
    ///
    /// See rust-bins/wallet-notes/README.md for the description of input and output
    /// formats for encrypted transfers.
    ///
    /// # Safety
    /// The input pointer must point to a null-terminated buffer, otherwise this
    /// function will fail in unspecified ways.
    => create_encrypted_transfer -> create_encrypted_transfer_aux);

make_wrapper!(
    /// Take a pointer to a NUL-terminated UTF8-string and return a NUL-terminated
    /// UTF8-encoded string. The returned string must be freed by the caller by
    /// calling the function 'free_response_string'. In case of failure the function
    /// returns an error message as the response, and sets the 'success' flag to 0.
    ///
    /// See rust-bins/wallet-notes/README.md for the description of input and output
    /// formats for encrypted transfers.
    ///
    /// # Safety
    /// The input pointer must point to a null-terminated buffer, otherwise this
    /// function will fail in unspecified ways.
    => create_pub_to_sec_transfer -> create_pub_to_sec_transfer_aux);

make_wrapper!(
    /// Take a pointer to a NUL-terminated UTF8-string and return a NUL-terminated
    /// UTF8-encoded string. The returned string must be freed by the caller by
    /// calling the function 'free_response_string'. In case of failure the function
    /// returns an error message as the response, and sets the 'success' flag to 0.
    ///
    /// See rust-bins/wallet-notes/README.md for the description of input and output
    /// formats for encrypted transfers.
    ///
    /// # Safety
    /// The input pointer must point to a null-terminated buffer, otherwise this
    /// function will fail in unspecified ways.
    => create_sec_to_pub_transfer -> create_sec_to_pub_transfer_aux);

make_wrapper!(
    /// Take pointers to NUL-terminated UTF8-strings and return a NUL-terminated
    /// UTF8-encoded string. The returned string must be freed by the caller by
    /// calling the function 'free_response_string'. In case of failure the function
    /// returns an error message as the response, and sets the 'success' flag to 0.
    ///
    /// The input strings must contain base16 encoded encrypted amounts. If they can be
    /// decoded then the result is also a string of the same form, and the success flag is 1.
    /// If there is failure decoding input arguments the return value is a string
    /// describing the error.
    ///
    /// # Safety
    /// The input pointers must point to a null-terminated buffer, otherwise this
    /// function will fail in unspecified ways.
    => combine_encrypted_amounts --> combine_encrypted_amounts_aux);

make_wrapper!(
    /// Take pointers to NUL-terminated UTF8-strings and return a NUL-terminated
    /// UTF8-encoded string. The returned string must be freed by the caller by
    /// calling the function 'free_response_string'. In case of failure the function
    /// returns an error message as the response, and sets the 'success' flag to 0.
    ///
    /// The input strings must contain a valid JSON object with fields `identityObject`, `privateIdObjectData`, and `global`.
    /// If there is failure decoding input arguments the return value is a string
    /// describing the error.
    ///
    /// # Safety
    /// The input pointer must point to a null-terminated buffer, otherwise this
    /// function will fail in unspecified ways.
    => generate_accounts -> generate_accounts_aux);

make_wrapper!(
    /// Take a pointer to a NUL-terminated UTF8-string and return a NUL-terminated
    /// UTF8-encoded string. The returned string must be freed by the caller by
    /// calling the function 'free_response_string'. In case of failure the function
    /// returns an error message as the response, and sets the 'success' flag to 0.
    ///
    /// See rust-bins/wallet-notes/README.md for the description of input and output
    /// formats.
    ///
    /// # Safety
    /// The input pointer must point to a null-terminated buffer, otherwise this
    /// function will fail in unspecified ways.
    => get_identity_keys_and_randomness -> get_identity_keys_and_randomness_aux);

make_wrapper!(
    /// Take a pointer to a NUL-terminated UTF8-string and return a NUL-terminated
    /// UTF8-encoded string. The returned string must be freed by the caller by
    /// calling the function 'free_response_string'. In case of failure the function
    /// returns an error message as the response, and sets the 'success' flag to 0.
    ///
    /// See rust-bins/wallet-notes/README.md for the description of input and output
    /// formats.
    ///
    /// # Safety
    /// The input pointer must point to a null-terminated buffer, otherwise this
    /// function will fail in unspecified ways.
    => get_account_keys_and_randomness -> get_account_keys_and_randomness_aux);

make_wrapper!(
    /// Take a pointer to a NUL-terminated UTF8-string and return a NUL-terminated
    /// UTF8-encoded string. The returned string must be freed by the caller by
    /// calling the function 'free_response_string'. In case of failure the function
    /// returns an error message as the response, and sets the 'success' flag to 0.
    ///
    /// See rust-bins/wallet-notes/README.md for the description of input and output
    /// formats.
    ///
    /// # Safety
    /// The input pointer must point to a null-terminated buffer, otherwise this
    /// function will fail in unspecified ways.
    => parameter_to_json -> parameter_to_json_aux);

make_wrapper!(
    /// Take a pointer to a NUL-terminated UTF8-string and return a NUL-terminated
    /// UTF8-encoded string. The returned string must be freed by the caller by
    /// calling the function 'free_response_string'. In case of failure the function
    /// returns an error message as the response, and sets the 'success' flag to 0.
    ///
    /// See rust-bins/wallet-notes/README.md for the description of input and output
    /// formats.
    ///
    /// # Safety
    /// The input pointer must point to a null-terminated buffer, otherwise this
    /// function will fail in unspecified ways.
    => create_account_transaction -> create_account_transaction_aux);

make_wrapper!(
    /// Take a pointer to a NUL-terminated UTF8-string and return a NUL-terminated
    /// UTF8-encoded string. The returned string must be freed by the caller by
    /// calling the function 'free_response_string'. In case of failure the function
    /// returns an error message as the response, and sets the 'success' flag to 0.
    ///
    /// See rust-bins/wallet-notes/README.md for the description of input and output
    /// formats.
    ///
    /// # Safety
    /// The input pointer must point to a null-terminated buffer, otherwise this
    /// function will fail in unspecified ways.
    => serialize_token_transfer_parameters -> serialize_token_transfer_parameters_aux);

make_wrapper!(
    /// Take a pointer to a NUL-terminated UTF8-string and return a NUL-terminated
    /// UTF8-encoded string. The returned string must be freed by the caller by
    /// calling the function 'free_response_string'. In case of failure the function
    /// returns an error message as the response, and sets the 'success' flag to 0.
    ///
    /// See rust-bins/wallet-notes/README.md for the description of input and output
    /// formats.
    ///
    /// # Safety
    /// The input pointer must point to a null-terminated buffer, otherwise this
    /// function will fail in unspecified ways.
    => sign_message -> sign_message_aux);

/// Take pointers to a NUL-terminated UTF8-string and return a u64.
///
/// In case of failure to decode the input the function will
/// set the `success` flag to `0`, and the return value should not be used.
/// If `success` is set to `1` the return value is the decryption of the input
/// amount.
///
/// The input string should encode a JSON object with two fields "global" and
/// "encryptedAmount".
///
/// # Safety
/// The input pointer must point to a null-terminated buffer, otherwise this
/// function will fail in unspecified ways.
#[no_mangle]
pub unsafe fn decrypt_encrypted_amount(input_ptr: *const c_char, success: *mut u8) -> u64 {
    let input_str = if input_ptr.is_null() {
        *success = 0;
        return 0;
    } else {
        match CStr::from_ptr(input_ptr).to_str() {
            Ok(s) => s,
            Err(_) => {
                *success = 0;
                return 0;
            }
        }
    };
    if let Ok(v) = decrypt_encrypted_amount_aux(input_str) {
        *success = 1;
        v.micro_ccd()
    } else {
        *success = 0;
        0
    }
}

#[no_mangle]
/// # Safety
/// The input must be NUL-terminated.
pub unsafe fn check_account_address(input_ptr: *const c_char) -> u8 {
    let input_str = {
        match CStr::from_ptr(input_ptr).to_str() {
            Ok(s) => s,
            Err(_) => return 0,
        }
    };
    if check_account_address_aux(input_str) {
        1
    } else {
        0
    }
}

#[no_mangle]
/// # Safety
/// This function is unsafe in the sense that if the argument pointer was not
/// Constructed via CString::into_raw its behaviour is undefined.
pub unsafe fn free_response_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        let _ = CString::from_raw(ptr);
    }
}

#[cfg(target_os = "android")]
mod android;
