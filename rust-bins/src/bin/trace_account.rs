//! This tool can be used to trace transactions on a given account.
//! It needs access to the wallet-proxy to obtain a list of transactions on a
//! given account.
//!
//! If the account secret key is provided then the tool will decrypt all
//! encrypted transfers on the account.
//!
//! This tool is a proof-of-concept. It does not handle various kinds of
//! failures gracefully, typically just aborting execution entirely if something
//! unexpected happens.

use anyhow::Context;
use chrono::{DateTime, NaiveDateTime, Utc};
use clap::AppSettings;
use client_server_helpers::read_json_from_file;
use crypto_common::{types::Amount, *};
use id::types::*;

use std::path::PathBuf;
use structopt::StructOpt;

type EncryptedAmount = encrypted_transfers::types::EncryptedAmount<id::constants::ArCurve>;

#[derive(Debug)]
pub enum AmountDelta {
    PositiveAmount(Amount),
    NegativeAmount(Amount),
}

impl std::fmt::Display for AmountDelta {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AmountDelta::PositiveAmount(a) => write!(f, "+{}", a),
            AmountDelta::NegativeAmount(a) => write!(f, "-{}", a),
        }
    }
}

impl<'de> SerdeDeserialize<'de> for AmountDelta {
    fn deserialize<D: serde::de::Deserializer<'de>>(des: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        use std::convert::TryInto;
        let s = String::deserialize(des)?;
        let n = s
            .parse::<i128>()
            .map_err(|e| D::Error::custom(format!("Could not parse amount delta: {}", e)))?;
        if n >= 0 {
            let micro_ccd: u64 = n
                .try_into()
                .map_err(|_| D::Error::custom("Amount delta out of range."))?;
            Ok(AmountDelta::PositiveAmount(Amount::from_micro_ccd(
                micro_ccd,
            )))
        } else {
            let m = n
                .checked_abs()
                .ok_or_else(|| D::Error::custom("Amount delta out of range."))?;
            let micro_ccd: u64 = m
                .try_into()
                .map_err(|_| D::Error::custom("Amount delta out of range."))?;
            Ok(AmountDelta::NegativeAmount(Amount::from_micro_ccd(
                micro_ccd,
            )))
        }
    }
}

/// Should match what's output by the anonymity_revocation tool.
#[derive(SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
struct RetrievalInput {
    account_address:       AccountAddress,
    /// An optional secret key. If present amounts will be decrypted, otherwise
    /// they will not.
    encryption_secret_key: Option<elgamal::SecretKey<id::constants::ArCurve>>,
}

/// A success response from the accTransactions endpoint of the wallet-proxy.
#[derive(SerdeDeserialize)]
struct GoodResponse {
    limit:        u64,
    count:        u64,
    transactions: Vec<TransactionResponse>,
}

/// Since we don't do anything with hashes we leave them as strings for this
/// binary.
type BlockHash = String;
type TransactionHash = String;

#[derive(Debug, SerdeDeserialize, PartialEq, Eq)]
enum OriginType {
    #[serde(rename = "self")]
    Own, // named Own instead of Self because Self is a keyword
    #[serde(rename = "account")]
    Account,
    #[serde(rename = "reward")]
    Reward,
}

/// Origin of the transaction, either "self" or "account", in the latter case
/// the address is in the second field.
#[derive(Debug, SerdeDeserialize)]
struct Origin {
    #[serde(rename = "type")]
    origin_type: OriginType,
    address:     Option<AccountAddress>,
}

/// Interesting parts of the response for a single transaction.
#[derive(SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
struct TransactionResponse {
    id:               u64,
    origin:           Origin,
    block_hash:       BlockHash,
    block_time:       f64,
    transaction_hash: Option<TransactionHash>,
    details:          Details,
    subtotal:         Option<AmountDelta>,
    total:            Option<AmountDelta>,
}
/// Outcome of a transaction.
#[derive(SerdeDeserialize, Eq, PartialEq, Debug)]
enum Outcome {
    #[serde(rename = "success")]
    Success,
    #[serde(rename = "reject")]
    Reject,
}

/// Details of a particular transaction. The actual details are transaction
/// specific, and are thus handled by the enumeration `AdditionalDetails`.
#[derive(SerdeDeserialize)]
struct Details {
    outcome:            Option<Outcome>,
    #[serde(flatten)]
    additional_details: AdditionalDetails,
}

/// Additional details of a transaction, itemized by transaction type.
/// This should match what the wallet-proxy returns.
#[derive(SerdeDeserialize, Debug)]
#[serde(tag = "type")]
#[allow(clippy::large_enum_variant)]
enum AdditionalDetails {
    #[serde(rename = "initContract")]
    InitContract,
    #[serde(rename = "update")]
    Update,
    #[serde(rename = "transfer")]
    SimpleTransfer(SimpleTransfer),
    #[serde(rename = "encryptedAmountTransfer")]
    EncryptedAmountTransfer(EncryptedTransfer),
    #[serde(rename = "transferToEncrypted")]
    TransferToEncrypted(TransferToEncrypted),
    #[serde(rename = "transferToPublic")]
    TransferToPublic(TransferToPublic),
    #[serde(rename = "transferWithSchedule")]
    TransferWithSchedule(TransferWithSchedule),
    #[serde(rename = "blockReward")]
    BlockReward,
    #[serde(rename = "finalizationReward")]
    FinalizationReward,
    #[serde(rename = "bakingReward")]
    BakingReward,
    #[serde(rename = "platformDevelopmentCharge")]
    Mint,
    #[serde(other)]
    Uninteresting,
}

#[derive(SerdeDeserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SimpleTransfer {
    transfer_source:      AccountAddress,
    transfer_destination: AccountAddress,
    transfer_amount:      Amount,
}

#[derive(SerdeDeserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedTransfer {
    transfer_source:           AccountAddress,
    transfer_destination:      AccountAddress,
    encrypted_amount:          EncryptedAmount,
    input_encrypted_amount:    EncryptedAmount,
    new_self_encrypted_amount: EncryptedAmount,
}

#[derive(SerdeDeserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TransferWithSchedule {
    transfer_destination: AccountAddress,
    transfer_amount:      Amount,
}

#[derive(SerdeDeserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TransferToEncrypted {
    pub transfer_source:           AccountAddress,
    pub amount_subtracted:         Amount,
    pub new_self_encrypted_amount: EncryptedAmount,
}

#[derive(SerdeDeserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TransferToPublic {
    pub transfer_source:           AccountAddress,
    pub amount_added:              Amount,
    pub input_encrypted_amount:    EncryptedAmount,
    pub new_self_encrypted_amount: EncryptedAmount,
}

/// A success response from accBalance endpoint
#[derive(SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
struct AccBalanceResponse {
    current_balance:   Option<serde_json::Value>,
    finalized_balance: Option<serde_json::Value>,
}

#[derive(StructOpt)]
/// Mode of operation, either decrypt all, or just one.
enum Mode {
    #[structopt(about = "Trace all accounts in the given file.", name = "all")]
    All {
        #[structopt(
            help = "File with data about the account we need to decrypt.",
            long = "regids"
        )]
        regids_file: PathBuf,
    },
    #[structopt(about = "Trace a single account.", name = "single")]
    Single {
        #[structopt(help = "Account address to trace.", long = "address")]
        address:        AccountAddress,
        #[structopt(
            help = "Optionally a decryption key to decrypt encrypted transfers.",
            long = "decryption-key"
        )]
        decryption_key: Option<String>,
    },
}

#[derive(StructOpt)]
struct Trace {
    #[structopt(
        long = "global",
        help = "File with cryptographic parameters.",
        default_value = "global.json"
    )]
    global: PathBuf,
    #[structopt(
        long = "out",
        help = "File to output the account trace to. If not provided the data is printed to \
                stdout."
    )]
    out:    Option<PathBuf>,
    #[structopt(
        long = "source",
        help = "URL to the wallet-proxy instance.",
        default_value = "https://wallet-proxy.eu.staging.concordium.com"
    )]
    source: url::Url,
    #[structopt(subcommand)]
    mode:   Mode,
}

fn main() {
    let app = Trace::clap()
        .setting(AppSettings::ArgRequiredElseHelp)
        .global_setting(AppSettings::ColoredHelp);
    let matches = app.get_matches();
    let tr = Trace::from_clap(&matches);
    let global: GlobalContext<id::constants::ArCurve> =
        match read_json_from_file::<_, Versioned<GlobalContext<_>>>(&tr.global) {
            Ok(global) if global.version == VERSION_0 => global.value,
            Ok(global) => {
                eprintln!(
                    "Cryptographic parameters have an unsupported version tag {}",
                    global.version
                );
                return;
            }
            Err(e) => {
                eprintln!("Could not read cryptographic parameters {}", e);
                return;
            }
        };
    let table = elgamal::BabyStepGiantStep::new(global.encryption_in_exponent_generator(), 1 << 16);
    let mut writer: Box<dyn std::io::Write> = if let Some(file) = tr.out {
        Box::new(std::fs::File::create(file).expect("Cannot create output file"))
    } else {
        Box::new(std::io::stdout())
    };
    match tr.mode {
        Mode::All { regids_file } => {
            let inputs: Vec<RetrievalInput> = match read_json_from_file(regids_file) {
                Ok(data) => data,
                Err(_) => {
                    eprintln!("Could not read regids from the provided file.");
                    return;
                }
            };
            for input in inputs.iter() {
                trace_single_account(&table, &tr.source, input, &mut writer);
                writeln!(writer, "\n\n").expect("Could not write.");
            }
        }
        Mode::Single {
            address,
            decryption_key,
        } => {
            let input = match decryption_key {
                Some(decryption_key) => {
                    let encryption_secret_key = match hex::decode(&decryption_key)
                        .context("Hex decoding error")
                        .and_then(|bs| from_bytes(&mut std::io::Cursor::new(bs)))
                    {
                        Ok(v) => Some(v),
                        Err(e) => {
                            eprintln!("The provided decryption key is malformed due to: {}", e);
                            return;
                        }
                    };
                    RetrievalInput {
                        account_address: address,
                        encryption_secret_key,
                    }
                }
                None => RetrievalInput {
                    account_address:       address,
                    encryption_secret_key: None,
                },
            };
            trace_single_account(&table, &tr.source, &input, &mut writer)
        }
    };
}

fn trace_single_account(
    table: &elgamal::BabyStepGiantStep<id::constants::ArCurve>,
    source: &url::Url,
    input: &RetrievalInput,
    writer: &mut impl std::io::Write,
) {
    writeln!(writer, "Tracing account {}.", input.account_address).expect("Could not write.");
    // First check whether the account exists.
    {
        let mut exists_url = source.clone();
        exists_url.set_path(&format!("v0/accBalance/{}", input.account_address));
        let response = reqwest::blocking::get(exists_url).unwrap();
        if !response.status().is_success() {
            writeln!(writer, "Account does not exist on the chain at the moment.")
                .expect("Could not write.");
            return;
        } else {
            let response: Option<AccBalanceResponse> = response.json().ok();
            let does_account_exist = response.map_or(true, |abr| {
                abr.current_balance.is_none() && abr.finalized_balance.is_none()
            });
            if does_account_exist {
                writeln!(
                    writer,
                    "    Account does not exist on the chain at the moment."
                )
                .expect("Could not write.");
                return;
            }
        }
    }

    let mut base_url = source.clone();
    base_url.set_path(&format!("v0/accTransactions/{}", input.account_address));
    let request_template = reqwest::blocking::Client::new()
        .get(base_url.as_str())
        .query(&[("order", "ascending")])
        .query(&[("limit", 1000)]);

    let mk_request = |from: Option<u64>| {
        let response = match from {
            Some(from) => request_template
                .try_clone()
                .unwrap()
                .query(&[("from", from)])
                .send(),
            None => request_template.try_clone().unwrap().send(),
        };
        match response {
            Ok(response) => {
                use reqwest::StatusCode;
                match response.status() {
                    StatusCode::OK => response
                        .json()
                        .map_err(|e| format!("Cannot decode response {}", e)),
                    StatusCode::BAD_REQUEST => {
                        Err("Bad request.".to_owned())
                        // TODO: Add description
                    }
                    StatusCode::BAD_GATEWAY => {
                        Err("The server experienced an internal error.".to_owned())
                        // TODO Add description.
                    }
                    status => Err(format!("Unexpected response status {}", status)),
                }
            }
            Err(e) => Err(format!("Request cannot be made {}", e)),
        }
    };
    let mut init = None;
    let mut i = 0u64;
    let sk = &input.encryption_secret_key;

    loop {
        let rq: Result<GoodResponse, String> = mk_request(init);
        match rq {
            Ok(response) => {
                for tx in response.transactions.iter() {
                    if tx
                        .details
                        .outcome
                        .as_ref()
                        .map_or(false, |x| x == &Outcome::Reject)
                    {
                        continue;
                    }
                    match &tx.details.additional_details {
                        AdditionalDetails::InitContract => {
                            writeln!(
                                writer,
                                "[{}] {}: initialized a contract resulting in a change of balance \
                                 of {} GTUs\n    Block hash: {}\n    Transaction hash: {}",
                                pretty_time(tx.block_time),
                                i,
                                tx.subtotal.as_ref().unwrap(),
                                tx.block_hash,
                                tx.transaction_hash.as_ref().unwrap()
                            )
                            .expect("Could not write.");
                        }
                        AdditionalDetails::Update => {
                            writeln!(
                                writer,
                                "[{}] {}: updated a contract resulting in a change of balance of \
                                 {} GTUs\n    Block hash: {}\n    Transaction hash: {}",
                                pretty_time(tx.block_time),
                                i,
                                tx.subtotal.as_ref().unwrap(),
                                tx.block_hash,
                                tx.transaction_hash.as_ref().unwrap()
                            )
                            .expect("Could not write.");
                        }
                        AdditionalDetails::SimpleTransfer(st) => {
                            if tx.origin.origin_type == OriginType::Own {
                                writeln!(
                                    writer,
                                    "[{}] {}: Outgoing transfer of {} GTU to account {}.\n    \
                                     Block hash: {}\n   Transaction hash: {}",
                                    pretty_time(tx.block_time),
                                    i,
                                    st.transfer_amount,
                                    st.transfer_destination,
                                    tx.block_hash,
                                    tx.transaction_hash.as_ref().unwrap(),
                                )
                                .expect("Could not write.");
                            } else {
                                writeln!(
                                    writer,
                                    "[{}] {}: Incoming transfer of {} GTU from account {}.\n    \
                                     Block hash: {}\n    Transaction hash: {}",
                                    pretty_time(tx.block_time),
                                    i,
                                    st.transfer_amount,
                                    st.transfer_source,
                                    tx.block_hash,
                                    tx.transaction_hash.as_ref().unwrap(),
                                )
                                .expect("Could not write.");
                            }
                        }

                        AdditionalDetails::EncryptedAmountTransfer(et) => {
                            if tx.origin.origin_type == OriginType::Own {
                                if let Some(sk) = &sk {
                                    let before = encrypted_transfers::decrypt_amount(
                                        table,
                                        sk,
                                        &et.input_encrypted_amount,
                                    );
                                    let after = encrypted_transfers::decrypt_amount(
                                        table,
                                        sk,
                                        &et.new_self_encrypted_amount,
                                    );
                                    assert!(before >= after);
                                    let amount = before - after;
                                    writeln!(
                                        writer,
                                        "[{}] {}: outgoing encrypted transfer of {} GTU to \
                                         account {}.\n    Block hash: {}\n    Transaction hash: {}",
                                        pretty_time(tx.block_time),
                                        i,
                                        amount,
                                        et.transfer_destination,
                                        tx.block_hash,
                                        tx.transaction_hash.as_ref().unwrap(),
                                    )
                                    .expect("Could not write.");
                                } else {
                                    writeln!(
                                        writer,
                                        "[{}] {}: outgoing encrypted transfer to account {}.\n    \
                                         Block hash: {}\n    Transaction hash: {}",
                                        pretty_time(tx.block_time),
                                        i,
                                        et.transfer_destination,
                                        tx.block_hash,
                                        tx.transaction_hash.as_ref().unwrap(),
                                    )
                                    .expect("Could not write.");
                                }
                            } else if tx.origin.origin_type == OriginType::Account {
                                if let Some(sk) = &sk {
                                    let amount = encrypted_transfers::decrypt_amount(
                                        table,
                                        sk,
                                        &et.encrypted_amount,
                                    );
                                    writeln!(
                                        writer,
                                        "[{}] {}: incoming encrypted transfer of {} GTU from \
                                         account {}\n    Block hash: {}\n    Transaction hash: {}",
                                        pretty_time(tx.block_time),
                                        i,
                                        amount,
                                        et.transfer_source,
                                        tx.block_hash,
                                        tx.transaction_hash.as_ref().unwrap(),
                                    )
                                    .expect("Could not write.")
                                } else {
                                    writeln!(
                                        writer,
                                        "[{}] {}: incoming encrypted transfer from \
                                         account {}\n    Block hash: {}\n    Transaction \
                                         hash: {}",
                                        pretty_time(tx.block_time),
                                        i,
                                        et.transfer_source,
                                        tx.block_hash,
                                        tx.transaction_hash.as_ref().unwrap()
                                    )
                                    .expect("Could not write.")
                                }
                            }
                        }
                        AdditionalDetails::TransferToEncrypted(tte) => {
                            writeln!(
                                writer,
                                "[{}] {}: account {} shielded {} GTU\n    Block hash: {}\n    \
                                 Transaction hash: {}",
                                pretty_time(tx.block_time),
                                i,
                                tte.transfer_source,
                                tte.amount_subtracted,
                                tx.block_hash,
                                tx.transaction_hash.as_ref().unwrap()
                            )
                            .expect("Could not write.");
                        }
                        AdditionalDetails::TransferToPublic(ttp) => {
                            writeln!(
                                writer,
                                "[{}] {}: account {} unshielded {} GTU\n    Block hash: {}\n    \
                                 Transaction hash: {}",
                                pretty_time(tx.block_time),
                                i,
                                ttp.transfer_source,
                                ttp.amount_added,
                                tx.block_hash,
                                tx.transaction_hash.as_ref().unwrap()
                            )
                            .expect("Could not write.");
                        }
                        AdditionalDetails::TransferWithSchedule(tws) => {
                            if tx.origin.origin_type == OriginType::Own {
                                writeln!(
                                    writer,
                                    "[{}] {}: Outgoing scheduled transfer of {} GTU to account \
                                     {}\n    Block hash: {}\n    Transaction hash: {}",
                                    pretty_time(tx.block_time),
                                    i,
                                    tws.transfer_amount,
                                    tws.transfer_destination,
                                    tx.block_hash,
                                    tx.transaction_hash.as_ref().unwrap()
                                )
                                .expect("Could not write.");
                            } else if let AmountDelta::PositiveAmount(am) =
                                tx.total.as_ref().unwrap()
                            {
                                writeln!(
                                    writer,
                                    "[{}] {}: Incoming scheduled transfer of {} GTU from account \
                                     {}\n    Block hash: {}\n    Transaction hash: {}",
                                    pretty_time(tx.block_time),
                                    i,
                                    am,
                                    tx.origin.address.as_ref().unwrap(),
                                    tx.block_hash,
                                    tx.transaction_hash.as_ref().unwrap()
                                )
                                .expect("Could not write.");
                            } else {
                                panic!(
                                    "Malformed transaction details. Incoming scheduled transfer \
                                     with negative balance"
                                );
                            }
                        }
                        AdditionalDetails::BlockReward
                        | AdditionalDetails::FinalizationReward
                        | AdditionalDetails::BakingReward
                        | AdditionalDetails::Mint => {
                            if let AmountDelta::PositiveAmount(am) = tx.total.as_ref().unwrap() {
                                writeln!(
                                    writer,
                                    "[{}] {}: Received a {} reward of {} GTU\n    Block hash: {}",
                                    pretty_time(tx.block_time),
                                    i,
                                    match &tx.details.additional_details {
                                        AdditionalDetails::BlockReward => "block",
                                        AdditionalDetails::FinalizationReward => "finalization",
                                        AdditionalDetails::BakingReward => "baking",
                                        AdditionalDetails::Mint => "minting",
                                        _ => unreachable!(),
                                    },
                                    am,
                                    tx.block_hash
                                )
                                .expect("Could not write.");
                            } else {
                                panic!("Malformed transaction details. Negative reward");
                            }
                        }
                        AdditionalDetails::Uninteresting => {
                            // do nothing for other transaction types.
                        }
                    }
                    i += 1;
                }
                if response.count == response.limit {
                    init = Some(response.transactions.last().unwrap().id);
                } else {
                    break;
                }
            }
            Err(e) => {
                eprintln!("Could not retrieve account information due to {}", e);
                break;
            }
        }
    }
}

fn pretty_time(timestamp: f64) -> String {
    let naive = NaiveDateTime::from_timestamp(timestamp.round() as i64, 0);
    let dt: DateTime<Utc> = DateTime::from_utc(naive, Utc);
    dt.format("UTC %Y-%m-%d %H:%M:%S").to_string()
}
