use chrono::{DateTime, NaiveDateTime, Utc};
use clap::AppSettings;
use client_server_helpers::read_json_from_file;
use crypto_common::{types::Amount, *};
use id::types::*;

use std::path::PathBuf;
use structopt::StructOpt;

type EncryptedAmount = encrypted_transfers::types::EncryptedAmount<id::constants::ArCurve>;

#[derive(StructOpt)]
struct WalletProxy {
    #[structopt(
        long = "source",
        help = "Source of the data, dependent on the source-type.",
        global = true
    )]
    source: url::Url,
}
#[derive(StructOpt)]
enum Source {
    #[structopt(
        name = "wallet-proxy",
        about = "Use the wallet-proxy as the transaction source."
    )]
    WalletProxy(WalletProxy),
}
// Should match what's output by the anonymity_revocation tool.
#[derive(SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
struct RetrievalInput {
    #[serde(serialize_with = "base16_encode", deserialize_with = "base16_decode")]
    #[allow(dead_code)]
    reg_id: id::constants::ArCurve,
    account_address: AccountAddress,
    #[serde(serialize_with = "base16_encode", deserialize_with = "base16_decode")]
    encryption_secret_key: elgamal::SecretKey<id::constants::ArCurve>,
}

#[derive(SerdeDeserialize)]
struct GoodResponse {
    limit:        u64,
    count:        u64,
    transactions: Vec<TransactionResponse>,
}

type BlockHash = String;
type TransactionHash = String;

#[derive(Debug, SerdeDeserialize)]
struct Origin {
    #[serde(rename = "type")]
    origin_type: String,
    address: Option<AccountAddress>,
}

#[derive(SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
struct TransactionResponse {
    id:               u64,
    origin:           Origin,
    block_hash:       BlockHash,
    block_time:       f64,
    transaction_hash: Option<TransactionHash>,
    details:          Details,
}
#[derive(SerdeDeserialize, Eq, PartialEq)]
enum Outcome {
    #[serde(rename = "success")]
    Success,
    #[serde(rename = "reject")]
    Reject,
}
#[derive(SerdeDeserialize)]
struct Details {
    outcome: Outcome,
    #[serde(flatten)]
    additional_details: AdditionalDetails,
}
#[derive(SerdeDeserialize, Debug)]
#[serde(tag = "type")]
#[allow(clippy::large_enum_variant)]
enum AdditionalDetails {
    #[serde(rename = "transfer")]
    SimpleTransfer(SimpleTransfer),
    #[serde(rename = "encryptedAmountTransfer")]
    EncryptedTransfer(EncryptedTransfer),
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

#[derive(StructOpt)]
struct Trace {
    #[structopt(
        long = "out",
        help = "File to output the decryption to.",
        global = true
    )]
    out: Option<PathBuf>,
    #[structopt(
        long = "global",
        help = "File with cryptographic parameters.",
        default_value = "global.json"
    )]
    global: PathBuf,
    #[structopt(help = "File with data about the account we need to decrypt.")]
    input: PathBuf,
    #[structopt(flatten)]
    source_type: Source,
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
    let input: RetrievalInput = match read_json_from_file(&tr.input) {
        Ok(data) => data,
        Err(_) => {
            eprintln!("Could not read account data.");
            return;
        }
    };
    let table = elgamal::BabyStepGiantStep::new(global.encryption_in_exponent_generator(), 1 << 16);
    let sk = input.encryption_secret_key;
    match tr.source_type {
        Source::WalletProxy(wp) => {
            let mut base_url = wp.source;
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

            let mut writer: Box<dyn std::io::Write> = if let Some(file) = tr.out {
                Box::new(std::fs::File::create(file).expect("Cannot create output file"))
            } else {
                Box::new(std::io::stdout())
            };
            loop {
                let rq: Result<GoodResponse, String> = mk_request(init);
                match rq {
                    Ok(response) => {
                        for tx in response.transactions.iter() {
                            if tx.details.outcome == Outcome::Reject {
                                continue;
                            }
                            match &tx.details.additional_details {
                                AdditionalDetails::SimpleTransfer(st) => {
                                    if tx.origin.origin_type == "self" {
                                        writeln!(
                                            writer,
                                            "[{}] {}: Outgoing transfer of {} GTU to account \
                                             {}.\n    Block hash: {}\n   Transaction hash: {}",
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
                                            "[{}] {}: Incoming transfer of {} GTU from account \
                                             {}.\n    Block hash: {}\n    Transaction hash: {}",
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
                                AdditionalDetails::EncryptedTransfer(et) => {
                                    if tx.origin.origin_type == "self" {
                                        let before = encrypted_transfers::decrypt_amount(
                                            &table,
                                            &sk,
                                            &et.input_encrypted_amount,
                                        );
                                        let after = encrypted_transfers::decrypt_amount(
                                            &table,
                                            &sk,
                                            &et.new_self_encrypted_amount,
                                        );
                                        assert!(before >= after);
                                        let amount = Amount {
                                            microgtu: before.microgtu - after.microgtu,
                                        };
                                        writeln!(
                                            writer,
                                            "[{}] {}: outgoing encrypted transfer of {} GTU to \
                                             account {}.\n    Block hash: {}\n    Transaction \
                                             hash: {}",
                                            pretty_time(tx.block_time),
                                            i,
                                            amount,
                                            et.transfer_destination,
                                            tx.block_hash,
                                            tx.transaction_hash.as_ref().unwrap(),
                                        )
                                        .expect("Could not write.");
                                    } else {
                                        let amount = encrypted_transfers::decrypt_amount(
                                            &table,
                                            &sk,
                                            &et.encrypted_amount,
                                        );
                                        writeln!(
                                            writer,
                                            "[{}] {}: incoming encrypted transfer of {} GTU from \
                                             account {}\n    Block hash: {}\n    Transaction \
                                             hash: {}",
                                            pretty_time(tx.block_time),
                                            i,
                                            amount,
                                            et.transfer_source,
                                            tx.block_hash,
                                            tx.transaction_hash.as_ref().unwrap(),
                                        )
                                        .expect("Could not write.")
                                    }
                                }
                                AdditionalDetails::Uninteresting => {}
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
    }
}

fn pretty_time(timestamp: f64) -> String {
    let naive = NaiveDateTime::from_timestamp(timestamp.round() as i64, 0);
    let dt: DateTime<Utc> = DateTime::from_utc(naive, Utc);
    dt.format("UTC %Y-%m-%d %H:%M:%S").to_string()
}
