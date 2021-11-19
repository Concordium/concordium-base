use clap::AppSettings;
use client_server_helpers::*;
use crypto_common::{types::TransactionTime, *};
use dialoguer::Input;
use id::{
    constants::{ArCurve, IpPairing},
    identity_provider::*,
    types::*,
};
use pairing::bls12_381::Bls12;
use std::{collections::btree_map::BTreeMap, io, path::PathBuf};
use structopt::StructOpt;

#[derive(StructOpt)]
struct IpSignPio {
    #[structopt(
        long = "pio",
        help = "File with input pre-identity object information."
    )]
    pio:                PathBuf,
    #[structopt(
        long = "ip-data",
        help = "Possibly encrypted file with all information about the identity provider (public \
                and private)."
    )]
    ip_data:            PathBuf,
    #[structopt(long = "out", help = "File to write the signed identity object to.")]
    out_file:           PathBuf,
    #[structopt(
        long = "initial-cdi-out",
        help = "File to output the JSON transaction payload to (regarding the initial account)."
    )]
    out_icdi:           PathBuf,
    #[structopt(
        long = "global",
        help = "File with global parameters.",
        default_value = "database/global.json"
    )]
    global:             PathBuf,
    #[structopt(
        long = "ars",
        help = "File with a list of anonymity revokers.",
        default_value = "database/anonymity_revokers.json"
    )]
    anonymity_revokers: PathBuf,
    #[structopt(
        long = "expiry",
        help = "Expiry time of the initial credential message. In seconds from __now__.",
        required = true
    )]
    expiry:             u64,
    #[structopt(
        long = "id-object-expiry",
        help = "Expiry time of the identity object message. As YYYYMM."
    )]
    id_expiry:          Option<YearMonth>,
    #[structopt(
        long = "ar-record",
        help = "File to write anonymity revocation record to."
    )]
    ar_record:          PathBuf,
}

#[derive(StructOpt)]
#[structopt(
    about = "Identity provider client",
    author = "Concordium",
    version = "1"
)]
enum IpClient {
    #[structopt(
        name = "ip-sign-pio",
        about = "Act as the identity provider, checking and signing a pre-identity object."
    )]
    IpSignPio(IpSignPio),
}

fn read_validto() -> io::Result<YearMonth> {
    let input: String = Input::new()
        .with_prompt("Enter valid to (YYYYMM)")
        .interact()?;
    match parse_yearmonth(&input) {
        Some(ym) => Ok(ym),
        None => panic!("Unable to parse YYYYMM"),
    }
}

fn main() {
    let app = IpClient::clap()
        .setting(AppSettings::ArgRequiredElseHelp)
        .global_setting(AppSettings::ColoredHelp);
    let matches = app.get_matches();
    let client = IpClient::from_clap(&matches);
    use IpClient::*;
    match client {
        IpSignPio(isp) => handle_act_as_ip(isp),
    }
}

fn handle_act_as_ip(aai: IpSignPio) {
    let pio = match read_pre_identity_object(&aai.pio) {
        Ok(pio) => pio,
        Err(e) => {
            eprintln!("Could not read file because {}", e);
            return;
        }
    };
    let (ip_info, ip_sec_key, ip_cdi_secret_key) =
        match decrypt_input::<_, IpData<Bls12>>(&aai.ip_data) {
            Ok(ip_data) => (
                ip_data.public_ip_info,
                ip_data.ip_secret_key,
                ip_data.ip_cdi_secret_key,
            ),
            Err(x) => {
                eprintln!("Could not read identity issuer information because: {}", x);
                return;
            }
        };

    let valid_to = match aai.id_expiry {
        Some(exp) => exp,
        None => match read_validto() {
            Ok(ym) => ym,
            Err(e) => {
                eprintln!("Could not read credential expiry because: {}", e);
                return;
            }
        },
    };

    let global_ctx = {
        if let Some(gc) = read_global_context(aai.global) {
            gc
        } else {
            eprintln!("Cannot read global context information database. Terminating.");
            return;
        }
    };

    // all known anonymity revokers.
    let ars = {
        if let Ok(ars) = read_anonymity_revokers(aai.anonymity_revokers) {
            ars.anonymity_revokers
        } else {
            eprintln!("Cannot read anonymity revokers from the database. Terminating.");
            return;
        }
    };

    let created_at = YearMonth::now();

    let alist = {
        let mut alist: BTreeMap<AttributeTag, ExampleAttribute> = BTreeMap::new();
        match Input::new()
            .with_prompt("Please provide LEI (Legal Entity Identifier)")
            .interact()
        {
            Err(e) => {
                eprintln!("Could not read input because: {}", e);
                return;
            }
            Ok(s) => {
                let _ = alist.insert(AttributeTag(13u8), s);
            }
        }
        alist
    };

    let attributes = AttributeList {
        valid_to,
        created_at,
        max_accounts: 238,
        alist,
        _phantom: Default::default(),
    };
    let context = IpContext::new(&ip_info, &ars, &global_ctx);
    let message_expiry = TransactionTime {
        seconds: chrono::Utc::now().timestamp() as u64 + aai.expiry,
    };
    let vf = verify_credentials(
        &pio,
        context,
        &attributes,
        message_expiry,
        &ip_sec_key,
        &ip_cdi_secret_key,
    );
    let ar_record = Versioned::new(VERSION_0, AnonymityRevocationRecord {
        id_cred_pub:  pio.pub_info_for_ip.id_cred_pub,
        ar_data:      pio.ip_ar_data.clone(),
        max_accounts: attributes.max_accounts,
        threshold:    pio.choice_ar_parameters.threshold,
    });

    match vf {
        Ok((signature, icdi)) => {
            let account_address = AccountAddress::new(&pio.pub_info_for_ip.reg_id);
            let id_object = IdentityObject {
                pre_identity_object: pio,
                alist: attributes,
                signature,
            };
            let ver_id_object = Versioned::new(VERSION_0, id_object);
            println!("Successfully checked pre-identity data.");
            match write_json_to_file(&aai.out_file, &ver_id_object) {
                Ok(_) => println!(
                    "Wrote signed identity object to file {:?}",
                    &aai.out_file.to_string_lossy()
                ),
                Err(e) => eprintln!("Could not write Identity object to file because: {:?}", e),
            }

            let icdi_message = AccountCredentialMessage::<IpPairing, ArCurve, _> {
                message_expiry,
                credential: AccountCredential::Initial { icdi },
            };
            let versioned_icdi = Versioned::new(VERSION_0, icdi_message);
            match write_json_to_file(&aai.out_icdi, &versioned_icdi) {
                Ok(_) => println!(
                    "Wrote transaction payload to JSON file {}.",
                    &aai.out_icdi.to_string_lossy()
                ),
                Err(e) => {
                    eprintln!(
                        "Could not JSON write transaction payload to file because: {}",
                        e
                    );
                }
            }
            let to_store = serde_json::json!({
                "arRecord": ar_record,
                "accountAddress": account_address
            });
            match write_json_to_file(&aai.ar_record, &to_store) {
                Ok(_) => println!(
                    "Wrote anonymity revocation record to JSON file {}.",
                    &aai.ar_record.to_string_lossy()
                ),
                Err(e) => {
                    eprintln!(
                        "Could not JSON write anonymity revocation record to file because: {}",
                        e
                    );
                }
            }
        }
        Err(r) => eprintln!("Could not verify pre-identity object because {}", r),
    }
}
