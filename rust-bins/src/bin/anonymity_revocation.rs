use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};
use id::anonymity_revoker::reveal_id_cred_pub;

use id::secret_sharing::*;

use crypto_common::*;

use elgamal::message::Message;

use id::types::*;

use std::convert::TryFrom;

use client_server_helpers::*;

use serde_json::json;

#[macro_use]
extern crate failure;
use failure::Fallible;

fn main() {
    let app = App::new("A tool for anonymity revocation.")
        .version("0.00787499699")
        .author("Concordium")
        .setting(AppSettings::ArgRequiredElseHelp)
        .global_setting(AppSettings::ColoredHelp)
        .arg(
            Arg::with_name("credential")
                .long("credential")
                .short("c")
                .value_name("FILE")
                .global(true)
                .help("File with the JSON encoded credential or credential values."),
        )
        .subcommand(
            SubCommand::with_name("decrypt")
                .about("Take a deployed credential and let one anonymity revoker decrypt its share")
                .arg(
                    Arg::with_name("ar-private")
                        .long("ar-private")
                        .short("a")
                        .value_name("FILE")
                        .required(true)
                        .requires("credential")
                        .help("File with anonymity revoker's private and public keys."),
                )
                .arg(
                    Arg::with_name("out")
                        .long("out")
                        .value_name("FILE")
                        .help("File to output the decryption to."),
                ),
        )
        .subcommand(
            SubCommand::with_name("combine")
                .about("Combines decrypted shares of anonymity revokers to get idCredPub")
                .arg(
                    Arg::with_name("shares")
                        .long("shares")
                        .short("s")
                        .multiple(true)
                        .value_name("FILE(S)")
                        .required(true)
                        .requires("credential")
                        .help("Files with the JSON encoded decrypted shares."),
                )
                .arg(
                    Arg::with_name("out")
                        .long("out")
                        .value_name("FILE")
                        .help("File to output idCredPub"),
                ),
        );
    let matches = app.get_matches();
    let exec_if = |x: &str| matches.subcommand_matches(x);
    exec_if("decrypt").map(handle_decrypt);
    exec_if("combine").map(handle_combine);
}

fn read_credential_values(
    file_name: &str,
) -> Fallible<CredentialDeploymentValues<ExampleCurve, ExampleAttribute>> {
    // this will work fine even if the whole credential is given since
    // JSON serialization of credentials flattens the values.
    match read_json_from_file(file_name) {
        Ok(r) => Ok(r),
        Err(x) => bail!("Could not read credential because {}", x),
    }
}

/// Combine shares to get idCredPub of the owner of the credential
fn handle_combine(matches: &ArgMatches) {
    let credential: CredentialDeploymentValues<ExampleCurve, ExampleAttribute> = {
        let file_name = matches
            .value_of("credential")
            .expect("Mandatory argument should be present.");
        match read_credential_values(file_name) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("{}", e);
                return;
            }
        }
    };
    let revocation_threshold = credential.threshold;

    let ar_data = credential.ar_data;

    let shares_values: Vec<_> = match matches.values_of("shares") {
        Some(v) => v.collect(),
        None => {
            eprintln!("Could not read shares");
            return;
        }
    };

    let number_of_ars = shares_values.len();
    let number_of_ars = u32::try_from(number_of_ars)
        .expect("Number of anonymity revokers should not exceed 2^32-1");
    if number_of_ars < revocation_threshold.into() {
        eprintln!(
            "insufficient number of anonymity revokers {}, {:?}",
            number_of_ars, revocation_threshold
        );
        return;
    }

    let mut ar_decrypted_data_vec: Vec<ChainArDecryptedData<ExampleCurve>> =
        Vec::with_capacity(shares_values.len());
    let mut shares: Vec<(ShareNumber, Message<ExampleCurve>)> =
        Vec::with_capacity(shares_values.len());

    for share_value in shares_values.iter() {
        match read_json_from_file(share_value) {
            Err(y) => {
                eprintln!("Could not read from ar file {} {}", share_value, y);
                return;
            }
            Ok(val) => ar_decrypted_data_vec.push(val),
        }
    }

    let mut share_numbers = Vec::new();
    let mut ar_identities = Vec::new();

    for ar_decrypted_data in ar_decrypted_data_vec {
        match ar_data.iter().find(|&x| {
            x.id_cred_pub_share_number == ar_decrypted_data.id_cred_pub_share_number
                && x.ar_identity == ar_decrypted_data.ar_identity
        }) {
            None => {
                eprintln!(
                    "AR with {:?} and {:?} is not part of the credential",
                    ar_decrypted_data.ar_identity, ar_decrypted_data.id_cred_pub_share_number
                );
                return;
            }
            Some(_) => {}
        }
        share_numbers.push(ar_decrypted_data.id_cred_pub_share_number.0);
        ar_identities.push(ar_decrypted_data.ar_identity.0);
        shares.push((
            ar_decrypted_data.id_cred_pub_share_number,
            ar_decrypted_data.id_cred_pub_share,
        ));
    }
    share_numbers.sort();
    share_numbers.dedup();
    ar_identities.sort();
    ar_identities.dedup();
    if share_numbers.len() < shares.len() || ar_identities.len() < shares.len() {
        println!(
            "No duplicates among the anonymity revokers identities nor share numbers are allowed"
        );
        return;
    }

    let id_cred_pub = reveal_id_cred_pub(&shares);
    let id_cred_pub_string = base16_encode_string(&id_cred_pub);
    println!(
        "IdCredPub of the credential owner is:\n {}",
        id_cred_pub_string
    );
    println!(
        "Contact the identity provider with this information to get the real-life identity of the \
         user."
    );

    if let Some(json_file) = matches.value_of("out") {
        let json = json!({ "idCredPub": id_cred_pub_string });
        match write_json_to_file(json_file, &json) {
            Ok(_) => println!("Wrote idCredPub to {}.", json_file),
            Err(e) => {
                println!("Could not JSON write to file because {}", e);
                output_json(&json);
            }
        }
    }
}

/// Decrypt encIdCredPubShare
fn handle_decrypt(matches: &ArgMatches) {
    let credential: CredentialDeploymentValues<ExampleCurve, ExampleAttribute> = {
        let file_name = matches
            .value_of("credential")
            .expect("Mandatory argument should be present.");
        match read_credential_values(file_name) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("{}", e);
                return;
            }
        }
    };

    let ar_data = credential.ar_data;
    let ar: ArData<ExampleCurve> = match matches.value_of("ar-private").map(read_json_from_file) {
        Some(Ok(r)) => r,
        Some(Err(x)) => {
            eprintln!("Could not read ar-private because {}", x);
            return;
        }
        None => unreachable!("Should not happen since the argument is mandatory."),
    };
    let share: ChainArDecryptedData<ExampleCurve>;

    match ar_data
        .iter()
        .find(|&x| x.ar_identity == ar.public_ar_info.ar_identity)
    {
        None => {
            eprintln!("AR is not part of the credential");
            return;
        }
        Some(single_ar_data) => {
            let m = ar
                .ar_secret_key
                .decrypt(&single_ar_data.enc_id_cred_pub_share);
            share = ChainArDecryptedData {
                ar_identity:              single_ar_data.ar_identity,
                id_cred_pub_share_number: single_ar_data.id_cred_pub_share_number,
                id_cred_pub_share:        m,
            };
        }
    }
    if let Some(json_file) = matches.value_of("out") {
        match write_json_to_file(json_file, &share) {
            Ok(_) => println!("Wrote decryption to {}", json_file),
            Err(e) => {
                println!("Could not JSON write to file because {}", e);
                output_json(&share);
            }
        }
    } else {
        output_json(&share);
    }
}
