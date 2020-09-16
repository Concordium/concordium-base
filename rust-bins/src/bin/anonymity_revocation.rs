use clap::AppSettings;
use client_server_helpers::*;
use crypto_common::*;
use crypto_common_derive::*;
use curve_arithmetic::{Curve, Value};
use dodis_yampolskiy_prf::secret as prf;
use elgamal::{decrypt_from_chunks_given_generator, Message};
use id::{anonymity_revoker::*, types::*};
use serde_json::json;
use std::convert::TryFrom;

use std::path::PathBuf;
use structopt::StructOpt;

#[macro_use]
extern crate failure;
use failure::Fallible;

#[derive(StructOpt)]
struct DecryptPrf {
    #[structopt(
        long = "ar-record",
        help = "File with the JSON encoded (pre) identity object."
    )]
    ar_record: PathBuf,
    #[structopt(
        long = "ar-private",
        help = "File with anonymity revoker's private and public keys."
    )]
    ar_private: PathBuf,
    #[structopt(long = "global-context", help = "File with global context.")]
    global_context: PathBuf,
    #[structopt(long = "out", help = "File to output the decryption to")]
    out: Option<PathBuf>,
}

#[derive(StructOpt)]
struct Decrypt {
    #[structopt(
        long = "credential",
        help = "File with the JSON encoded credential or credential values."
    )]
    credential: PathBuf,
    #[structopt(
        long = "ar-private",
        help = "File with anonymity revoker's private and public keys."
    )]
    ar_private: PathBuf,
    #[structopt(long = "out", help = "File to output the decryption to")]
    out: Option<PathBuf>,
}

#[derive(StructOpt)]
struct CombinePrf {
    #[structopt(
        long = "credential",
        help = "File with the JSON encoded credential or credential values."
    )]
    credential: PathBuf,
    #[structopt(
        long = "shares",
        help = "Files with the JSON encoded decrypted shares."
    )]
    shares: Vec<PathBuf>,
    #[structopt(long = "out", help = "File to output the PRF key to")]
    out: Option<PathBuf>,
}

#[derive(StructOpt)]
struct Combine {
    #[structopt(
        long = "credential",
        help = "File with the JSON encoded credential or credential values."
    )]
    credential: PathBuf,
    #[structopt(
        long = "shares",
        help = "Files with the JSON encoded decrypted shares."
    )]
    shares: Vec<PathBuf>,
    #[structopt(long = "out", help = "File to output the IdCredPub to")]
    out: Option<PathBuf>,
}

#[derive(StructOpt)]
struct ComputeRegIds {
    #[structopt(
        long = "max-accounts",
        help = "Integer specifying the maximal number of accounts"
    )]
    max_accounts: u8,
    #[structopt(long = "prf-key", help = "File containing the PRF key.")]
    prf_key: PathBuf,
    #[structopt(long = "global-context", help = "File with global context.")]
    global_context: PathBuf,
    #[structopt(long = "out", help = "File to output the RegIds to")]
    out: Option<PathBuf>,
}

#[derive(StructOpt)]
#[structopt(
    about = "Prototype tool showcasing anonymity revoker (inter)actions.",
    author = "Concordium",
    version = "0.36787944117"
)]
enum AnonymityRevocation {
    #[structopt(
        name = "decrypt",
        about = "Take a deployed credential and let one anonymity revoker decrypt its encrypted \
                 share if idCredPub"
    )]
    Decrypt(Decrypt),
    #[structopt(
        name = "combine",
        about = "Combines decrypted shares of anonymity revokers to get idCredPub"
    )]
    Combine(Combine),
    #[structopt(
        name = "decrypt-prf",
        about = "Take a deployed credential and let one anonymity revoker decrypt its encrypted \
                 share of the PRF key"
    )]
    DecryptPrf(DecryptPrf),
    #[structopt(
        name = "combine-prf",
        about = "Combines decrypted shares of anonymity revokers to get the PRF key"
    )]
    CombinePrf(CombinePrf),
    #[structopt(
        name = "compute-regids",
        about = "Computes all possible RegIds given a PRF key and the maximal number of accounts."
    )]
    ComputeRegIds(ComputeRegIds),
}

#[derive(Debug, Serialize, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(serialize = "C: Curve", deserialize = "C: Curve"))]
struct PrfWrapper<C: Curve> {
    #[serde(rename = "prfKey")]
    pub prf_key: prf::SecretKey<C>,
}

fn main() {
    let app = AnonymityRevocation::clap()
        .setting(AppSettings::ArgRequiredElseHelp)
        .global_setting(AppSettings::ColoredHelp);
    let matches = app.get_matches();
    let ar = AnonymityRevocation::from_clap(&matches);
    use AnonymityRevocation::*;
    match ar {
        Decrypt(dcr) => handle_decrypt_id(dcr),
        Combine(cmb) => handle_combine_id(cmb),
        DecryptPrf(dcr) => handle_decrypt_prf(dcr),
        CombinePrf(cmb) => handle_combine_prf(cmb),
        ComputeRegIds(rid) => handle_compute_regids(rid),
    }
}

fn handle_compute_regids(rid: ComputeRegIds) {
    let prf_wrapper: PrfWrapper<ExampleCurve> = {
        let file_name = rid.prf_key;
        match read_json_from_file(file_name) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Could not read credential because {}", e);
                return;
            }
        }
    };
    let global_context: Versioned<GlobalContext<ExampleCurve>> = {
        let file_name = rid.global_context;
        match read_json_from_file(file_name) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Could not read global context because {}", e);
                return;
            }
        }
    };
    if global_context.version != VERSION_0 {
        eprintln!("The version of the GlobalContext should be 0");
        return;
    }
    let global_context = global_context.value;

    let max_accounts: u8 = rid.max_accounts;
    let g = global_context.on_chain_commitment_key.g;
    let prf_key: prf::SecretKey<_> = prf_wrapper.prf_key;

    let mut regids = Vec::with_capacity(usize::from(max_accounts));
    for x in 0..max_accounts {
        let regid = prf_key.prf(&g, x);
        match regid {
            Ok(id) => regids.push(hex::encode(&to_bytes(&id))),
            Err(x) => {
                eprintln!("Could not produce RegIds, because {} ", x);
                return;
            }
        };
    }
    // let json = json!({ "regIds": regids});
    println!("Here is a list of regids:");
    output_json(&regids);
    if let Some(json_file) = rid.out {
        let json = json!({ "regIds": regids });
        let name = json_file.clone();
        match write_json_to_file(json_file, &json) {
            Ok(_) => println!("Wrote regIds to {:?}.", name.file_name().unwrap()),
            Err(e) => {
                println!("Could not JSON write to file because {}", e);
                output_json(&json);
            }
        }
    }
    // println!("{:?}\n {}", prf_wrapper.prf_key, max_accounts);
}

/// Decrypt encIdCredPubShare
fn handle_decrypt_id(dcr: Decrypt) {
    let credential: Versioned<CredentialDeploymentValues<ExampleCurve, ExampleAttribute>> = {
        let file_name = dcr.credential;
        match read_json_from_file(file_name) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Could not read credential because {}", e);
                return;
            }
        }
    };
    if credential.version != VERSION_0 {
        eprintln!("The version of the credential should be 0");
        return;
    }
    let credential = credential.value;

    let ar_data = credential.ar_data;
    let ar: ArData<ExampleCurve> = match read_json_from_file(dcr.ar_private) {
        Ok(r) => r,
        Err(x) => {
            eprintln!("Could not read ar-private because {}", x);
            return;
        }
    };
    let share: ChainArDecryptedData<ExampleCurve>;

    match ar_data.get(&ar.public_ar_info.ar_identity) {
        None => {
            eprintln!("AR is not part of the credential");
            return;
        }
        Some(single_ar_data) => {
            let m = ar
                .ar_secret_key
                .decrypt(&single_ar_data.enc_id_cred_pub_share);
            share = ChainArDecryptedData {
                ar_identity:       ar.public_ar_info.ar_identity,
                id_cred_pub_share: m,
            };
        }
    }
    if let Some(json_file) = dcr.out {
        let name = json_file.clone();
        match write_json_to_file(json_file, &share) {
            Ok(_) => println!("Wrote decryption to {:?}", name.file_name().unwrap()),
            Err(e) => {
                println!("Could not JSON write to file because {}", e);
                output_json(&share);
            }
        }
    } else {
        output_json(&share);
    }
}

/// Decrypt encPrfKeyShare
fn handle_decrypt_prf(dcr: DecryptPrf) {
    let ar_record: Versioned<AnonymityRevocationRecord<ExampleCurve>> = {
        let file_name = dcr.ar_record;
        match read_json_from_file(file_name) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Could not read ArRecord because {}", e);
                return;
            }
        }
    };

    if ar_record.version != VERSION_0 {
        eprintln!("The version of the ArRecord should be 0");
        return;
    }
    let ar_record = ar_record.value;

    let global_context: Versioned<GlobalContext<ExampleCurve>> = {
        let file_name = dcr.global_context;
        match read_json_from_file(file_name) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Could not read global context because {}", e);
                return;
            }
        }
    };
    if global_context.version != VERSION_0 {
        eprintln!("The version of the GlobalContext should be 0");
        return;
    }
    let global_context = global_context.value;

    let ar_data = ar_record.ar_data;
    let ar: ArData<ExampleCurve> = match read_json_from_file(dcr.ar_private) {
        Ok(r) => r,
        Err(x) => {
            eprintln!("Could not read ar-private because {}", x);
            return;
        }
    };
    let share: IpArDecryptedData<ExampleCurve>;

    match ar_data.get(&ar.public_ar_info.ar_identity) {
        None => {
            eprintln!("AR is not part of the record");
            return;
        }
        Some(single_ar_data) => {
            let m = decrypt_from_chunks_given_generator(
                &ar.ar_secret_key,
                &single_ar_data.enc_prf_key_share,
                &global_context.encryption_in_exponent_generator(),
                1 << 16,
                CHUNK_SIZE,
            );
            share = IpArDecryptedData {
                ar_identity:   ar.public_ar_info.ar_identity,
                prf_key_share: m,
            };
        }
    }
    if let Some(json_file) = dcr.out {
        let name = json_file.clone();
        match write_json_to_file(json_file, &share) {
            Ok(_) => println!("Wrote decryption to {:?}", name.file_name().unwrap()),
            Err(e) => {
                println!("Could not JSON write to file because {}", e);
                output_json(&share);
            }
        }
    } else {
        output_json(&share);
    }
}

fn handle_combine_id(cmb: Combine) {
    let credential: Versioned<CredentialDeploymentValues<ExampleCurve, ExampleAttribute>> = {
        let file_name = cmb.credential;
        match read_json_from_file(file_name) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Could not read credential because {}", e);
                return;
            }
        }
    };
    if credential.version != VERSION_0 {
        eprintln!("The version should be 0");
        return;
    }
    let credential = credential.value;
    let revocation_threshold = credential.threshold;

    let shares_values: Vec<_> = cmb.shares;

    let number_of_ars = shares_values.len();
    let number_of_ars =
        u8::try_from(number_of_ars).expect("Number of anonymity revokers should not exceed 2^8-1");
    if number_of_ars < revocation_threshold.into() {
        eprintln!(
            "insufficient number of anonymity revokers {}, {:?}",
            number_of_ars, revocation_threshold
        );
        return;
    }

    let mut ar_decrypted_data_vec: Vec<ChainArDecryptedData<ExampleCurve>> =
        Vec::with_capacity(shares_values.len());
    let mut shares: Vec<(ArIdentity, Message<ExampleCurve>)> =
        Vec::with_capacity(shares_values.len());

    for share_value in shares_values.iter() {
        let name = share_value.clone();
        match read_json_from_file(share_value) {
            Err(y) => {
                match name.file_name() {
                    Some(name) => eprintln!("Could not read from ar file {:?}, error: {}", name, y),
                    None => eprintln!("Could not read from ar file, error: {}", y),
                }
                return;
            }
            Ok(val) => ar_decrypted_data_vec.push(val),
        }
    }

    let mut ar_identities = Vec::with_capacity(ar_decrypted_data_vec.len());

    for ar_decrypted_data in ar_decrypted_data_vec {
        let ar_id = ar_decrypted_data.ar_identity;
        ar_identities.push(ar_id);
        shares.push((ar_id, ar_decrypted_data.id_cred_pub_share));
    }
    ar_identities.sort();
    ar_identities.dedup();
    if ar_identities.len() < shares.len() {
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

    if let Some(json_file) = cmb.out {
        let json = json!({ "idCredPub": id_cred_pub_string });
        let name = json_file.clone();
        match write_json_to_file(json_file, &json) {
            Ok(_) => println!("Wrote idCredPub to {:?}.", name.file_name().unwrap()),
            Err(e) => {
                println!("Could not JSON write to file because {}", e);
                output_json(&json);
            }
        }
    }
}

fn handle_combine_prf(cmb: CombinePrf) {
    let credential: Versioned<CredentialDeploymentValues<ExampleCurve, ExampleAttribute>> = {
        let file_name = cmb.credential;
        match read_json_from_file(file_name) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Could not read credential because {}", e);
                return;
            }
        }
    };
    if credential.version != VERSION_0 {
        eprintln!("The version should be 0");
        return;
    }
    let credential = credential.value;
    let revocation_threshold = credential.threshold;

    let shares_values: Vec<_> = cmb.shares;

    let number_of_ars = shares_values.len();
    let number_of_ars =
        u8::try_from(number_of_ars).expect("Number of anonymity revokers should not exceed 2^8-1");
    if number_of_ars < revocation_threshold.into() {
        eprintln!(
            "insufficient number of anonymity revokers {}, {:?}",
            number_of_ars, revocation_threshold
        );
        return;
    }

    let mut ar_decrypted_data_vec: Vec<IpArDecryptedData<ExampleCurve>> =
        Vec::with_capacity(shares_values.len());
    let mut shares: Vec<(ArIdentity, Value<ExampleCurve>)> =
        Vec::with_capacity(shares_values.len());

    for share_value in shares_values.iter() {
        let name = share_value.clone();
        match read_json_from_file(share_value) {
            Err(y) => {
                match name.file_name() {
                    Some(name) => eprintln!("Could not read from ar file {:?}, error: {}", name, y),
                    None => eprintln!("Could not read from ar file, error: {}", y),
                }
                return;
            }
            Ok(val) => ar_decrypted_data_vec.push(val),
        }
    }

    let mut ar_identities = Vec::with_capacity(ar_decrypted_data_vec.len());

    for ar_decrypted_data in ar_decrypted_data_vec {
        let ar_id = ar_decrypted_data.ar_identity;
        ar_identities.push(ar_id);
        shares.push((ar_id, ar_decrypted_data.prf_key_share));
    }
    ar_identities.sort();
    ar_identities.dedup();
    if ar_identities.len() < shares.len() {
        println!(
            "No duplicates among the anonymity revokers identities nor share numbers are allowed"
        );
        return;
    }

    let prf_key = reveal_prf_key(&shares);
    let prf_key_string = base16_encode_string(&prf_key);
    println!("PRF key is:\n {}", prf_key_string);

    if let Some(json_file) = cmb.out {
        let json = json!({ "prfKey": prf_key_string });
        let name = json_file.clone();
        match write_json_to_file(json_file, &json) {
            Ok(_) => println!("Wrote prfKey to {:?}.", name.file_name().unwrap()),
            Err(e) => {
                println!("Could not JSON write to file because {}", e);
                output_json(&json);
            }
        }
    }
}
