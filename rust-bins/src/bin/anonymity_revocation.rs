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
    #[structopt(long = "out", help = "File to output the decryption to.")]
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
    #[structopt(long = "out", help = "File to output the decryption to.")]
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
    #[structopt(long = "out", help = "File to output the decryption to.")]
    out: Option<PathBuf>,
}

#[derive(StructOpt)]
struct ComputeRegIds {
    #[structopt(
        long = "max-account",
        help = "Integer specifying the maximal account number that could have been used.",
        default_value = "255"
    )]
    max_account: u8,
    #[structopt(long = "prf-key", help = "File containing the PRF key.")]
    prf_key: PathBuf,
    #[structopt(long = "global-context", help = "File with global context.")]
    global_context: PathBuf,
    #[structopt(long = "out", help = "File to output the RegIds to")]
    out: Option<PathBuf>,
    #[structopt(
        long = "no-secret",
        help = "Do __not__ output the decryption key together with the RegId."
    )]
    no_secret: bool,
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
        about = "Take a deployed credential and decrypt a share of idCredPub."
    )]
    Decrypt(Decrypt),
    #[structopt(
        name = "combine",
        about = "Combine decrypted shares of anonymity revokers to get idCredPub."
    )]
    Combine(Combine),
    #[structopt(
        name = "decrypt-prf",
        about = "Take an anonymity revocation record and let one anonymity revoker decrypt its \
                 share of the PRF key."
    )]
    DecryptPrf(DecryptPrf),
    #[structopt(
        name = "combine-prf",
        about = "Combine decrypted shares of the PRF key to reconstruct the PRF key."
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
        Decrypt(dcr) => {
            if let Err(e) = handle_decrypt_id(dcr) {
                eprintln!("{}", e)
            }
        }
        Combine(cmb) => {
            if let Err(e) = handle_combine_id(cmb) {
                eprintln!("{}", e)
            }
        }
        DecryptPrf(dcr) => {
            if let Err(e) = handle_decrypt_prf(dcr) {
                eprintln!("{}", e)
            }
        }
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

    let max_account: u8 = rid.max_account;
    let g = global_context.on_chain_commitment_key.g;
    let prf_key: prf::SecretKey<_> = prf_wrapper.prf_key;

    let mut regids = Vec::with_capacity(usize::from(max_account));
    for x in 0..=max_account {
        if let Ok(secret) = prf_key.prf_exponent(x) {
            let regid = g.mul_by_scalar(&secret);
            let regid_hex = hex::encode(&to_bytes(&regid));
            if !rid.no_secret {
                regids.push(json!({
                    "regId": regid_hex,
                    "accountAddress": AccountAddress::new(&regid),
                    "decryptionKey": hex::encode(&to_bytes(&secret))
                }));
            } else {
                regids.push(json!({
                    "regId": regid_hex,
                    "accountAddress": AccountAddress::new(&regid),
                }));
            }
        }
    }

    if let Some(json_file) = rid.out {
        match write_json_to_file(&json_file, &regids) {
            Ok(_) => eprintln!("Wrote regIds to {}.", json_file.to_string_lossy()),
            Err(e) => {
                eprintln!("Could not JSON write to file because {}", e);
                eprintln!("Here are the potential accounts.");
                output_json(&regids);
            }
        }
    }
}

macro_rules! succeed_or_die {
    ($e:expr, $match:ident => $s:expr) => {
        match $e {
            Ok(v) => v,
            Err($match) => return Err(format!($s, $match)),
        }
    };
    ($e:expr, $s:expr) => {
        match $e {
            Some(x) => x,
            None => return Err($s.to_owned()),
        }
    };
}

/// Decrypt encIdCredPubShare
fn handle_decrypt_id(dcr: Decrypt) -> Result<(), String> {
    let credential: Versioned<CredentialDeploymentValues<ExampleCurve, ExampleAttribute>> = succeed_or_die!(read_json_from_file(dcr.credential), e => "Could not read credential from provided file because {}");

    if credential.version != VERSION_0 {
        return Err("The version of the credential should be 0".to_owned());
    }
    let credential = credential.value;

    let ar_data = credential.ar_data;
    let ar: ArData<ExampleCurve> = succeed_or_die!(read_json_from_file(dcr.ar_private), e => "Could not read anonymity revoker secret keys due to {}");

    let single_ar_data = succeed_or_die!(
        ar_data.get(&ar.public_ar_info.ar_identity),
        "Supplied AR is not part of the credential."
    );
    let m = ar
        .ar_secret_key
        .decrypt(&single_ar_data.enc_id_cred_pub_share);
    let share = ChainArDecryptedData {
        ar_identity:       ar.public_ar_info.ar_identity,
        id_cred_pub_share: m,
    };
    if let Some(json_file) = dcr.out {
        match write_json_to_file(&json_file, &share) {
            Ok(_) => eprintln!("Wrote decryption to {}", json_file.to_string_lossy()),
            Err(e) => {
                eprintln!("Could not write JSON to file due to {}", e);
                output_json(&share);
            }
        }
    } else {
        output_json(&share);
    }
    Ok(())
}

/// Decrypt encPrfKeyShare
fn handle_decrypt_prf(dcr: DecryptPrf) -> Result<(), String> {
    let ar_record: Versioned<AnonymityRevocationRecord<ExampleCurve>> = succeed_or_die!(read_json_from_file(dcr.ar_record), e => "Could not read ArRecord due to {}");

    if ar_record.version != VERSION_0 {
        return Err("The version of the ArRecord should be 0.".to_owned());
    }
    let ar_record = ar_record.value;

    let global_context: Versioned<GlobalContext<ExampleCurve>> = succeed_or_die!(read_json_from_file(dcr.global_context), e => "Could not read global context due to {}");
    if global_context.version != VERSION_0 {
        return Err("The version of the GlobalContext should be 0.".to_owned());
    }
    let global_context = global_context.value;

    let ar_data = ar_record.ar_data;
    let ar: ArData<ExampleCurve> = succeed_or_die!(read_json_from_file(dcr.ar_private), e => "Could not read AR secret keys due to {}");

    let single_ar_data = succeed_or_die!(
        ar_data.get(&ar.public_ar_info.ar_identity),
        "Given AR is not part of the credential."
    );
    let m = decrypt_from_chunks_given_generator(
        &ar.ar_secret_key,
        &single_ar_data.enc_prf_key_share,
        &global_context.encryption_in_exponent_generator(),
        1 << 16,
        CHUNK_SIZE,
    );
    let share = IpArDecryptedData {
        ar_identity:   ar.public_ar_info.ar_identity,
        prf_key_share: m,
    };
    if let Some(json_file) = dcr.out {
        match write_json_to_file(&json_file, &share) {
            Ok(_) => eprintln!("Wrote decryption to {}.", json_file.to_string_lossy()),
            Err(e) => {
                eprintln!("Could not write JSON to file because {}", e);
                output_json(&share);
            }
        }
    } else {
        output_json(&share);
    }
    Ok(())
}

fn handle_combine_id(cmb: Combine) -> Result<(), String> {
    let credential: Versioned<CredentialDeploymentValues<ExampleCurve, ExampleAttribute>> = succeed_or_die!(read_json_from_file(cmb.credential), e => "Could not read credential because {}.");
    if credential.version != VERSION_0 {
        return Err("The version should be 0".to_owned());
    }
    let credential = credential.value;
    let revocation_threshold = credential.threshold;

    let shares_values: Vec<_> = cmb.shares;

    let number_of_ars = shares_values.len();
    let number_of_ars =
        u8::try_from(number_of_ars).expect("Number of anonymity revokers should not exceed 2^8-1");
    if number_of_ars < revocation_threshold.into() {
        return Err(format!(
            "Insufficient number of anonymity revokers ({}). Threshold is {}.",
            number_of_ars, revocation_threshold
        ));
    }

    let mut ar_decrypted_data_vec: Vec<ChainArDecryptedData<ExampleCurve>> =
        Vec::with_capacity(shares_values.len());
    let mut shares: Vec<(ArIdentity, Message<ExampleCurve>)> =
        Vec::with_capacity(shares_values.len());

    for share_value in shares_values.iter() {
        let decrypted = read_json_from_file(&share_value).map_err(|e| {
            format!(
                "Could not read from ar file {}, error: {}",
                share_value.to_string_lossy(),
                e
            )
        })?;
        ar_decrypted_data_vec.push(decrypted);
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
        return Err(
            "No duplicates among the anonymity revokers identities nor share numbers are allowed."
                .to_owned(),
        );
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
        match write_json_to_file(&json_file, &json) {
            Ok(_) => eprintln!("Wrote idCredPub to {}.", json_file.to_string_lossy()),
            Err(e) => {
                eprintln!("Could not JSON write to file because {}", e);
                output_json(&json);
            }
        }
    }
    Ok(())
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
            "Insufficient number of anonymity revokers ({}). Threshold is {}.",
            number_of_ars, revocation_threshold
        );
        return;
    }

    let mut ar_decrypted_data_vec: Vec<IpArDecryptedData<ExampleCurve>> =
        Vec::with_capacity(shares_values.len());
    let mut shares: Vec<(ArIdentity, Value<ExampleCurve>)> =
        Vec::with_capacity(shares_values.len());

    for share_value in shares_values.iter() {
        match read_json_from_file(&share_value) {
            Err(y) => {
                eprintln!(
                    "Could not read from ar file {}, error: {}",
                    share_value.to_string_lossy(),
                    y
                );
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
        match write_json_to_file(&json_file, &json) {
            Ok(_) => println!("Wrote PRF key to {}.", json_file.to_string_lossy()),
            Err(e) => {
                println!("Could not JSON write to file because {}", e);
                output_json(&json);
            }
        }
    }
}
