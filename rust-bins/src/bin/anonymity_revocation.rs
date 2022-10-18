use clap::AppSettings;
use client_server_helpers::*;
use crypto_common::*;
use crypto_common_derive::*;
use curve_arithmetic::{Curve, Value};
use dodis_yampolskiy_prf as prf;
use elgamal::{decrypt_from_chunks_given_generator, Message};
use id::{anonymity_revoker::*, constants::ArCurve, types::*};
use serde_json::json;
use std::{
    convert::TryFrom,
    path::{Path, PathBuf},
};
use structopt::StructOpt;

#[derive(StructOpt)]
struct DecryptPrf {
    #[structopt(
        long = "ar-record",
        help = "File with the JSON encoded anonymity revocation record."
    )]
    ar_record:      PathBuf,
    #[structopt(
        long = "ar-private",
        help = "File with anonymity revoker's private and public keys."
    )]
    ar_private:     PathBuf,
    #[structopt(long = "global-context", help = "File with global context.")]
    global_context: PathBuf,
    #[structopt(long = "out", help = "File to output the decryption to.")]
    out:            PathBuf,
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
        help = "File with anonymity revoker's private and public keys. As plaintext or encrypted."
    )]
    ar_private: PathBuf,
    #[structopt(long = "out", help = "File to output the decryption to")]
    out:        PathBuf,
}

#[derive(StructOpt)]
struct CombinePrf {
    #[structopt(
        long = "ar-record",
        help = "File with the JSON encoded anonymity revocation record."
    )]
    ar_record: PathBuf,
    #[structopt(
        long = "shares",
        help = "Files with the JSON encoded decrypted shares."
    )]
    shares:    Vec<PathBuf>,
    #[structopt(long = "out", help = "File to output the decryption to.")]
    out:       PathBuf,
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
    shares:     Vec<PathBuf>,
    #[structopt(long = "out", help = "File to output the decryption to.")]
    out:        PathBuf,
}

#[derive(StructOpt)]
struct ComputeRegIds {
    #[structopt(long = "ar-record", help = "The anonymity revocation record.")]
    ar_record:      PathBuf,
    #[structopt(long = "prf-key", help = "File containing the PRF key.")]
    prf_key:        PathBuf,
    #[structopt(long = "global-context", help = "File with global context.")]
    global_context: PathBuf,
    #[structopt(long = "out", help = "File to output the RegIds to")]
    out:            PathBuf,
    #[structopt(
        long = "no-secret",
        help = "Do __not__ output the decryption key together with the RegId."
    )]
    no_secret:      bool,
}

#[derive(StructOpt)]
#[structopt(
    about = "Prototype tool showcasing anonymity revoker (inter)actions.",
    author = "Concordium",
    version = "0.5"
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
        CombinePrf(cmb) => {
            if let Err(e) = handle_combine_prf(cmb) {
                eprintln!("{}", e)
            }
        }
        ComputeRegIds(rid) => {
            if let Err(e) = handle_compute_regids(rid) {
                eprintln!("{}", e)
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

fn handle_compute_regids(rid: ComputeRegIds) -> Result<(), String> {
    let prf_wrapper: PrfWrapper<ExampleCurve> = {
        let file_name = rid.prf_key;
        match read_json_from_file(file_name) {
            Ok(v) => v,
            Err(e) => {
                return Err(format!("Could not read prf key due to {}", e));
            }
        }
    };
    let global_context: Versioned<GlobalContext<ExampleCurve>> = {
        let file_name = rid.global_context;
        match read_json_from_file(file_name) {
            Ok(v) => v,
            Err(e) => {
                return Err(format!("Could not read global context because {}", e));
            }
        }
    };
    if global_context.version != VERSION_0 {
        return Err("The version of the GlobalContext should be 0".to_owned());
    }
    let global_context = global_context.value;
    let ar_record: Versioned<AnonymityRevocationRecord<ExampleCurve>> = succeed_or_die!(read_json_from_file(rid.ar_record), e => "Could not read ArRecord due to {}");

    if ar_record.version != VERSION_0 {
        return Err("The version of the ArRecord should be 0.".to_owned());
    }
    let max_account: u8 = ar_record.value.max_accounts;
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
                    "accountAddress": account_address_from_registration_id(&regid),
                    "encryptionSecretKey": elgamal::SecretKey{
                        generator: *global_context.elgamal_generator(),
                        scalar: secret
                    }
                }));
            } else {
                regids.push(json!({
                    "regId": regid_hex,
                    "accountAddress": account_address_from_registration_id(&regid),
                }));
            }
        }
    }

    match write_json_to_file(&rid.out, &regids) {
        Ok(_) => eprintln!("Wrote regIds to {}.", rid.out.display()),
        Err(e) => {
            eprintln!("Could not JSON write to file due to {}", e);
        }
    }
    Ok(())
}

// Try to read ArData, either from encrypted or a plaintext file.
fn decrypt_ar_data(fname: &Path) -> Result<ArData<ArCurve>, String> {
    let data = succeed_or_die!(std::fs::read(fname), e => "Could not read anonymity revoker secret keys due to {}");
    match serde_json::from_slice(&data) {
        Ok(v) => Ok(v),
        Err(_) => {
            // try to decrypt
            let parsed = succeed_or_die!(serde_json::from_slice(&data), e => "Could not parse encrypted file {}");
            let pass = succeed_or_die!(rpassword::prompt_password("Enter password to decrypt AR credentials: "), e => "Could not read password {}.");
            let decrypted = succeed_or_die!(crypto_common::encryption::decrypt(&pass.into(), &parsed), e =>  "Could not decrypt AR credentials. Most likely the password you provided is incorrect {}.");
            serde_json::from_slice(&decrypted).map_err(|_| {
                "Could not decrypt AR credentials. Most likely the password you provided is \
                 incorrect."
                    .to_owned()
            })
        }
    }
}

/// Decrypt encIdCredPubShare
fn handle_decrypt_id(dcr: Decrypt) -> Result<(), String> {
    let credential: Versioned<AccountCredentialValues<ExampleCurve, ExampleAttribute>> = succeed_or_die!(read_json_from_file(dcr.credential), e => "Could not read credential from provided file because {}");

    if credential.version != VERSION_0 {
        return Err("The version of the credential should be 0".to_owned());
    }
    let credential = match credential.value {
        AccountCredentialValues::Initial { .. } => {
            return Err("Cannot decrypt data from initial account.".to_owned())
        }
        AccountCredentialValues::Normal { cdi } => cdi,
    };

    let ar_data = credential.ar_data;
    let ar: ArData<ExampleCurve> = succeed_or_die!(decrypt_ar_data(&dcr.ar_private), e => "Could not read anonymity revoker secret keys due to {}");

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
    match write_json_to_file(&dcr.out, &share) {
        Ok(_) => println!("Wrote decryption to {}", dcr.out.display()),
        Err(e) => {
            eprintln!("Could not write JSON to file due to {}", e);
        }
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
    let ar: ArData<ExampleCurve> = succeed_or_die!(decrypt_ar_data(&dcr.ar_private), e => "Could not read AR secret keys due to {}");

    let single_ar_data = succeed_or_die!(
        ar_data.get(&ar.public_ar_info.ar_identity),
        "Given AR is not part of the credential."
    );
    let m = decrypt_from_chunks_given_generator(
        &ar.ar_secret_key,
        &single_ar_data.enc_prf_key_share,
        global_context.encryption_in_exponent_generator(),
        1 << 16,
        CHUNK_SIZE,
    );
    let share = IpArDecryptedData {
        ar_identity:   ar.public_ar_info.ar_identity,
        prf_key_share: m,
    };
    match write_json_to_file(&dcr.out, &share) {
        Ok(_) => println!("Wrote decryption to {}.", dcr.out.display()),
        Err(e) => {
            eprintln!("Could not write JSON to file because {}", e);
        }
    }
    Ok(())
}

fn handle_combine_id(cmb: Combine) -> Result<(), String> {
    let credential: Versioned<AccountCredentialValues<ExampleCurve, ExampleAttribute>> = succeed_or_die!(read_json_from_file(cmb.credential), e => "Could not read credential from provided file because {}");

    if credential.version != VERSION_0 {
        return Err("The version of the credential should be 0".to_owned());
    }
    let credential = match credential.value {
        AccountCredentialValues::Initial { .. } => {
            return Err("Cannot decrypt data from initial account.".to_owned())
        }
        AccountCredentialValues::Normal { cdi } => cdi,
    };
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
                share_value.display(),
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

    let json = json!({ "idCredPub": id_cred_pub_string });
    match write_json_to_file(&cmb.out, &json) {
        Ok(_) => println!("Wrote idCredPub to {}.", cmb.out.display()),
        Err(e) => {
            eprintln!("Could not write to file because {}", e);
        }
    }
    Ok(())
}

fn handle_combine_prf(cmb: CombinePrf) -> Result<(), String> {
    let ar_record: Versioned<AnonymityRevocationRecord<ExampleCurve>> = succeed_or_die!(read_json_from_file(cmb.ar_record), e => "Could not read ArRecord due to {}");

    if ar_record.version != VERSION_0 {
        return Err("The version of the ArRecord should be 0.".to_owned());
    }

    let revocation_threshold = ar_record.value.threshold;

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

    let mut ar_decrypted_data_vec: Vec<IpArDecryptedData<ExampleCurve>> =
        Vec::with_capacity(shares_values.len());
    let mut shares: Vec<(ArIdentity, Value<ExampleCurve>)> =
        Vec::with_capacity(shares_values.len());

    for share_value in shares_values.iter() {
        match read_json_from_file(&share_value) {
            Err(y) => {
                return Err(format!(
                    "Could not read from ar file {}, error: {}",
                    share_value.display(),
                    y
                ));
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
        return Err(
            "No duplicates among the anonymity revokers identities nor share numbers are allowed."
                .to_owned(),
        );
    }

    let prf_key = reveal_prf_key(&shares);
    let prf_key_string = base16_encode_string(&prf_key);
    let json = json!({ "prfKey": prf_key_string });
    match write_json_to_file(&cmb.out, &json) {
        Ok(_) => println!("Wrote PRF key to {}.", cmb.out.display()),
        Err(e) => {
            println!("Could not write to file because {}", e);
        }
    }
    Ok(())
}
