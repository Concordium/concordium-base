use clap::AppSettings;
use client_server_helpers::*;
use concordium_base::{
    common::*,
    curve_arithmetic::{Curve, Value},
    dodis_yampolskiy_prf as prf, elgamal,
    elgamal::{decrypt_from_chunks_given_generator, Message},
    id::{anonymity_revoker::*, constants::ArCurve, types::*},
};
use serde_json::json;
use std::{convert::TryFrom, path::PathBuf};
use structopt::StructOpt;

#[derive(StructOpt)]
struct DecryptLinkingKey {
    #[structopt(
        long = "id-record",
        help = "File with the JSON encoded identity record."
    )]
    id_record:      PathBuf,
    #[structopt(
        long = "pg-private",
        help = "File with privacy guardians's private and public keys. As plaintext or encrypted."
    )]
    pg_private:     PathBuf,
    #[structopt(long = "global-context", help = "File with global context.")]
    global_context: PathBuf,
    #[structopt(long = "out", help = "File to output the decrypted share to.")]
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
        long = "pg-private",
        help = "File with privacy guardians's private and public keys. As plaintext or encrypted."
    )]
    pg_private: PathBuf,
    #[structopt(long = "out", help = "File to output the decrypted share to.")]
    out:        PathBuf,
}

#[derive(StructOpt)]
struct CombineLinkingKey {
    #[structopt(
        long = "id-record",
        help = "File with the JSON encoded identity record."
    )]
    id_record: PathBuf,
    #[structopt(
        long = "shares",
        help = "Files with the JSON encoded decrypted linking key shares."
    )]
    shares:    Vec<PathBuf>,
    #[structopt(long = "out", help = "File to output the combined linking key to.")]
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
        help = "Files with the JSON encoded decrypted identifier shares."
    )]
    shares:     Vec<PathBuf>,
    #[structopt(long = "out", help = "File to output the public holder identifier to.")]
    out:        PathBuf,
}

#[derive(StructOpt)]
struct ComputeCredIds {
    #[structopt(long = "id-record", help = "The identity record.")]
    id_record:      PathBuf,
    #[structopt(long = "key", help = "File containing the decrypted linking key.")]
    key:            PathBuf,
    #[structopt(long = "global-context", help = "File with global context.")]
    global_context: PathBuf,
    #[structopt(
        long = "out",
        help = "File to output the account credential identifiers to"
    )]
    out:            PathBuf,
    #[structopt(
        long = "no-secret",
        help = "Do __not__ output the account decryption key together with the account credential \
                identifiers."
    )]
    no_secret:      bool,
}

#[derive(StructOpt)]
#[structopt(
    about = "Prototype tool showcasing identity disclosure (inter)actions.",
    author = "Concordium",
    version = "0.6"
)]
enum IdentityDisclosure {
    #[structopt(
        name = "decrypt",
        about = "Take a deployed account credential and decrypt a share of the public holder \
                 identifier."
    )]
    Decrypt(Decrypt),
    #[structopt(
        name = "combine",
        about = "Combine decrypted shares of privacy guardians to get the public holder \
                 identifier."
    )]
    Combine(Combine),
    #[structopt(
        name = "decrypt-linking-key",
        about = "Take an identity record and let one privacy guardian decrypt its share of the \
                 linking key."
    )]
    DecryptLinkingKey(DecryptLinkingKey),
    #[structopt(
        name = "combine-linking-key",
        about = "Combine decrypted shares of the linking key to reconstruct the linking key."
    )]
    CombineLinkingKey(CombineLinkingKey),
    #[structopt(
        name = "compute-credids",
        about = "Computes all possible account credential identifiers given a linking key and the \
                 maximal number of accounts."
    )]
    ComputeCredIds(ComputeCredIds),
}

#[derive(Debug, Serialize, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(serialize = "C: Curve", deserialize = "C: Curve"))]
struct PrfWrapper<C: Curve> {
    #[serde(rename = "prfKey")]
    pub prf_key: prf::SecretKey<C>,
}

fn main() {
    let app = IdentityDisclosure::clap()
        .setting(AppSettings::ArgRequiredElseHelp)
        .global_setting(AppSettings::ColoredHelp);
    let matches = app.get_matches();
    let id = IdentityDisclosure::from_clap(&matches);
    use IdentityDisclosure::*;
    match id {
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
        DecryptLinkingKey(dcr) => {
            if let Err(e) = handle_decrypt_key(dcr) {
                eprintln!("{}", e)
            }
        }
        CombineLinkingKey(cmb) => {
            if let Err(e) = handle_combine_key(cmb) {
                eprintln!("{}", e)
            }
        }
        ComputeCredIds(rid) => {
            if let Err(e) = handle_compute_cred_id(rid) {
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

fn handle_compute_cred_id(rid: ComputeCredIds) -> Result<(), String> {
    let prf_wrapper: PrfWrapper<ArCurve> = {
        let file_name = rid.key;
        match read_json_from_file(file_name) {
            Ok(v) => v,
            Err(e) => {
                return Err(format!("Could not read decrypted linking key due to {}", e));
            }
        }
    };
    let global_context: Versioned<GlobalContext<ArCurve>> = {
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
    let id_record: Versioned<AnonymityRevocationRecord<ArCurve>> = succeed_or_die!(read_json_from_file(rid.id_record), e => "Could not read identity record due to {}");

    if id_record.version != VERSION_0 {
        return Err("The version of the identity record should be 0.".to_owned());
    }
    let max_account: u8 = id_record.value.max_accounts;
    let g = global_context.on_chain_commitment_key.g;
    let prf_key: prf::SecretKey<_> = prf_wrapper.prf_key;

    let mut credids = Vec::with_capacity(usize::from(max_account));
    for x in 0..=max_account {
        if let Ok(secret) = prf_key.prf_exponent(x) {
            let credid = g.mul_by_scalar(&secret);
            let credid_hex = hex::encode(to_bytes(&credid));
            if !rid.no_secret {
                credids.push(json!({
                    "regId": credid_hex,
                    "accountAddress": account_address_from_registration_id(&credid),
                    "encryptionSecretKey": elgamal::SecretKey{
                        generator: *global_context.elgamal_generator(),
                        scalar: secret
                    }
                }));
            } else {
                credids.push(json!({
                    "regId": credid_hex,
                    "accountAddress": account_address_from_registration_id(&credid),
                }));
            }
        }
    }

    match write_json_to_file(&rid.out, &credids) {
        Ok(_) => eprintln!("Wrote account credential ids to {}.", rid.out.display()),
        Err(e) => {
            eprintln!("Could not JSON write to file due to {}", e);
        }
    }
    Ok(())
}

/// Decrypt encIdCredPubShare
fn handle_decrypt_id(dcr: Decrypt) -> Result<(), String> {
    let credential: Versioned<AccountCredentialValues<ArCurve, ExampleAttribute>> = succeed_or_die!(read_json_from_file(dcr.credential), e => "Could not read account credential from provided file because {}");

    if credential.version != VERSION_0 {
        return Err("The version of the account credential should be 0".to_owned());
    }
    let credential = match credential.value {
        AccountCredentialValues::Initial { .. } => {
            return Err("Cannot decrypt data from initial account.".to_owned())
        }
        AccountCredentialValues::Normal { cdi } => cdi,
    };

    let pg_data = credential.ar_data;
    let pg: ArData<ArCurve> = succeed_or_die!(decrypt_pg_data(&dcr.pg_private), e => "Could not read privacy guardian's secret keys due to {}");

    let single_pg_data = succeed_or_die!(
        pg_data.get(&pg.public_ar_info.ar_identity),
        "Supplied PG is not part of the credential."
    );
    let m = pg
        .ar_secret_key
        .decrypt(&single_pg_data.enc_id_cred_pub_share);
    let share = ChainArDecryptedData {
        ar_identity:       pg.public_ar_info.ar_identity,
        id_cred_pub_share: m,
    };
    match write_json_to_file(&dcr.out, &share) {
        Ok(_) => println!(
            "Wrote decrypted public holder identifier share to {}",
            dcr.out.display()
        ),
        Err(e) => {
            eprintln!("Could not write JSON to file due to {}", e);
        }
    }
    Ok(())
}

/// Decrypt encPrfKeyShare
fn handle_decrypt_key(dcr: DecryptLinkingKey) -> Result<(), String> {
    let id_record: Versioned<AnonymityRevocationRecord<ArCurve>> = succeed_or_die!(read_json_from_file(dcr.id_record), e => "Could not read identity record due to {}");

    if id_record.version != VERSION_0 {
        return Err("The version of the identity record should be 0.".to_owned());
    }
    let pg_record = id_record.value;

    let global_context: Versioned<GlobalContext<ArCurve>> = succeed_or_die!(read_json_from_file(dcr.global_context), e => "Could not read global context due to {}");
    if global_context.version != VERSION_0 {
        return Err("The version of the GlobalContext should be 0.".to_owned());
    }
    let global_context = global_context.value;

    let pg_data = pg_record.ar_data;
    let pg: ArData<ArCurve> = succeed_or_die!(decrypt_pg_data(&dcr.pg_private), e => "Could not read privacy guardian's secret keys due to {}");

    let single_pg_data = succeed_or_die!(
        pg_data.get(&pg.public_ar_info.ar_identity),
        "Given PG is not part of the identity record."
    );
    let m = decrypt_from_chunks_given_generator(
        &pg.ar_secret_key,
        &single_pg_data.enc_prf_key_share,
        global_context.encryption_in_exponent_generator(),
        1 << 16,
        CHUNK_SIZE,
    );
    let share = IpArDecryptedData {
        ar_identity:   pg.public_ar_info.ar_identity,
        prf_key_share: m,
    };
    match write_json_to_file(&dcr.out, &share) {
        Ok(_) => println!(
            "Wrote decrypted linking key share to {}.",
            dcr.out.display()
        ),
        Err(e) => {
            eprintln!("Could not write JSON to file because {}", e);
        }
    }
    Ok(())
}

fn handle_combine_id(cmb: Combine) -> Result<(), String> {
    let credential: Versioned<AccountCredentialValues<ArCurve, ExampleAttribute>> = succeed_or_die!(read_json_from_file(cmb.credential), e => "Could not read account credential from provided file because {}");

    if credential.version != VERSION_0 {
        return Err("The version of the account credential should be 0".to_owned());
    }
    let credential = match credential.value {
        AccountCredentialValues::Initial { .. } => {
            return Err("Cannot decrypt data from initial account.".to_owned())
        }
        AccountCredentialValues::Normal { cdi } => cdi,
    };
    let revocation_threshold = credential.threshold;

    let shares_values: Vec<_> = cmb.shares;

    let number_of_pgs = shares_values.len();
    let number_of_pgs =
        u8::try_from(number_of_pgs).expect("Number of privacy guardians should not exceed 2^8-1");
    if number_of_pgs < revocation_threshold.into() {
        return Err(format!(
            "Insufficient number of privacy guardians ({}). Threshold is {}.",
            number_of_pgs, revocation_threshold
        ));
    }

    let mut pg_decrypted_data_vec: Vec<ChainArDecryptedData<ArCurve>> =
        Vec::with_capacity(shares_values.len());
    let mut shares: Vec<(ArIdentity, Message<ArCurve>)> = Vec::with_capacity(shares_values.len());

    for share_value in shares_values.iter() {
        let decrypted = read_json_from_file(share_value).map_err(|e| {
            format!(
                "Could not read from PG share file {}, error: {}",
                share_value.display(),
                e
            )
        })?;
        pg_decrypted_data_vec.push(decrypted);
    }

    let mut pg_identities = Vec::with_capacity(pg_decrypted_data_vec.len());

    for pg_decrypted_data in pg_decrypted_data_vec {
        let pg_id = pg_decrypted_data.ar_identity;
        pg_identities.push(pg_id);
        shares.push((pg_id, pg_decrypted_data.id_cred_pub_share));
    }
    pg_identities.sort();
    pg_identities.dedup();
    if pg_identities.len() < shares.len() {
        return Err(
            "No duplicates among the privacy guardian identities nor share numbers are allowed."
                .to_owned(),
        );
    }

    let id_cred_pub = reveal_id_cred_pub(&shares);
    let id_cred_pub_string = base16_encode_string(&id_cred_pub);

    let json = json!({ "idCredPub": id_cred_pub_string });
    match write_json_to_file(&cmb.out, &json) {
        Ok(_) => println!("Wrote public holder identifier to {}.", cmb.out.display()),
        Err(e) => {
            eprintln!("Could not write to file because {}", e);
        }
    }
    Ok(())
}

fn handle_combine_key(cmb: CombineLinkingKey) -> Result<(), String> {
    let id_record: Versioned<AnonymityRevocationRecord<ArCurve>> = succeed_or_die!(read_json_from_file(cmb.id_record), e => "Could not read identity record due to {}");

    if id_record.version != VERSION_0 {
        return Err("The version of the identity record should be 0.".to_owned());
    }

    let revocation_threshold = id_record.value.threshold;

    let shares_values: Vec<_> = cmb.shares;

    let number_of_pgs = shares_values.len();
    let number_of_pgs =
        u8::try_from(number_of_pgs).expect("Number of privacy guardians should not exceed 2^8-1");
    if number_of_pgs < revocation_threshold.into() {
        return Err(format!(
            "Insufficient number of privacy guardians ({}). Threshold is {}.",
            number_of_pgs, revocation_threshold
        ));
    }

    let mut pg_decrypted_data_vec: Vec<IpArDecryptedData<ArCurve>> =
        Vec::with_capacity(shares_values.len());
    let mut shares: Vec<(ArIdentity, Value<ArCurve>)> = Vec::with_capacity(shares_values.len());

    for share_value in shares_values.iter() {
        match read_json_from_file(share_value) {
            Err(y) => {
                return Err(format!(
                    "Could not read from PG share file {}, error: {}",
                    share_value.display(),
                    y
                ));
            }
            Ok(val) => pg_decrypted_data_vec.push(val),
        }
    }

    let mut pg_identities = Vec::with_capacity(pg_decrypted_data_vec.len());

    for pg_decrypted_data in pg_decrypted_data_vec {
        let pg_id = pg_decrypted_data.ar_identity;
        pg_identities.push(pg_id);
        shares.push((pg_id, pg_decrypted_data.prf_key_share));
    }
    pg_identities.sort();
    pg_identities.dedup();
    if pg_identities.len() < shares.len() {
        return Err(
            "No duplicates among the privacy guardian identities nor share numbers are allowed."
                .to_owned(),
        );
    }

    let prf_key = reveal_prf_key(&shares);
    let prf_key_string = base16_encode_string(&prf_key);
    let json = json!({ "prfKey": prf_key_string });
    match write_json_to_file(&cmb.out, &json) {
        Ok(_) => println!("Wrote linking key to {}.", cmb.out.display()),
        Err(e) => {
            println!("Could not write to file because {}", e);
        }
    }
    Ok(())
}
