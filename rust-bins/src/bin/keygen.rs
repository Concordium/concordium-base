use clap::AppSettings;
use client_server_helpers::*;
use crypto_common::*;
use crypto_common_derive::*;
use curve_arithmetic::Curve;
use dodis_yampolskiy_prf::secret as prf;
use elgamal::{PublicKey, SecretKey};
use id::types::*;
use std::convert::TryFrom;

use pairing::bls12_381::Bls12;
use rand::{rngs::StdRng, thread_rng, RngCore, SeedableRng};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(StructOpt)]
struct KeygenIp {
    #[structopt(long = "rand-input", help = "File with additional randomness.")]
    rand_input: PathBuf,
    #[structopt(
        long = "ip-identity",
        help = "The integer identifying the identity provider"
    )]
    ip_identity: u32,
    #[structopt(long = "name", help = "Name of the identity provider")]
    name: String,
    #[structopt(long = "url", help = "url to identity provider")]
    url: String,
    #[structopt(long = "description", help = "Description of identity provider")]
    description: String,
    #[structopt(
        long = "bound",
        help = "Upper bound on messages signed by the IP",
        default_value = "30"
    )]
    bound: usize,
    #[structopt(long = "out", help = "File to output the secret keys to.")]
    out: PathBuf,
    #[structopt(long = "out-pub", help = "File to output the public keys to.")]
    out_pub: PathBuf,
}

#[derive(StructOpt)]
struct KeygenAr {
    #[structopt(long = "rand-input", help = "File with additional randomness.")]
    rand_input: PathBuf,
    #[structopt(
        long = "ar-identity",
        help = "The integer identifying the anonymity revoker"
    )]
    ar_identity: u32,
    #[structopt(long = "name", help = "Name of the anonymity revoker")]
    name: String,
    #[structopt(long = "url", help = "url to anonymity revoker")]
    url: String,
    #[structopt(long = "description", help = "Description of anonymity revoker")]
    description: String,
    #[structopt(
        long = "global",
        help = "File with global parameters.",
        default_value = "database/global.json"
    )]
    global: PathBuf,
    #[structopt(long = "out", help = "File to output the secret keys to.")]
    out: PathBuf,
    #[structopt(long = "out-pub", help = "File to output the public keys to.")]
    out_pub: PathBuf,
}

#[derive(StructOpt)]
#[structopt(
    about = "Tool for generating keys",
    author = "Concordium",
    version = "0.36787944117"
)]
enum KeygenTool {
    #[structopt(name = "keygen-ip", about = "Generate identity provider keys")]
    KeygenIp(KeygenIp),
    #[structopt(name = "keygen-ar", about = "Generate anonymity revoker keys")]
    KeygenAr(KeygenAr),
}

#[derive(Debug, Serialize, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(serialize = "C: Curve", deserialize = "C: Curve"))]
struct PrfWrapper<C: Curve> {
    #[serde(rename = "prfKey")]
    pub prf_key: prf::SecretKey<C>,
}

fn main() {
    let app = KeygenTool::clap()
        .setting(AppSettings::ArgRequiredElseHelp)
        .global_setting(AppSettings::ColoredHelp);
    let matches = app.get_matches();
    let kg = KeygenTool::from_clap(&matches);
    use KeygenTool::*;
    match kg {
        KeygenIp(kgip) => {
            if let Err(e) = handle_generate_ip_keys(kgip) {
                eprintln!("{}", e)
            }
        }
        KeygenAr(kgar) => {
            if let Err(e) = handle_generate_ar_keys(kgar) {
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

fn handle_generate_ar_keys(kgar: KeygenAr) -> Result<(), String> {
    let mut csprng = thread_rng();
    let bytes_from_file = succeed_or_die!(read_bytes_from_file(kgar.rand_input), e => "Could not read random input from provided file because {}");
    let mut bytes: Vec<u8> = vec![0; bytes_from_file.len()];
    csprng.fill_bytes(&mut bytes);
    let seed_32 = Sha256::new()
        .chain(&bytes_from_file)
        .chain(&bytes)
        .finalize();
    let mut rng = StdRng::from_seed(seed_32.into());
    let global_ctx = {
        if let Some(gc) = read_global_context(kgar.global) {
            gc
        } else {
            return Err(
                "Cannot read global context information database. Terminating.".to_string(),
            );
        }
    };
    let ar_base = global_ctx.on_chain_commitment_key.g;
    let ar_secret_key = SecretKey::generate(&ar_base, &mut rng);
    let ar_public_key = PublicKey::from(&ar_secret_key);
    let id = kgar.ar_identity;
    let ar_identity = ArIdentity::try_from(id).unwrap();
    let name = kgar.name;
    let url = kgar.url;
    let description = kgar.description;
    let public_ar_info = ArInfo {
        ar_identity,
        ar_description: Description {
            name,
            url,
            description,
        },
        ar_public_key,
    };
    let ar_data = ArData {
        public_ar_info,
        ar_secret_key,
    };
    let ver_public_ar_info = Versioned::new(VERSION_0, ar_data.public_ar_info.clone());
    match write_json_to_file(&kgar.out, &ar_data) {
        Ok(_) => println!("Wrote to {}.", kgar.out.to_string_lossy()),
        Err(e) => {
            return Err(format!(
                "Could not JSON write private keys to file because {}",
                e
            ));
        }
    }
    match write_json_to_file(&kgar.out_pub, &ver_public_ar_info) {
        Ok(_) => println!("Wrote to {}.", kgar.out_pub.to_string_lossy()),
        Err(e) => {
            return Err(format!(
                "Could not JSON write public keys to file because {}",
                e
            ));
        }
    }
    Ok(())
}

fn handle_generate_ip_keys(kgip: KeygenIp) -> Result<(), String> {
    let mut csprng = thread_rng();
    let bytes_from_file = succeed_or_die!(read_bytes_from_file(kgip.rand_input), e => "Could not read random input from provided file because {}");
    let mut bytes: Vec<u8> = vec![0; bytes_from_file.len()];
    csprng.fill_bytes(&mut bytes);
    let seed_32 = Sha256::new()
        .chain(&bytes_from_file)
        .chain(&bytes)
        .finalize();
    let mut rng = StdRng::from_seed(seed_32.into());
    let ip_secret_key = ps_sig::secret::SecretKey::<Bls12>::generate(kgip.bound, &mut rng);
    let ip_public_key = ps_sig::public::PublicKey::from(&ip_secret_key);
    let keypair = ed25519_dalek::Keypair::generate(&mut rng);
    let ip_cdi_verify_key = keypair.public;
    let ip_cdi_secret_key = keypair.secret;
    let id = kgip.ip_identity;
    let name = kgip.name;
    let url = kgip.url;
    let description = kgip.description;
    let ip_id = IpIdentity(id);
    let ip_info = IpInfo {
        ip_identity: ip_id,
        ip_description: Description {
            name,
            url,
            description,
        },
        ip_verify_key: ip_public_key,
        ip_cdi_verify_key,
    };
    let full_info = IpData {
        ip_secret_key,
        public_ip_info: ip_info,
        ip_cdi_secret_key,
    };
    let versioned_ip_info_public = Versioned::new(VERSION_0, full_info.public_ip_info.clone());
    match write_json_to_file(&kgip.out, &full_info) {
        Ok(_) => println!("Wrote to {}.", kgip.out.to_string_lossy()),
        Err(e) => {
            return Err(format!(
                "Could not JSON private keys write to file because {}",
                e
            ));
        }
    }

    match write_json_to_file(&kgip.out_pub, &versioned_ip_info_public) {
        Ok(_) => println!("Wrote to {}.", kgip.out_pub.to_string_lossy()),
        Err(e) => {
            return Err(format!(
                "Could not JSON write public keys to file because {}",
                e
            ));
        }
    }

    Ok(())
}
