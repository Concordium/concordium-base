use clap::AppSettings;
use client_server_helpers::*;
use crypto_common::*;
use curve_arithmetic::Curve;
use elgamal::{PublicKey, SecretKey};
use id::types::*;
use keygen_bls::keygen_bls;
use std::convert::TryFrom;

use hmac::{Hmac, Mac, NewMac};
use pairing::bls12_381::Bls12;
use sha2::Sha512;
use std::path::PathBuf;
use structopt::StructOpt;

use pairing::bls12_381::{Fr, G1, G2};
use std::fs;
#[derive(StructOpt)]
struct KeygenIp {
    #[structopt(long = "rand-input", help = "File with randomness.")]
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
    bound: u32,
    #[structopt(long = "out", help = "File to output the secret keys to.")]
    out: PathBuf,
    #[structopt(long = "out-pub", help = "File to output the public keys to.")]
    out_pub: PathBuf,
}

#[derive(StructOpt)]
struct KeygenAr {
    #[structopt(long = "rand-input", help = "File with randomness.")]
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
    version = "0.2"
)]
enum KeygenTool {
    #[structopt(name = "keygen-ip", about = "Generate identity provider keys")]
    KeygenIp(KeygenIp),
    #[structopt(name = "keygen-ar", about = "Generate anonymity revoker keys")]
    KeygenAr(KeygenAr),
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

fn output_possibly_encrypted<X: SerdeSerialize>(
    fname: &PathBuf,
    data: &X,
) -> Result<(), std::io::Error> {
    let pass = rpassword::read_password_from_tty(Some(
        "Enter password to encrypt credentials (leave empty for no encryption): ",
    ))?;
    if pass.is_empty() {
        println!("No password supplied, so output will not be encrypted.");
        write_json_to_file(fname, data)
    } else {
        let plaintext = serde_json::to_vec(data).expect("JSON serialization does not fail.");
        let encrypted =
            crypto_common::encryption::encrypt(&pass.into(), &plaintext, &mut rand::thread_rng());
        write_json_to_file(fname, &encrypted)
    }
}

fn handle_generate_ar_keys(kgar: KeygenAr) -> Result<(), String> {
    let bytes_from_file = succeed_or_die!(fs::read(kgar.rand_input), e => "Could not read random input from provided file because {}");
    if bytes_from_file.len() < 64 {
        return Err("Provided randomness should be of size at least 64 bytes".to_string());
    }
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
    let key_info = b"elgamal_keys".as_ref();
    let scalar = succeed_or_die!(keygen_bls(&bytes_from_file, &key_info), e => "Could not generate key because {}");
    let ar_secret_key = SecretKey {
        generator: ar_base,
        scalar,
    };
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
    match output_possibly_encrypted(&kgar.out, &ar_data) {
        Ok(_) => println!("Wrote private keys to {}.", kgar.out.to_string_lossy()),
        Err(e) => {
            return Err(format!(
                "Could not JSON write private keys to file because {}",
                e
            ));
        }
    }
    match write_json_to_file(&kgar.out_pub, &ver_public_ar_info) {
        Ok(_) => println!("Wrote public keys to {}.", kgar.out_pub.to_string_lossy()),
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
    let bytes_from_file = succeed_or_die!(fs::read(kgip.rand_input), e => "Could not read random input from provided file because {}");
    if bytes_from_file.len() < 64 {
        return Err("Provided randomness should be of size at least 64 bytes".to_string());
    }
    // let seed_32 = Sha256::digest(&bytes_from_file);
    let ip_secret_key = succeed_or_die!(generate_ps_sk(kgip.bound, &bytes_from_file), e => "Could not generate signature key for the Pointcheval-Sanders Signature Scheme because {}");
    let ip_public_key = ps_sig::public::PublicKey::from(&ip_secret_key);
    let ed_sk = succeed_or_die!(generate_ed_sk(&bytes_from_file), e => "Could not generate signature key for EdDSA because {}");
    let ed_pk = ed25519_dalek::PublicKey::from(&ed_sk);
    let ip_cdi_verify_key = ed_pk;
    let ip_cdi_secret_key = ed_sk;
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
    match output_possibly_encrypted(&kgip.out, &full_info) {
        Ok(_) => println!("Wrote private to {}.", kgip.out.to_string_lossy()),
        Err(e) => {
            return Err(format!(
                "Could not JSON private keys write to file because {}",
                e
            ));
        }
    }

    match write_json_to_file(&kgip.out_pub, &versioned_ip_info_public) {
        Ok(_) => println!("Wrote public keys to {}.", kgip.out_pub.to_string_lossy()),
        Err(e) => {
            return Err(format!(
                "Could not JSON write public keys to file because {}",
                e
            ));
        }
    }

    Ok(())
}

/// This function generates a secret key for the Pointcheval-Sanders Signature
/// Scheme using the `keygen_bls` function above.
/// It generates multiple scalars by calling keygen_bls with different values
/// `key_info`. The integer n determines the number of scalars generated and
/// must be less than 256.
pub fn generate_ps_sk(
    n: u32,
    ikm: &[u8],
) -> Result<ps_sig::secret::SecretKey<Bls12>, hkdf::InvalidLength> {
    let mut ys: Vec<Fr> = Vec::with_capacity(n as usize);
    for i in 0..n {
        let key = keygen_bls(&ikm, &i.to_be_bytes()[..])?;
        ys.push(key);
    }
    let key = keygen_bls(&ikm, &[])?;
    Ok(ps_sig::secret::SecretKey {
        g: G1::one_point(),
        g_tilda: G2::one_point(),
        ys,
        x: key,
    })
}

/// This function is an implementation of the procedure described in https://github.com/satoshilabs/slips/blob/master/slip-0010.md
/// It produces 32 random bytes given a seed, which is exactly a secret key for
/// the ed25519_dalek.
pub fn keygen_ed(seed: &[u8]) -> [u8; 32] {
    let mut mac =
        Hmac::<Sha512>::new_varkey(b"ed25519 seed").expect("HMAC can take key of any size");
    mac.update(&seed);
    let result = mac.finalize();
    let code_bytes = result.into_bytes();
    let mut il = [0u8; 32];
    il.clone_from_slice(&code_bytes[0..32]);
    il
}

/// It generates a ed25519_dalek secret key given a seed, using the `keygen_ed`
/// above.
pub fn generate_ed_sk(
    seed: &[u8],
) -> Result<ed25519_dalek::SecretKey, ed25519_dalek::SignatureError> {
    let sk = ed25519_dalek::SecretKey::from_bytes(&keygen_ed(&seed))?;
    Ok(sk)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Checking with the two test vectors mentioned in https://github.com/satoshilabs/slips/blob/master/slip-0010.md
    #[test]
    pub fn testvector_ed() {
        let seed1 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        assert_eq!(
            Ok(keygen_ed(&seed1).to_vec()),
            hex::decode("2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7")
        );
        let seed2 = hex::decode("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542").unwrap();
        assert_eq!(
            Ok(keygen_ed(&seed2).to_vec()),
            hex::decode("171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012")
        );
    }
}
