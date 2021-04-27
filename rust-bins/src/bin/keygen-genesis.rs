use clap::AppSettings;
use client_server_helpers::*;
use crypto_common::*;
use curve_arithmetic::Curve;
use elgamal::PublicKey;
use id::types::*;
use std::convert::TryFrom;

use pairing::bls12_381::Bls12;
use sha2::Sha512;
use std::path::PathBuf;
use structopt::StructOpt;

use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::*;
use pairing::bls12_381::{G1, G2};
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
    #[structopt(long = "out-pub", help = "File to output the public keys to.")]
    out_pub: PathBuf,
}

#[derive(StructOpt)]
#[structopt(
    about = "Tool for generating keys for genesis",
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

fn handle_generate_ar_keys(kgar: KeygenAr) -> Result<(), String> {
    let bytes_from_file = succeed_or_die!(fs::read(kgar.rand_input), e => "Could not read random input from provided file because {}");
    if bytes_from_file.len() < 64 {
        return Err("Provided randomness should be of size at least 64 bytes".to_string());
    }
    let mut bytes = bytes_from_file;
    bytes.extend_from_slice(b"concordium_generator");
    let generator = G1::hash_to_group(&bytes);
    bytes.extend_from_slice(b"concordium_ar_public_key");
    let ar_public_key = PublicKey {
        generator,
        key: G1::hash_to_group(&bytes),
    };
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
    let ver_public_ar_info = Versioned::new(VERSION_0, public_ar_info);
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
    let ip_public_key = generate_ps_pk(kgip.bound, &bytes_from_file);

    let ip_cdi_verify_key = hash_to_ed25519(&bytes_from_file).unwrap();
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
    let versioned_ip_info_public = Versioned::new(VERSION_0, ip_info);

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

/// This function uses the functions for hashing to G1 and G2 from
/// curve_arithmetic to generate random looking group elements to
/// create an instance of `ps_sig::public::PublicKey`.
pub fn generate_ps_pk(n: u32, bytes: &[u8]) -> ps_sig::public::PublicKey<Bls12> {
    let mut ys: Vec<G1> = Vec::with_capacity(n as usize);
    let mut y_tildas: Vec<G2> = Vec::with_capacity(n as usize);
    let mut g1_element = G1::hash_to_group(bytes);
    let mut g2_element = G2::hash_to_group(&to_bytes(&g1_element));
    for _ in 0..n {
        ys.push(g1_element);
        y_tildas.push(g2_element);
        g1_element = G1::hash_to_group(&to_bytes(&g2_element));
        g2_element = G2::hash_to_group(&to_bytes(&g1_element));
    }
    let x_tilda = G2::hash_to_group(&to_bytes(&g2_element));
    ps_sig::public::PublicKey {
        g: G1::one_point(),
        g_tilda: G2::one_point(),
        ys,
        y_tildas,
        x_tilda,
    }
}

/// Follows Appendix A of https://eprint.iacr.org/2017/099.pdf
pub fn hash_to_ed25519(msg: &[u8]) -> Option<ed25519_dalek::PublicKey> {
    let mut p_candidate_bytes = [0u8; 32];
    let mut h: Sha512 = Sha512::new();
    h.update(b"concordium_genesis_ed25519");
    h.update(msg);
    for ctr in 0..=u8::max_value() {
        let mut attempt_h = h.clone();
        attempt_h.update(ctr.to_le_bytes()); // ctr_string
        let hash = attempt_h.finalize();
        p_candidate_bytes.copy_from_slice(&hash[..32]);
        let p_candidate = CompressedEdwardsY(p_candidate_bytes);
        if let Some(ed_point) = p_candidate.decompress() {
            // Make sure the point is not of small order, i.e., it will
            // not be 0 after multiplying by cofactor.
            if !ed_point.is_small_order() {
                return Some(
                    ed25519_dalek::PublicKey::from_bytes(
                        &ed_point.mul_by_cofactor().compress().to_bytes(),
                    )
                    .unwrap(),
                );
            }
        }
    }
    // Each iteration of the loop succeeds with probability about a half,
    // so the return below will not happen.
    None
}
