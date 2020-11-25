use clap::AppSettings;
use client_server_helpers::*;
use crypto_common::*;
use crypto_common_derive::*;
use curve_arithmetic::Curve;
use dodis_yampolskiy_prf::secret as prf;
use elgamal::{PublicKey, SecretKey};
use id::types::*;
use std::convert::TryFrom;

use hmac::{Hmac, Mac, NewMac};
use pairing::bls12_381::Bls12;
use sha2::{Digest, Sha256, Sha512};
use std::path::PathBuf;
use structopt::StructOpt;

use ff::{Field, PrimeField};
use hkdf::Hkdf;
use pairing::bls12_381::{Fr, FrRepr, G1, G2};
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
    let bytes_from_file = succeed_or_die!(read_bytes_from_file(kgar.rand_input), e => "Could not read random input from provided file because {}");
    let seed_32 = Sha256::new().chain(&bytes_from_file).finalize();
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
    let scalar =
        succeed_or_die!(keygen_bls(&seed_32, &key_info), e => "Could not generate key because {}");
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
    let bytes_from_file = succeed_or_die!(read_bytes_from_file(kgip.rand_input), e => "Could not read random input from provided file because {}");
    let seed_32 = Sha256::new().chain(&bytes_from_file).finalize();
    let ip_secret_key = succeed_or_die!(generate_ps_sk(kgip.bound, &seed_32), e => "Could not generate signature key for the Pointcheval-Sanders Signature Scheme because {}");
    let ip_public_key = ps_sig::public::PublicKey::from(&ip_secret_key);
    let ed_sk = succeed_or_die!(generate_ed_sk(&seed_32), e => "Could not generate signature key for EdDSA because {}");
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

/// This function is an implementation of the procedure described in https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-2.3
/// It computes a random scalar in Fr given a seed (the argument `ikm`).
pub fn keygen_bls(ikm: &[u8], key_info: &[u8]) -> Result<Fr, hkdf::InvalidLength> {
    let mut ikm = ikm.to_vec();
    ikm.push(0);
    let l = 48; // = 48 for G1; r is
                // 52435875175126190479447740508185965837690552500527637822603658699938581184513
    let mut l_bytes = key_info.to_vec();
    l_bytes.push(l);
    l_bytes.push(0);
    let salt = b"BLS-SIG-KEYGEN-SALT-";
    let mut sk = Fr::zero();
    // shift with
    // 452312848583266388373324160190187140051835877600158453279131187530910662656 =
    // 2^31
    let shift = Fr::from_repr(FrRepr([0, 0, 0, 72057594037927936])).unwrap();
    let mut salt = Sha256::digest(&salt[..]);
    while sk.is_zero() {
        let (_, h) = Hkdf::<Sha256>::extract(Some(&salt), &ikm);
        let mut okm = vec![0u8; l as usize];
        h.expand(&l_bytes, &mut okm)?;
        let mut y1_vec = [0; 32];
        let mut y2_vec = [0; 32];
        let slice_y1 = &mut y1_vec[0..31];
        slice_y1.clone_from_slice(&okm[0..31]);
        let slice_y2 = &mut y2_vec[0..okm.len() - slice_y1.len()];
        slice_y2.clone_from_slice(&okm[31..]);
        let y1 = G1::scalar_from_bytes(&y1_vec);
        let mut y2 = G1::scalar_from_bytes(&y2_vec);
        y2.mul_assign(&shift);
        sk = y1;
        sk.add_assign(&y2);
        salt = Sha256::digest(&salt);
    }
    Ok(sk)
}

/// This function generates a secret key for the Pointcheval-Sanders Signature
/// Scheme using the `keygen_bls` function above.
pub fn generate_ps_sk(
    n: usize,
    ikm: &[u8],
) -> Result<ps_sig::secret::SecretKey<Bls12>, hkdf::InvalidLength> {
    let mut ys: Vec<Fr> = Vec::with_capacity(n);
    for i in 0..n {
        let key = keygen_bls(&ikm, &[i as u8])?;
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
