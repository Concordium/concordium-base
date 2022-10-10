use clap::AppSettings;
use client_server_helpers::*;
use crossterm::{
    execute,
    terminal::{Clear, ClearType},
};
use crypto_common::*;
use curve_arithmetic::Curve;
use dialoguer::{Confirm, Input};
use elgamal::{PublicKey, SecretKey};
use hmac::{Hmac, Mac};
use id::types::*;
use keygen_bls::{keygen_bls, keygen_bls_deprecated};
use pairing::bls12_381::{Bls12, Fr, G1, G2};
use sha2::Sha512;
use std::{
    collections::HashMap,
    fs::{self, File},
    io::Write,
    path::PathBuf,
    str::FromStr,
};
use structopt::StructOpt;

const BIP39_ENGLISH: &str = include_str!("data/BIP39English.txt");

/// List of BIP39 words. There is a test that checks that this list has correct
/// length, so there is no need to check when using this in the tool.
fn bip39_words() -> impl Iterator<Item = &'static str> { BIP39_ENGLISH.split_whitespace() }

/// Inverse mapping to the implicit mapping in bip39_words. Maps word to its
/// index in the list. This allows to quickly test membership and convert words
/// to their index.
fn bip39_map() -> HashMap<&'static str, usize> { bip39_words().zip(0..).collect() }

#[derive(StructOpt)]
struct KeygenIp {
    #[structopt(long = "rand-input", help = "File with randomness.")]
    rand_input:  PathBuf,
    #[structopt(
        long = "ip-identity",
        help = "The integer identifying the identity provider"
    )]
    ip_identity: u32,
    #[structopt(long = "name", help = "Name of the identity provider")]
    name:        String,
    #[structopt(long = "url", help = "url to identity provider")]
    url:         String,
    #[structopt(long = "description", help = "Description of identity provider")]
    description: String,
    #[structopt(
        long = "bound",
        help = "Upper bound on messages signed by the IP",
        default_value = "30"
    )]
    bound:       u32,
    #[structopt(long = "out", help = "File to output the secret keys to.")]
    out:         PathBuf,
    #[structopt(long = "out-pub", help = "File to output the public keys to.")]
    out_pub:     PathBuf,
    #[structopt(
        long = "v1",
        help = "Use deprecated version 1 of BLS keygen. If keys were generated with version 1, \
                this flag must be used during recovery."
    )]
    v1:          bool,
}

#[derive(StructOpt)]
struct KeygenAr {
    #[structopt(
        long = "recover-from-phrase",
        help = "Recover keys from backup phrase. Otherwise, fresh keys are generated."
    )]
    recover:                bool,
    #[structopt(
        long = "ar-identity",
        help = "The integer identifying the anonymity revoker"
    )]
    ar_identity:            Option<ArIdentity>,
    #[structopt(long = "name", help = "Name of the anonymity revoker")]
    name:                   Option<String>,
    #[structopt(long = "url", help = "url to anonymity revoker")]
    url:                    Option<String>,
    #[structopt(long = "description", help = "Description of anonymity revoker")]
    description:            Option<String>,
    #[structopt(long = "global", help = "File with cryptographic parameters.")]
    global:                 Option<PathBuf>,
    #[structopt(long = "out", help = "File to output the secret keys to.")]
    out:                    Option<PathBuf>,
    #[structopt(long = "out-pub", help = "File to output the public keys to.")]
    out_pub:                Option<PathBuf>,
    #[structopt(
        long = "in-len",
        help = "Number of words read from user. Must be in {12, 15, 18, 21, 24} to constitute a \
                valid BIP39 sentences. If --no-verification is used, arbitrary values are allowed.",
        default_value = "24"
    )]
    in_len:                 u8,
    #[structopt(
        long = "no-verification",
        help = "Do not verify the validity of the input. Otherwise the input is verified to be a \
                valid BIP39 sentence."
    )]
    no_verification:        bool,
    #[structopt(
        long = "no-confirmation",
        help = "Do not ask user to re-enter generated recovery phrase."
    )]
    no_confirmation:        bool,
    #[structopt(
        long = "only-system-randomness",
        help = "Do not ask for a list of words from the user. Generate keys only using the system \
                randomness."
    )]
    only_system_randomness: bool,
    #[structopt(
        long = "v1",
        help = "Use deprecated version 1 of BLS keygen. If keys were generated with version 1, \
                this flag must be used during recovery."
    )]
    v1:                     bool,
}

#[derive(Debug)]
enum Level {
    Root,
    One,
    Two,
}

impl FromStr for Level {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "root" => Ok(Level::Root),
            "1" => Ok(Level::One),
            "one" => Ok(Level::One),
            "2" => Ok(Level::Two),
            "two" => Ok(Level::Two),
            _ => anyhow::bail!("Unknown governance key level '{}'", s),
        }
    }
}

#[derive(StructOpt)]
struct KeygenGovernance {
    #[structopt(long = "level", help = "Governance key level.", default_value = "2")]
    level:   Level,
    #[structopt(long = "out", help = "File to output the secret keys to.")]
    out:     PathBuf,
    #[structopt(long = "out-pub", help = "File to output the public keys to.")]
    out_pub: PathBuf,
}

#[derive(StructOpt)]
struct GenRand {
    #[structopt(
        long = "in",
        help = "File containing input words. If not provided, words are read from stdin."
    )]
    input_path: Option<PathBuf>,

    #[structopt(long = "out", help = "File to output the randomness to.")]
    output_path: PathBuf,

    #[structopt(
        long = "in-len",
        help = "Number of words read from user. Must be in {12, 15, 18, 21, 24} to constitute a \
                valid BIP39 sentences. If --no-verification is used, arbitrary values are \
                allowed. Value is ignored if input file is provided.",
        default_value = "24"
    )]
    in_len: u8,

    #[structopt(
        long = "no-verification",
        help = "Do not verify the validity of the input. Otherwise the input is verified to be a \
                valid BIP39 sentence."
    )]
    no_verification: bool,
}

#[derive(StructOpt)]
#[structopt(
    about = "Tool for generating keys",
    name = "keygen",
    author = "Concordium",
    version = "2.1"
)]
enum KeygenTool {
    #[structopt(
        name = "keygen-ip",
        about = "Generate identity provider keys.",
        version = "2.0"
    )]
    KeygenIp(KeygenIp),
    #[structopt(
        name = "keygen-ar",
        about = "Generate anonymity revoker keys.",
        version = "2.0"
    )]
    KeygenAr(KeygenAr),
    #[structopt(
        name = "gen-rand",
        about = "Generate randomness file.",
        version = "2.0"
    )]
    GenRand(GenRand),
    #[structopt(
        name = "keygen-governance",
        about = "Generate update keys.",
        version = "1.0"
    )]
    KeygenUpdate(KeygenGovernance),
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
        GenRand(grand) => {
            if let Err(e) = handle_generate_randomness(grand) {
                eprintln!("{}", e)
            }
        }
        KeygenUpdate(kgup) => {
            if let Err(e) = handle_generate_update_keys(kgup) {
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

/// Read vector of words from file.
pub fn read_words_from_file(
    path: PathBuf,
    verify_bip: bool,
    bip39_map: &HashMap<&str, usize>,
) -> Result<Vec<String>, String> {
    let word_string = succeed_or_die!(
        fs::read_to_string(path),
        e => "Could not read input from provided file because {}"
    );

    let word_list: Vec<String> = word_string.split_whitespace().map(str::to_owned).collect();

    // verify whether input_words is a valid BIP39 sentence if check is enabled
    if verify_bip && !verify_bip39(&word_list, bip39_map) {
        return Err("The input does not constitute a valid BIP39 sentence.".to_string());
    }

    Ok(word_list)
}

fn handle_generate_update_keys(kgup: KeygenGovernance) -> Result<(), String> {
    let mut csprng = rand::thread_rng();
    let keypair = crypto_common::types::KeyPair::generate(&mut csprng);
    let public_bytes = keypair.public.to_bytes();
    let sig = keypair.sign(&public_bytes);
    let level_str = match kgup.level {
        Level::Root => "root",
        Level::One => "level1",
        Level::Two => "level2",
    };
    let public_data = serde_json::json!({
        "key": {
            "verifyKey": base16_encode_string(&keypair.public),
            "scheme": "Ed25519",
        },
        "signature": sig,
        "type": level_str,
    });
    let secret_data = serde_json::json!({
        "keyPair": keypair,
        "type": level_str,
    });
    match write_json_to_file(&kgup.out_pub, &public_data) {
        Ok(_) => println!("Wrote public keys to {}.", kgup.out_pub.display()),
        Err(e) => {
            return Err(format!(
                "Could not JSON write public keys to file because {}",
                e
            ));
        }
    }
    match output_possibly_encrypted(&kgup.out, &secret_data) {
        Ok(_) => println!("Wrote private keys to {}.", kgup.out.display()),
        Err(e) => {
            return Err(format!(
                "Could not JSON write private keys to file because {}",
                e
            ));
        }
    }
    Ok(())
}

fn handle_generate_ar_keys(kgar: KeygenAr) -> Result<(), String> {
    let bip39_vec = bip39_words().collect::<Vec<_>>();
    let bip39_map = bip39_map();

    let words_str = if kgar.recover {
        println!("Please enter recovery phrase below.");
        let input_words = read_words_from_terminal(kgar.in_len, !kgar.no_verification, &bip39_map)?;

        input_words.join(" ")
    } else {
        let input_words = if kgar.only_system_randomness {
            Vec::new()
        } else {
            println!(
                "Please generate a seed phrase, e.g., using a hardware wallet, and input the \
                 words below."
            );
            read_words_from_terminal(kgar.in_len, !kgar.no_verification, &bip39_map)?
        };

        // rerandomize input words using system randomness
        let randomized_words = rerandomize_bip39(&input_words, &bip39_vec)?;

        // print randomized words and ask user to re-enter
        // clear screen
        execute!(std::io::stdout(), Clear(ClearType::All))
            .map_err(|_| "Could not clear screen.".to_owned())?;
        println!("Please write down your recovery phrase on paper.");
        for (i, word) in randomized_words.iter().enumerate() {
            println!("Word {}: {}", i + 1, word);
        }

        while !Confirm::new()
            .with_prompt("Have you written down all words?")
            .interact()
            .unwrap_or(false)
        {
            println!("Please write down all words.");
        }

        if !kgar.no_confirmation {
            let mut first = true;
            loop {
                // clear screen
                execute!(std::io::stdout(), Clear(ClearType::All))
                    .map_err(|_| "Could not clear screen.".to_owned())?;
                if first {
                    println!("Please enter recovery phrase again to confirm.");
                } else {
                    println!("Recovery phrases do not match. Try again.")
                }

                let confirmation_words = read_words_from_terminal(kgar.in_len, true, &bip39_map)?;

                if confirmation_words == randomized_words {
                    break;
                }
                first = false;
            }
        }

        randomized_words.join(" ")
    };

    // use input words separated by spaces as randomness
    let random_bytes = words_str.as_bytes();

    let global_file = kgar.global.unwrap_or_else(|| {
        // read a file from the user, checking that the file they input actually exists.
        let validator = |candidate: &String| -> Result<(), String> {
            if std::path::Path::new(candidate).exists() {
                Ok(())
            } else {
                Err(format!("File {} does not exist. Try again.", candidate))
            }
        };

        let mut input = Input::new();
        input.with_prompt("Enter the path to the cryptographic parameters file");
        // offer a default option if the file exists.
        if std::path::Path::new("cryptographic-parameters.json").exists() {
            input.default("cryptographic-parameters.json".to_string());
        };
        input.validate_with(validator);
        loop {
            match input.interact() {
                Ok(x) => return PathBuf::from(x),
                Err(e) => println!("{}", e),
            }
        }
    });

    let global_ctx = {
        if let Some(gc) = read_global_context(global_file) {
            gc
        } else {
            return Err("Cannot read cryptographic parameters. Terminating.".to_string());
        }
    };
    let ar_base = global_ctx.on_chain_commitment_key.g;
    let key_info = b"elgamal_keys".as_ref();
    let scalar = if kgar.v1 {
        println!("Using deprecated BLS keygen.");
        succeed_or_die!(keygen_bls_deprecated(random_bytes, key_info), e => "Could not generate key because {}")
    } else {
        succeed_or_die!(keygen_bls(random_bytes, key_info), e => "Could not generate key because {}")
    };
    let ar_secret_key = SecretKey {
        generator: ar_base,
        scalar,
    };
    let ar_public_key = PublicKey::from(&ar_secret_key);
    let ar_identity = kgar.ar_identity.unwrap_or_else(|| {
        Input::new()
            .with_prompt("Enter AR identity")
            .interact()
            .expect("AR identity not provided")
    });
    let name = kgar.name.unwrap_or_else(|| {
        Input::new()
            .with_prompt("Enter the name of the AR")
            .interact()
            .expect("AR name not provided.")
    });
    let url = kgar.url.unwrap_or_else(|| {
        Input::new()
            .with_prompt("Enter URL of the AR")
            .interact()
            .expect("AR URL not provided.")
    });
    let description = kgar.description.unwrap_or_else(|| {
        Input::new()
            .with_prompt("Enter description of the AR")
            .interact()
            .expect("AR description not provided.")
    });
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
    let out_file = kgar.out.unwrap_or_else(|| {
        PathBuf::from(
            Input::new()
                .with_prompt("Output file name")
                .default(format!("ar-data-{}.json", ar_identity))
                .interact()
                .expect("Output file not provided."),
        )
    });
    let out_pub_file = kgar.out_pub.unwrap_or_else(|| {
        PathBuf::from(
            Input::new()
                .with_prompt("Output file for public data")
                .default(format!("ar-info-{}.pub.json", ar_identity))
                .interact()
                .expect("Output file not provided."),
        )
    });
    match output_possibly_encrypted(&out_file, &ar_data) {
        Ok(_) => println!("Wrote private keys to {}.", out_file.display()),
        Err(e) => {
            return Err(format!(
                "Could not JSON write private keys to file because {}",
                e
            ));
        }
    }
    match write_json_to_file(&out_pub_file, &ver_public_ar_info) {
        Ok(_) => println!("Wrote public keys to {}.", out_pub_file.display()),
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
    let ip_secret_key = succeed_or_die!(generate_ps_sk(kgip.bound, &bytes_from_file, kgip.v1), e => "Could not generate signature key for the Pointcheval-Sanders Signature Scheme because {}");
    if kgip.v1 {
        println!("Using deprecated BLS keygen.");
    }
    let ip_public_key = ps_sig::PublicKey::from(&ip_secret_key);
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
        Ok(_) => println!("Wrote private to {}.", kgip.out.display()),
        Err(e) => {
            return Err(format!(
                "Could not JSON write private keys to file because {}",
                e
            ));
        }
    }

    match write_json_to_file(&kgip.out_pub, &versioned_ip_info_public) {
        Ok(_) => println!("Wrote public keys to {}.", kgip.out_pub.display()),
        Err(e) => {
            return Err(format!(
                "Could not JSON write public keys to file because {}",
                e
            ));
        }
    }

    Ok(())
}

fn handle_generate_randomness(grand: GenRand) -> Result<(), String> {
    // Read word list and make sure it contains 2048 words.
    let bip39_vec = bip39_words().collect::<Vec<_>>();

    let bip39_map = bip39_map();

    // get vector of input words from file or stdin
    let input_words: Vec<_> = match grand.input_path {
        // if input_path is provided, read file
        Some(path) => read_words_from_file(path, !grand.no_verification, &bip39_map)?,
        // if input_path is not provided, read words from stdin
        None => {
            println!(
                "Please generate a seed phrase using a hardware wallet and input the words below."
            );
            read_words_from_terminal(grand.in_len, !grand.no_verification, &bip39_map)?
        }
    };

    // rerandomize input words and write result to file
    let output_words = rerandomize_bip39(&input_words, &bip39_vec)?;
    let mut file = succeed_or_die!(
        File::create(&grand.output_path),
        e => "Could not write output because {}"
    );
    for s in output_words {
        succeed_or_die!(
        writeln!(file, "{}", s),
        e => "Could not write output because {}"
            );
    }

    println!(
        "Random words have successfully been written to file {}.",
        grand.output_path.display()
    );

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
    legacy: bool,
) -> Result<ps_sig::SecretKey<Bls12>, hkdf::InvalidLength> {
    let mut ys: Vec<Fr> = Vec::with_capacity(n as usize);
    let key = if legacy {
        for i in 0..n {
            let key = keygen_bls_deprecated(ikm, &i.to_be_bytes()[..])?;
            ys.push(key);
        }
        keygen_bls_deprecated(ikm, &[])?
    } else {
        for i in 0..n {
            let key = keygen_bls(ikm, &i.to_be_bytes()[..])?;
            ys.push(key);
        }
        keygen_bls(ikm, &[])?
    };
    Ok(ps_sig::SecretKey {
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
        Hmac::<Sha512>::new_from_slice(b"ed25519 seed").expect("HMAC can take key of any size");
    mac.update(seed);
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
    let sk = ed25519_dalek::SecretKey::from_bytes(&keygen_ed(seed))?;
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

    /// Test correct generation of BIP39 sentences.
    /// Values are taken from https://github.com/trezor/python-mnemonic/blob/master/vectors.json
    #[test]
    pub fn test_bip39_generation() {
        let bip39_vec: Vec<_> = bip39_words().collect();
        assert_eq!(bip39_vec.len(), 2048);

        assert_eq!(
            bytes_to_bip39(
                &hex::decode("00000000000000000000000000000000").unwrap(),
                &bip39_vec
            )
            .unwrap()
            .join(" "),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon about",
        );
        assert_eq!(
            bytes_to_bip39(
                &hex::decode("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f").unwrap(),
                &bip39_vec
            )
            .unwrap()
            .join(" "),
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
        );
        assert_eq!(
            bytes_to_bip39(
                &hex::decode("000000000000000000000000000000000000000000000000").unwrap(),
                &bip39_vec
            )
            .unwrap()
            .join(" "),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon abandon agent",
        );
        assert_eq!(
            bytes_to_bip39(
                &hex::decode("0000000000000000000000000000000000000000000000000000000000000000")
                    .unwrap(),
                &bip39_vec
            )
            .unwrap()
            .join(" "),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon art",
        );
        assert_eq!(
            bytes_to_bip39(
                &hex::decode("f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f")
                    .unwrap(),
                &bip39_vec
            )
            .unwrap()
            .join(" "),
            "void come effort suffer camp survey warrior heavy shoot primary clutch crush open \
             amazing screen patrol group space point ten exist slush involve unfold",
        );
    }

    /// Test BIP39 verification.
    #[test]
    pub fn test_bip39_verification() {
        let bip39_vec: Vec<_> = bip39_words().collect();
        assert_eq!(bip39_vec.len(), 2048);
        let mut bip39_map = HashMap::new();
        for (i, word) in bip39_vec.iter().enumerate() {
            bip39_map.insert(*word, i);
        }

        let valid_list = vec![
            "abandon".to_string(),
            "abandon".to_string(),
            "abandon".to_string(),
            "abandon".to_string(),
            "abandon".to_string(),
            "abandon".to_string(),
            "abandon".to_string(),
            "abandon".to_string(),
            "abandon".to_string(),
            "abandon".to_string(),
            "abandon".to_string(),
            "abandon".to_string(),
            "abandon".to_string(),
            "abandon".to_string(),
            "abandon".to_string(),
            "abandon".to_string(),
            "abandon".to_string(),
            "abandon".to_string(),
            "abandon".to_string(),
            "abandon".to_string(),
            "abandon".to_string(),
            "abandon".to_string(),
            "abandon".to_string(),
            "art".to_string(),
        ];
        let invalid_list = vec![
            "abandon".to_string(),
            "abandon".to_string(),
            "abandon".to_string(),
            "abandon".to_string(),
            "abandon".to_string(),
            "abandon".to_string(),
            "abandon".to_string(),
            "abandon".to_string(),
            "abandon".to_string(),
            "abandon".to_string(),
            "abandon".to_string(),
            "abandon".to_string(),
            "abandon".to_string(),
            "abandon".to_string(),
            "abandon".to_string(),
            "abandon".to_string(),
            "abandon".to_string(),
            "abandon".to_string(),
            "abandon".to_string(),
            "abandon".to_string(),
            "abandon".to_string(),
            "abandon".to_string(),
            "abandon".to_string(),
            "abandon".to_string(),
        ];

        assert!(verify_bip39(&valid_list, &bip39_map));
        assert!(!verify_bip39(&invalid_list, &bip39_map));
    }
}
