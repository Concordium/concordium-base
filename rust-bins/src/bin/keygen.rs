use clap::AppSettings;
use client_server_helpers::*;
use crypto_common::*;
use curve_arithmetic::Curve;
use elgamal::{PublicKey, SecretKey};
use id::types::*;
use keygen_bls::keygen_bls;
use std::convert::TryFrom;

use hkdf::HkdfExtract;
use hmac::{Hmac, Mac, NewMac};
use pairing::bls12_381::Bls12;
use sha2::{Digest, Sha256, Sha512};
use std::path::PathBuf;
use structopt::StructOpt;

use bitvec::prelude::*;
use pairing::bls12_381::{Fr, G1, G2};
use rand::Rng;
use std::{
    collections::HashMap,
    fs::{self, File},
    io::{self, prelude::*, Write},
};

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
    #[structopt(
        long = "recover-from-phrase",
        help = "Recover keys from backup phrase. Otherwise, fresh keys are generated."
    )]
    recover: bool,
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
    #[structopt(
        long = "in-len",
        help = "Number of words read from user. Must be in {12, 15, 18, 21, 24} to constitute a \
                valid BIP39 sentences. If --no-verification is used, arbitrary values are allowed.",
        default_value = "24"
    )]
    in_len: u8,
    #[structopt(
        long = "no-verification",
        help = "Do not verify the validity of the input. Otherwise the input is verified to be a \
                valid BIP39 sentence."
    )]
    no_verification: bool,
    #[structopt(
        long = "no-confirmation",
        help = "Do not ask user to re-enter generated recovery phrase."
    )]
    no_confirmation: bool,
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
    author = "Concordium",
    version = "0.2"
)]
enum KeygenTool {
    #[structopt(name = "keygen-ip", about = "Generate identity provider keys")]
    KeygenIp(KeygenIp),
    #[structopt(name = "keygen-ar", about = "Generate anonymity revoker keys")]
    KeygenAr(KeygenAr),
    #[structopt(name = "gen-rand", about = "Generate randomness file")]
    GenRand(GenRand),
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
    let pass = ask_for_password_confirm(
        "Enter password to encrypt credentials (leave empty for no encryption): ",
        true,
    )?;
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
    // Read word list and make sure it contains 2048 words.
    let bip39_vec: Vec<_> = include_str!("data/BIP39English.txt")
        .split_whitespace()
        .collect();
    if bip39_vec.len() != 2048 {
        return Err("The BIP39 word list must contain 2048 words.".to_string());
    }

    // Create hashmap mapping word to its index in the list.
    // This allows to quickly test membership and convert words to their index
    let mut bip39_map = HashMap::with_capacity(bip39_vec.len());
    for (i, word) in bip39_vec.iter().enumerate() {
        bip39_map.insert(*word, i);
    }

    let words_str = if kgar.recover {
        println!("Please enter recovery phrase below.");
        let input_words = read_words_from_terminal(kgar.in_len, !kgar.no_verification, &bip39_map)?;

        input_words.join(" ")
    } else {
        println!(
            "Please generate a seed phrase, e.g., using a hardware wallet, and input the words \
             below."
        );
        let input_words = read_words_from_terminal(kgar.in_len, !kgar.no_verification, &bip39_map)?;

        // rerandomize input words using system randomness
        let randomized_words = rerandomize_bip39(&input_words, &bip39_vec)?;

        // print randomized words and ask user to re-enter
        // clear screen
        print!("\x1B[2J");
        println!("Please write down your recovery phrase on paper.");
        for (i, word) in randomized_words.iter().enumerate() {
            println!("Word {}: {}", i + 1, word);
        }
        println!("Press enter when ready.");
        io::stdin().read_exact(&mut [0u8]).unwrap();

        if !kgar.no_confirmation {
            // clear screen
            print!("\x1B[2J");
            println!("Please enter recovery phrase again to confirm.");

            let confirmation_words = read_words_from_terminal(kgar.in_len, true, &bip39_map)?;

            if confirmation_words != randomized_words {
                return Err("Recovery phrases do not match.".to_string());
            }
        }

        randomized_words.join(" ")
    };

    // use input words separated by spaces as randomness
    let random_bytes = words_str.as_bytes();

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
    let scalar = succeed_or_die!(keygen_bls(&random_bytes, &key_info), e => "Could not generate key because {}");
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

fn handle_generate_randomness(grand: GenRand) -> Result<(), String> {
    // Read word list and make sure it contains 2048 words.
    let bip39_vec: Vec<_> = include_str!("data/BIP39English.txt")
        .split_whitespace()
        .collect();
    if bip39_vec.len() != 2048 {
        return Err("The BIP39 word list must contain 2048 words.".to_string());
    }

    // Create hashmap mapping word to its index in the list.
    // This allows to quickly test membership and convert words to their index
    let mut bip39_map = HashMap::new();
    for (i, word) in bip39_vec.iter().enumerate() {
        bip39_map.insert(*word, i);
    }

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
    let output_str = output_words.join("\n"); // one word per line
    let mut file = succeed_or_die!(
        File::create(&grand.output_path),
        e => "Could not write output because {}"
    );
    succeed_or_die!(
        file.write_all(output_str.as_bytes()),
        e => "Could not write output because {}"
    );

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

/// Asks user to input word with given number and reads it from stdin.
pub fn read_word(number: u8) -> Result<String, std::io::Error> {
    print!("Word {}: ", number);
    io::stdout().flush()?; // actually print before reading
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    let word = line.trim().to_string(); // remove trailing newline
    Ok(word)
}

/// Asks user to input word with given number and reads it from stdin.
/// Then checks whether the word is in valid_words and starts over if not.
pub fn read_bip39_word(
    number: u8,
    bip39_map: &HashMap<&str, usize>,
) -> Result<String, std::io::Error> {
    loop {
        let word = read_word(number)?;
        if bip39_map.contains_key(&*word) {
            return Ok(word);
        } else {
            println!("The word you have entered is not in the BIP39 word list. Please try again.");
        }
    }
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
    if verify_bip && !verify_bip39(&word_list, &bip39_map) {
        return Err("The input does not constitute a valid BIP39 sentence.".to_string());
    }

    Ok(word_list)
}

/// Ask user to input num words.
/// If verify_bip39 is true, output is verified to be valid BIP39 sentence.
pub fn read_words_from_terminal(
    num: u8,
    verify_bip: bool,
    bip39_map: &HashMap<&str, usize>,
) -> Result<Vec<String>, String> {
    // Ensure that input length is in allowed set if verification is enabled.
    if verify_bip {
        match num {
            12 | 15 | 18 | 21 | 24 => (),
            _ => {
                return Err(format!(
                    "The input length was set to {}, but it must be in {{12, 15, 18, 21, 24}} for \
                     a valid BIP39 sentence.",
                    num
                ))
            }
        };
    }

    let mut word_list = Vec::<String>::new();
    for i in 1..=num {
        // read the ith word from stdin
        let word = if verify_bip {
            succeed_or_die!(
                read_bip39_word(i, &bip39_map),
                e => "Could not read input from user because {}"
            )
        } else {
            succeed_or_die!(
                read_word(i),
                e => "Could not read input from user because {}"
            )
        };
        word_list.push(word);
    }

    // verify whether input_words is a valid BIP39 sentence if check is enabled
    if verify_bip && !verify_bip39(&word_list, &bip39_map) {
        return Err("The input does not constitute a valid BIP39 sentence.".to_string());
    }

    Ok(word_list)
}

/// Verify whether the given vector of words constitutes a valid BIP39 sentence.
pub fn verify_bip39(word_vec: &[String], bip_word_map: &HashMap<&str, usize>) -> bool {
    // check that word_vec contains allowed number of words
    match word_vec.len() {
        12 | 15 | 18 | 21 | 24 => (),
        _ => return false,
    };

    // convert word vector to bits
    let mut bit_vec = BitVec::<Msb0, u8>::new();
    for word in word_vec {
        match bip_word_map.get(&**word) {
            Some(idx) => {
                let word_bits = BitVec::<Msb0, u16>::from_element(*idx as u16);
                // There are 2048 words in the BIP39 list, which can be represented using 11
                // bits. Thus, the first 5 bits of word_bits are 0. Remove those leading zeros
                // and add the remaining ones to bit_bec.
                bit_vec.extend_from_bitslice(&word_bits[5..]);
            }
            None => return false, // not valid if it contains invalid word
        };
    }

    // Valid sentence consists of initial entropy of length ent_len plus
    // checksum of length ent_len/32. Hence, ent_len * 33/32 = bit_vec.len().
    // Note that bit_vec.len() is always a multiple of 33 because 11 bits
    // are added for each word and all allowed word counts are multiples of 3.
    let ent_len = 32 * bit_vec.len() / 33;

    // split bits after ent_len off. These correspond to the checksum.
    let checksum = bit_vec.split_off(ent_len);

    // checksum is supposed to be first cs_len bits of SHA256(entropy)
    let mut sha = Sha256::new();
    sha.update(bit_vec.into_vec());
    let hash = sha.finalize();

    // convert hash from byte vector to bit vector
    let hash_bits = BitVec::<Msb0, u8>::from_slice(&hash).unwrap();

    // sentence is valid if checksum equals fist ent_len/32 bits of hash
    checksum == hash_bits[0..ent_len / 32]
}

/// Convert given byte array to valid BIP39 sentence.
/// Bytes must contain {16, 20, 24, 28, 32} bytes corresponding to
/// {128, 160, 192, 224, 256} bits.
/// This uses the method described at https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
pub fn bytes_to_bip39(bytes: &[u8], bip_word_list: &[&str]) -> Result<Vec<String>, String> {
    let ent_len = 8 * bytes.len(); // input is called entropy in BIP39
    match ent_len {
        128 | 160 | 192 | 224 | 256 => (),
        _ => {
            return Err(
                "The number of bytes to be converted to a BIP39 sentence must be in {16, 20, 24, \
                 28, 32}."
                    .to_string(),
            )
        }
    };

    // checksum length is ent_len / 32
    let cs_len = ent_len / 32;

    // checksum is first cs_len bits of SHA256(bytes)
    // first compute hash of bytes
    let mut sha = Sha256::new();
    sha.update(bytes);
    let hash = sha.finalize();

    // convert hash from byte vector to bit vector
    let hash_bits = succeed_or_die!(
        BitVec::<Msb0, u8>::from_slice(&hash),
        e => "Failed to convert hash to bit vector because {}"
    );

    // convert input bytes from byte vector to bit vector
    let mut random_bits = succeed_or_die!(
        BitVec::<Msb0, u8>::from_slice(&bytes),
        e => "Failed to convert hash to bit vector because {}"
    );

    // append the first cs_len bits of hash_bits to the end of random_bits
    for i in 0..cs_len {
        random_bits.push(hash_bits[i]);
    }

    // go over random_bits in chunks of 11 bits and convert those to words
    let mut vec = Vec::<String>::new();
    let random_iter = random_bits.chunks(11);
    for chunk in random_iter {
        let idx = chunk.iter().fold(0, |acc, b| acc << 1 | *b as usize); // convert chunk to integer
        vec.push(bip_word_list[idx].to_string());
    }

    Ok(vec)
}

/// Rerandomize given list of words using system randomness and HKDF extractor.
/// The input can be an arbitrary slice of strings.
/// The output is a valid BIP39 sentence with 24 words.
pub fn rerandomize_bip39(
    input_words: &[String],
    bip_word_list: &[&str],
) -> Result<Vec<String>, String> {
    // Get randomness from system.
    // Fill array with 256 random bytes, corresponding to 2048 bits.
    let mut system_randomness = [0u8; 256];
    rand::thread_rng().fill(&mut system_randomness[..]);

    // Combine both sources of randomness using HKDF extractor.
    // Using salt with randomness from random.org for added security.
    let salt = b"keygen-rand-wEtIBpTIyzPRpZxNUIherQh14uPlDIdiqngFSo1qrqE1UrXl5DcUfV4xddYNDnOMIumlkqS9HNshATaFxAwqiUtLj5rxeBJIOsav";
    let mut extract_ctx = HkdfExtract::<Sha256>::new(Some(salt));

    // First add all words separated by " " in input_words to key material.
    // Separation ensures word boundaries are preserved
    // to prevent different word lists from resulting in same string.
    for word in input_words {
        extract_ctx.input_ikm(word.as_bytes());
        extract_ctx.input_ikm(b" ");
    }

    // Now add system randomness to key material
    extract_ctx.input_ikm(&system_randomness);

    // Finally extract random key
    let (prk, _) = extract_ctx.finalize();

    // convert raw randomness to BIP39 word sentence
    let output_words = bytes_to_bip39(&prk, &bip_word_list)?;

    Ok(output_words)
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
        let bip39_vec: Vec<_> = include_str!("data/BIP39English.txt")
            .split_whitespace()
            .collect();
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
        let bip39_vec: Vec<_> = include_str!("data/BIP39English.txt")
            .split_whitespace()
            .collect();
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
