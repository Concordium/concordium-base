use anyhow::Context;
use bitvec::prelude::*;
use crypto_common::*;
use curve_arithmetic::*;
use dialoguer::Input;
use ed25519_hd_key_derivation::DeriveError;
use hkdf::HkdfExtract;
use id::{constants::*, types::*};
use pairing::bls12_381::Bls12;
use pedersen_scheme::Randomness as PedersenRandomness;
use rand::Rng;
use serde::{de::DeserializeOwned, Serialize as SerdeSerialize};
use serde_json::{to_string_pretty, to_writer_pretty};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fmt::Debug,
    fs::File,
    io::{self, BufReader},
    path::Path,
    str::FromStr,
};

use key_derivation::ConcordiumHdWallet;

pub type ExampleCurve = <Bls12 as Pairing>::G1;

pub type ExampleAttribute = AttributeKind;

pub type ExampleAttributeList = AttributeList<<Bls12 as Pairing>::ScalarField, ExampleAttribute>;

pub static GLOBAL_CONTEXT: &str = "database/global.json";
pub static IDENTITY_PROVIDERS: &str = "database/identity_providers.json";

const BIP39_ENGLISH: &str = include_str!("bin/data/BIP39English.txt");

/// List of BIP39 words. There is a test that checks that this list has correct
/// length, so there is no need to check when using this in the tool.
pub fn bip39_words() -> impl Iterator<Item = &'static str> { BIP39_ENGLISH.split_whitespace() }

/// Inverse mapping to the implicit mapping in bip39_words. Maps word to its
/// index in the list. This allows to quickly test membership and convert words
/// to their index.
pub fn bip39_map() -> HashMap<&'static str, usize> { bip39_words().zip(0..).collect() }

/// Read an object containing a versioned global context from the given file.
/// Currently only version 0 is supported.
pub fn read_global_context<P: AsRef<Path> + Debug>(
    filename: P,
) -> Option<GlobalContext<ExampleCurve>> {
    let params: Versioned<serde_json::Value> = read_json_from_file(filename).ok()?;
    match params.version {
        Version { value: 0 } => serde_json::from_value(params.value).ok(),
        _ => None,
    }
}

/// Read ip-info, deciding on how to parse based on the version.
pub fn read_ip_info<P: AsRef<Path> + Debug>(filename: P) -> io::Result<IpInfo<Bls12>> {
    let params: Versioned<serde_json::Value> = read_json_from_file(filename)?;
    match params.version {
        Version { value: 0 } => Ok(serde_json::from_value(params.value)?),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid identity provider version {}.", other),
        )),
    }
}

/// Read id recovery request.
pub fn read_recovery_request<P: AsRef<Path> + Debug>(
    filename: P,
) -> io::Result<IdRecoveryRequest<ExampleCurve>> {
    let params: Versioned<serde_json::Value> = read_json_from_file(filename)?;
    match params.version {
        Version { value: 0 } => Ok(serde_json::from_value(params.value)?),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid recovery request version {}.", other),
        )),
    }
}

/// Read id_object, deciding on how to parse based on the version.
pub fn read_id_object<P: AsRef<Path> + Debug>(
    filename: P,
) -> io::Result<IdentityObject<Bls12, ExampleCurve, ExampleAttribute>> {
    let params: Versioned<serde_json::Value> = read_json_from_file(filename)?;
    match params.version {
        Version { value: 0 } => Ok(serde_json::from_value(params.value)?),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid identity object version {}.", other),
        )),
    }
}

/// Read version id_object, deciding on how to parse based on the version.
pub fn read_id_object_v1<P: AsRef<Path> + Debug>(
    filename: P,
) -> io::Result<IdentityObjectV1<Bls12, ExampleCurve, ExampleAttribute>> {
    let params: Versioned<serde_json::Value> = read_json_from_file(filename)?;
    match params.version {
        Version { value: 0 } => Ok(serde_json::from_value(params.value)?),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid identity object version {}.", other),
        )),
    }
}

/// Encrypt data (if password is provided), and write the (encrypted) data to
/// file. Upon success, returns Ok(true) if data was encrypted and Ok(false) if
/// not.
pub fn output_possibly_encrypted<X: SerdeSerialize>(
    fname: &Path,
    data: &X,
) -> Result<bool, std::io::Error> {
    let pass = ask_for_password_confirm(
        "Enter password to encrypt (leave empty for no encryption): ",
        true,
    )?;
    if pass.is_empty() {
        println!("No password supplied, so output will not be encrypted.");
        write_json_to_file(fname, data)?;
        Ok(false)
    } else {
        let plaintext = serde_json::to_vec(data).expect("JSON serialization does not fail.");
        let encrypted =
            crypto_common::encryption::encrypt(&pass.into(), &plaintext, &mut rand::thread_rng());
        write_json_to_file(fname, &encrypted)?;
        Ok(true)
    }
}

/// Decrypt data if encrypted.
pub fn decrypt_input<P: AsRef<Path> + Debug, X: DeserializeOwned>(input: P) -> anyhow::Result<X> {
    let data = std::fs::read(&input).context("Cannot read input file.")?;
    match serde_json::from_slice(&data) {
        Ok(data) => Ok(data),
        Err(_) => {
            let parsed_data = serde_json::from_slice(&data)?;
            let pass = rpassword::prompt_password(&format!(
                "Enter password to decrypt file {} with: ",
                input.as_ref().to_string_lossy()
            ))?;
            let plaintext = crypto_common::encryption::decrypt(&pass.into(), &parsed_data)
                .context("Could not decrypt data.")?;
            serde_json::from_slice(&plaintext).context("Could not parse decrypted data.")
        }
    }
}

/// Read id_use_data, deciding on how to parse based on the version.
pub fn read_id_use_data<P: AsRef<Path> + Debug>(
    filename: P,
) -> io::Result<IdObjectUseData<Bls12, ExampleCurve>> {
    let params: Versioned<serde_json::Value> = match decrypt_input(filename) {
        Ok(versioned_val) => versioned_val,
        Err(e) => {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("{}", e)));
        }
    };
    match params.version {
        Version { value: 0 } => Ok(serde_json::from_value(params.value)?),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid identity object use data object version {}.", other),
        )),
    }
}

/// Read pre-identity object, deciding on how to parse based on the version.
pub fn read_pre_identity_object<P: AsRef<Path> + Debug>(
    filename: P,
) -> io::Result<PreIdentityObject<Bls12, ExampleCurve>> {
    let params: Versioned<serde_json::Value> = read_json_from_file(filename)?;
    match params.version {
        Version { value: 0 } => Ok(serde_json::from_value(params.value)?),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid identity object use data object version {}.", other),
        )),
    }
}

/// Read pre-identity object, deciding on how to parse based on the version.
pub fn read_pre_identity_object_v1<P: AsRef<Path> + Debug>(
    filename: P,
) -> io::Result<PreIdentityObjectV1<Bls12, ExampleCurve>> {
    let params: Versioned<serde_json::Value> = read_json_from_file(filename)?;
    match params.version {
        Version { value: 0 } => Ok(serde_json::from_value(params.value)?),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid identity object use data object version {}.", other),
        )),
    }
}

/// Read identity providers versioned with a single version at the top-level.
/// All values are parsed according to that version.
pub fn read_identity_providers<P: AsRef<Path> + Debug>(filename: P) -> io::Result<IpInfos<Bls12>> {
    let vips: Versioned<serde_json::Value> = read_json_from_file(filename)?;
    match vips.version {
        Version { value: 0 } => Ok(serde_json::from_value(vips.value)?),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid identity providers version {}.", other),
        )),
    }
}

/// Read a single identity provider versioned with a single version at the
/// top-level. All values are parsed according to that version.
pub fn read_identity_provider<P: AsRef<Path> + Debug>(filename: P) -> io::Result<IpInfo<Bls12>> {
    let vips: Versioned<serde_json::Value> = read_json_from_file(filename)?;
    match vips.version {
        Version { value: 0 } => Ok(serde_json::from_value(vips.value)?),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid identity provider version {}.", other),
        )),
    }
}

/// Read anonymity revokers from a file, determining how to parse them from the
/// version number.
pub fn read_anonymity_revokers<P: AsRef<Path> + Debug>(
    filename: P,
) -> io::Result<ArInfos<ExampleCurve>> {
    let vars: Versioned<serde_json::Value> = read_json_from_file(filename)?;
    match vars.version {
        Version { value: 0 } => Ok(serde_json::from_value(vars.value)?),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid anonymity revokers version {}.", other),
        )),
    }
}

/// Read anonymity revokers from a file, determining how to parse them from the
/// version number.
pub fn read_credential<P: AsRef<Path> + Debug>(
    filename: P,
) -> io::Result<CredentialDeploymentInfo<Bls12, ExampleCurve, ExampleAttribute>> {
    let vars: Versioned<serde_json::Value> = read_json_from_file(filename)?;
    match vars.version {
        Version { value: 0 } => Ok(serde_json::from_value(vars.value)?),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid credential version {}.", other),
        )),
    }
}

/// Parse YYYYMM as YearMonth
pub fn parse_yearmonth(input: &str) -> Option<YearMonth> { YearMonth::from_str(input).ok() }

/// Output json to a file, pretty printed.
pub fn write_json_to_file<P: AsRef<Path>, T: SerdeSerialize>(filepath: P, v: &T) -> io::Result<()> {
    let file = File::create(filepath)?;
    Ok(to_writer_pretty(file, v)?)
}

/// Output json to standard output, pretty printed.
pub fn output_json<T: SerdeSerialize>(v: &T) {
    println!("{}", to_string_pretty(v).unwrap());
}

pub fn read_json_from_file<P, T>(path: P) -> io::Result<T>
where
    P: AsRef<Path> + Debug,
    T: DeserializeOwned, {
    let file = File::open(path)?;

    let reader = BufReader::new(file);
    let u = serde_json::from_reader(reader)?;
    Ok(u)
}

/// Ask for a password and a confirmation
/// It doesn't ask for a confirmation if `skip_if_empty` is `true` and the
/// password is empty
pub fn ask_for_password_confirm(
    prompt: &str,
    skip_if_empty: bool,
) -> Result<String, std::io::Error> {
    loop {
        let pass = rpassword::prompt_password(prompt)?;
        if !(skip_if_empty && pass.is_empty()) {
            let pass2 = rpassword::prompt_password("Re-enter password: ")?;
            if pass != pass2 {
                println!("Passwords were not equal. Try again.");
                continue;
            }
        }
        return Ok(pass);
    }
}

// BIP related stuff

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

/// Asks user to input word with given number and reads it from stdin.
/// Checks whether the word is in valid_words if verify is true.
pub fn read_bip39_word(
    number: u8,
    verify: bool,
    bip39_map: &HashMap<&str, usize>,
) -> Result<String, std::io::Error> {
    Input::new()
        .with_prompt(format!("Word {}", number))
        .validate_with(|input: &String| -> Result<(), String> {
            // input is always valid if !verify. Otherwise must be in bip39_map
            if !verify || bip39_map.contains_key(&*input.to_owned()) {
                Ok(())
            } else {
                Err(format!(
                    "The word \"{}\" is not in the BIP39 word list. Please try again.",
                    input
                ))
            }
        })
        .interact_text()
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
        let word = succeed_or_die!(
            read_bip39_word(i, verify_bip, bip39_map),
            e => "Could not read input from user because {}"
        );
        word_list.push(word);
    }

    // verify whether input_words is a valid BIP39 sentence if check is enabled
    if verify_bip && !verify_bip39(&word_list, bip39_map) {
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
        match bip_word_map.get(word.as_str()) {
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
    let hash = Sha256::digest(&bit_vec.into_vec());

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
    let hash = Sha256::digest(bytes);

    // convert hash from byte vector to bit vector
    let hash_bits = succeed_or_die!(
        BitVec::<Msb0, u8>::from_slice(&hash),
        e => "Failed to convert hash to bit vector because {}"
    );

    // convert input bytes from byte vector to bit vector
    let mut random_bits = succeed_or_die!(
        BitVec::<Msb0, u8>::from_slice(bytes),
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
    // For added security, use pseudorandom salt.
    let salt = Sha256::digest(b"concordium-key-generation-tool-version-1");
    let mut extract_ctx = HkdfExtract::<Sha256>::new(Some(&salt));

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
    let output_words = bytes_to_bip39(&prk, bip_word_list)?;

    Ok(output_words)
}

pub struct CredentialContext {
    pub wallet:                  ConcordiumHdWallet,
    pub identity_provider_index: u32,
    pub identity_index:          u32,
    pub credential_index:        u32,
}

impl HasAttributeRandomness<ArCurve> for CredentialContext {
    type ErrorType = DeriveError;

    fn get_attribute_commitment_randomness(
        &self,
        attribute_tag: AttributeTag,
    ) -> Result<PedersenRandomness<ArCurve>, Self::ErrorType> {
        self.wallet.get_attribute_commitment_randomness(
            self.identity_provider_index,
            self.identity_index,
            self.credential_index,
            attribute_tag,
        )
    }
}
