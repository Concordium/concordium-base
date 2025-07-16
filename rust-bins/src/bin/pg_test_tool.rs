//! # Privacy Guardian Test Tool
//!
//! An application to test the functionality of privacy guardian keys.
use anyhow::Context;
use clap::AppSettings;
use client_server_helpers::*;
use concordium_base::{
    common::*,
    curve_arithmetic::{Curve, Value},
    elgamal::{decrypt_from_chunks_given_generator, Cipher},
    id::{constants::ArCurve, types::*, utils::encrypt_prf_share},
};
use dialoguer::Input;
use hex::encode;
use rand::{seq::IteratorRandom, thread_rng};
use sha2::{Digest, Sha256};
use std::{
    fmt::Debug,
    path::{Path, PathBuf},
    str::from_utf8,
};
use structopt::StructOpt;

/// Options for testing the functionality of a single PG key.
#[derive(StructOpt)]
struct SingleKeyTestDec {
    /// The test record containing the encrypted challenge message.
    #[structopt(
        short = "tr",
        long = "test-rec",
        help = "The test record to be decrypted."
    )]
    test_record: Option<PathBuf>,
    /// The private key of the privacy guardian.
    #[structopt(
        short = "sk",
        long = "pg-priv",
        help = "File with privacy guardian's private and public keys."
    )]
    pg_priv:     Option<PathBuf>,
    /// The global cryptographic parameters of the blockchain.
    #[structopt(
        short = "g",
        long = "global",
        help = "File with cryptographic parameters."
    )]
    global:      Option<PathBuf>,
}

/// Options for creating a test to check the functionality of a single PG key.
#[derive(StructOpt)]
struct SingleKeyTestEnc {
    /// The public key of the privacy guardian
    #[structopt(
        short = "pk",
        long = "pg-pub",
        help = "File with the privacy guardian public key."
    )]
    pg_pub:             Option<PathBuf>,
    /// The global cryptographic parameters of the blockchain.
    #[structopt(
        short = "g",
        long = "global",
        help = "File with cryptographic parameters."
    )]
    global:             Option<PathBuf>,
    /// The output test record.
    #[structopt(short = "o", long = "out", help = "File to output the test record to.")]
    out:                Option<PathBuf>,
    /// Set if the user wants to encrypt a custom message.
    #[structopt(
        long = "use-custom-message",
        help = "Encrypt user defined message instead of three random BIP-39 words."
    )]
    use_custom_message: bool,
    /// The custom message used by the `use-custom-message`.
    #[structopt(
        long = "message",
        help = "Pure ASCII string, excluding the null character (\x00), 31 character limit."
    )]
    custom_message:     Option<String>,
}

/// Enumerates the functionality of this tool.
#[derive(StructOpt)]
#[structopt(
    about = "Testing tool for privacy guardians.",
    name = "pg_test_tool",
    author = "Concordium",
    version = "1.0"
)]
enum KeygenTool {
    /// Test the functionality of a single PG key.
    #[structopt(
        name = "test-dec",
        about = "Test functionality of privacy guardian key by decrypting a test record.",
        version = "1.0"
    )]
    SingleDec(SingleKeyTestDec),
    /// Generate a new test instance for checking the functionality of a single
    /// PG key.
    #[structopt(
        name = "gen-enc",
        about = "Generate a test record for a given privacy guardian public key.",
        version = "1.0"
    )]
    GenSingleEnc(SingleKeyTestEnc),
}

/// The test record for testing the functionality of a single PG key.
#[derive(Debug, PartialEq, Eq, Serialize, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(serialize = "C: Curve", deserialize = "C: Curve"))]
pub struct SingleKeyTestRecord<C: Curve> {
    /// identity of the privacy guardian
    #[serde(rename = "pgIdentity")]
    pub pg_identity: ArIdentity,
    /// hash of the encrypted message
    #[serde(rename = "msgHash")]
    pub msg_hash:    String,
    /// encrypted message
    #[serde(rename = "msgEnc")]
    pub msg_enc:     [Cipher<C>; 8],
}

fn main() -> anyhow::Result<()> {
    let app = KeygenTool::clap()
        .setting(AppSettings::ArgRequiredElseHelp)
        .global_setting(AppSettings::ColoredHelp);
    let matches = app.get_matches();
    let kg = KeygenTool::from_clap(&matches);
    use KeygenTool::*;
    match kg {
        SingleDec(test_dec) => handle_test_dec(test_dec),
        GenSingleEnc(test_enc) => handle_generate_test_enc(test_enc),
    }
}

/// Extract file path from options and ask the user for a path if this fails.
fn get_file_path(
    maybe_file_path: Option<PathBuf>,
    description: &str,
    default_path: &str,
) -> PathBuf {
    maybe_file_path.unwrap_or_else(|| {
        let validator = |candidate: &String| -> Result<(), String> {
            if std::path::Path::new(candidate).exists() {
                Ok(())
            } else {
                Err(format!("File {} does not exist. Try again.", candidate))
            }
        };

        let mut input = Input::new();
        input.with_prompt(format!("Enter the path to the {} file", description));
        if std::path::Path::new(default_path).exists() {
            input.default(default_path.to_string());
        };
        input.validate_with(validator);
        loop {
            match input.interact() {
                Ok(x) => return PathBuf::from(x),
                Err(e) => println!("{}", e),
            }
        }
    })
}

/// Read privacy guardian information from a file, determining how to parse them
/// from the version number.
pub fn read_pg_info<P: AsRef<Path> + Debug>(filename: P) -> std::io::Result<ArInfo<ArCurve>> {
    let vars: Versioned<serde_json::Value> = read_json_from_file(filename)?;
    match vars.version {
        Version { value: 0 } => Ok(serde_json::from_value(vars.value)?),
        other => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Invalid privacy guardian version {}.", other),
        )),
    }
}

/// Encode a short string in a field element.
///
/// This function takes a string of length at most 31 bytes and converts
/// it to a field element.
///
/// Encoding fails if the string is not ASCII or contains \x00.
fn to_field_element<C: Curve>(m: String) -> Option<Value<C>> {
    if !m.is_ascii() || m.contains("\x00") {
        return None;
    }
    let mut buf = [0u8; 32];
    let len = m.as_bytes().len();
    if len > 31 {
        return None;
    }
    let rev_bytes: Vec<u8> = m
        .as_bytes()
        .iter()
        .filter(|x| **x != 0)
        .copied()
        .rev()
        .collect();
    buf[(32 - len - 1)..31].copy_from_slice(&rev_bytes);
    let s = C::scalar_from_bytes(buf);
    Some(Value::<C>::new(s))
}

/// Decode a string from a field element.
///
/// Zero bytes (`\x00`) are ignored.
/// This function may have undefined behavior if the encoded string is is not
/// ASCII or contains \x00.
fn from_field_element<C: Curve>(v: Value<C>) -> String {
    let v: C::Scalar = *v;
    let mut bytes = Vec::new();
    v.serial(&mut bytes);
    let bytes: Vec<u8> = bytes.into_iter().skip(1).filter(|x| *x != 0).collect();
    from_utf8(&bytes)
        .expect("Could not convert bytes to string")
        .to_string()
}

/// Test the functionality of a single PG key by decrypting the given test
/// record.
fn handle_test_dec(test_dec: SingleKeyTestDec) -> anyhow::Result<()> {
    // Read global context
    let global_file = get_file_path(test_dec.global, "global context", "global.json");
    let global_ctx = read_global_context(global_file)
        .context("Cannot read cryptographic parameters. Terminating.")?;

    // Read privacy guardian private key
    let pg_priv_file = get_file_path(
        test_dec.pg_priv,
        "privacy guardian private key",
        "pg-info.json",
    );
    let pg_data = match decrypt_pg_data(&pg_priv_file) {
        Ok(data) => data,
        Err(e) => anyhow::bail!("Could not read PG secret key due to {}", e),
    };

    // Read the test record
    let test_record_file = get_file_path(
        test_dec.test_record,
        "test record",
        &format!("pg-test-{}.json", pg_data.public_ar_info.ar_identity),
    );
    let test_record: Versioned<SingleKeyTestRecord<ArCurve>> =
        read_json_from_file(test_record_file).context("Could not read test record due to {}")?;
    anyhow::ensure!(
        test_record.version == VERSION_0,
        "The version of the test record should be 0."
    );
    let test_record = test_record.value;

    // Decrypt message
    let m = decrypt_from_chunks_given_generator(
        &pg_data.ar_secret_key,
        &test_record.msg_enc,
        global_ctx.encryption_in_exponent_generator(),
        1 << 16,
        CHUNK_SIZE,
    );
    let msg = from_field_element(m);

    // Compute hash of the decrypted message
    let h: [u8; 32] = Sha256::digest(&msg).into();
    let h = encode(h);

    // Check if hash matches the expected hash
    anyhow::ensure!(
        h == test_record.msg_hash,
        "The hash of the decrypted message does not match the expected hash."
    );

    println!("Test successful!");
    println!("Please report back the following message: {}", msg);
    Ok(())
}

/// Generate a new test record for checking the functionality of a given PG key.
fn handle_generate_test_enc(test_enc: SingleKeyTestEnc) -> anyhow::Result<()> {
    // Read global context
    let global_file = get_file_path(test_enc.global, "global context", "global.json");
    let global_ctx = read_global_context(global_file)
        .context("Cannot read cryptographic parameters. Terminating.")?;

    // Read privacy guardian public key
    let pg_pub_file = get_file_path(
        test_enc.pg_pub,
        "privacy guardian public key",
        "pg-info.pub.json",
    );
    let pg_pub: ArInfo<ArCurve> = read_pg_info(pg_pub_file)
        .context("Could not read privacy guardian public key from provided file because {}")?;

    // Define message to be encrypted
    let msg = match test_enc.use_custom_message {
        // Custom message
        true => {
            let msg = test_enc.custom_message.unwrap_or_else(|| {
                let mut input = Input::new();
                input.with_prompt("Enter the message to be encrypted");
                loop {
                    match input.interact() {
                        Ok(x) => return x,
                        Err(e) => println!("{}", e),
                    }
                }
            });
            anyhow::ensure!(
                msg.as_bytes().len() <= 31,
                "Message is too long. It must be at most 31 bytes."
            );
            msg
        }
        // Default: generate a random message from BIP-39 words
        _ => {
            // Note: Each word is at most 8 ASCII characters, so the message is at most
            // 3*8+2 = 26 bytes.
            let mut csprng = thread_rng();
            let mut msg = String::new();
            for _ in 0..3 {
                let word = bip39_words().choose(&mut csprng).unwrap();
                msg.push_str(word);
                msg.push(' ');
            }
            msg.pop(); // Remove the last space
            println!("The encrypted message will be: {}", msg);
            println!("Record the message for test result verification.");
            msg
        }
    };

    // Compute hash of the message
    let h: [u8; 32] = Sha256::digest(&msg).into();

    // Encrypt the message
    let m = to_field_element(msg).context("Message is too long. It must be at most 31 bytes.")?;
    let mut csprng = thread_rng();
    let enc = encrypt_prf_share(
        &global_ctx,
        pg_pub.ar_public_key.get_public_key(),
        &m,
        &mut csprng,
    )
    .0;

    // Generate and save the output
    let test_record = Versioned::new(VERSION_0, SingleKeyTestRecord {
        pg_identity: pg_pub.ar_identity,
        msg_hash:    encode(h),
        msg_enc:     enc,
    });

    let out_file = test_enc.out.unwrap_or_else(|| {
        PathBuf::from(
            Input::new()
                .with_prompt("Output file name")
                .default(format!("pg-test-{}.json", pg_pub.ar_identity))
                .interact()
                .expect("Output file not provided."),
        )
    });

    write_json_to_file(&out_file, &test_record)
        .context("Could not JSON write test information to file because {}")?;
    println!("Wrote test information to {}.", out_file.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use concordium_base::id::constants::ArCurve;

    use crate::{from_field_element, to_field_element};

    #[test]
    fn test_msg_to_from_field() {
        let msg = "abandon abandon zoo".to_string();
        let v = to_field_element::<ArCurve>(msg.clone()).expect("failed conversion");
        let msg_new = from_field_element(v);
        assert_eq!(msg, msg_new)
    }
}
