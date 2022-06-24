//! Some command line auxiliary utilities.
//! At the moment we have encryption and decryption in the formats used by other
//! parts of the Concordium project.

use anyhow::Context;
use clap::AppSettings;
use client_server_helpers::*;
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(StructOpt)]
struct ConfigEncrypt {
    #[structopt(long = "in", help = "File to encrypt.")]
    input:  PathBuf,
    #[structopt(long = "out", help = "Name of the output file.")]
    output: PathBuf,
}

#[derive(StructOpt)]
struct ConfigDecrypt {
    #[structopt(long = "in", help = "File to decrypt.")]
    input:  PathBuf,
    #[structopt(
        long = "out",
        help = "Place to output the decryption. Defaults to standard output."
    )]
    output: Option<PathBuf>,
}

#[derive(StructOpt)]
#[structopt(
    about = "Various helper utilities",
    author = "Concordium",
    version = "0.0"
)]
enum Utils {
    #[structopt(name = "encrypt", about = "Encrypt the contents of the supplied file.")]
    Encrypt(ConfigEncrypt),
    #[structopt(name = "decrypt", about = "Decrypt the contents of the supplied file.")]
    Decrypt(ConfigDecrypt),
}

fn main() -> anyhow::Result<()> {
    let app = Utils::clap()
        .setting(AppSettings::ArgRequiredElseHelp)
        .global_setting(AppSettings::ColoredHelp);
    let matches = app.get_matches();
    let utls = Utils::from_clap(&matches);
    match utls {
        Utils::Encrypt(cfg) => handle_encrypt(cfg),
        Utils::Decrypt(cfg) => handle_decrypt(cfg),
    }
}

fn handle_encrypt(cfg: ConfigEncrypt) -> anyhow::Result<()> {
    let data = std::fs::read(&cfg.input).context("Cannot read input file.")?;
    let pass = ask_for_password_confirm("Enter password to encrypt with: ", false)?;
    let encrypted =
        crypto_common::encryption::encrypt(&pass.into(), &data, &mut rand::thread_rng());
    eprintln!("Writing output to {}", cfg.output.to_string_lossy());
    write_json_to_file(&cfg.output, &encrypted)?;
    Ok(())
}

fn handle_decrypt(cfg: ConfigDecrypt) -> anyhow::Result<()> {
    let data = std::fs::read(&cfg.input).context("Cannot read input file.")?;
    let parsed_data = serde_json::from_slice(&data)?;
    let pass = rpassword::prompt_password("Enter password to decrypt with: ")?;
    let plaintext = match crypto_common::encryption::decrypt(&pass.into(), &parsed_data) {
        Ok(pt) => pt,
        Err(_) => anyhow::bail!("Could not decrypt."),
    };
    match cfg.output {
        Some(fname) => {
            eprintln!("Writing output to {}", fname.to_string_lossy());
            std::fs::write(fname, &plaintext)?;
        }
        None => {
            let s = String::from_utf8(plaintext)?;
            println!("{}", s);
        }
    }
    Ok(())
}
