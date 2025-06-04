use clap::AppSettings;
use client_server_helpers::*;
use concordium_base::{
    common::{Versioned, VERSION_0}, curve_arithmetic::{Curve, Value}, elgamal::{encrypt_in_chunks_given_generator, Cipher, PublicKey, SecretKey}, id::{
        constants::ArCurve, secret_sharing::Threshold, types::*
    }, pedersen_commitment::CommitmentKey, random_oracle::RandomOracle, sigma_protocols::{com_enc_eq::{self, ComEncEq, ComEncEqSecret}, common::prove}
};
use dialoguer::{Input};
use rand::{rngs::ThreadRng, thread_rng};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    str::FromStr,
};
use structopt::StructOpt;

#[derive(StructOpt)]
struct TestEnc {
    #[structopt(long = "message", help = "The test message to be encrypted")]
    message: Option<String>,
    #[structopt(long = "global", help = "File with cryptographic parameters.")]
    global: Option<PathBuf>,
    #[structopt(long = "ar-pub", help = "File with the PG public key.")]
    pg_pub: Option<PathBuf>,
    #[structopt(long = "out", help = "File to output the encryption to.")]
    out: Option<PathBuf>,
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
#[structopt(
    about = "Tool for generating PG tests.",
    name = "pg_test_tool",
    author = "Concordium",
    version = "1.0"
)]
enum KeygenTool {
    #[structopt(name = "test-enc", about = "Generate test encryption", version = "1.0")]
    TestEnc(TestEnc),
}

fn main() {
    let app = KeygenTool::clap()
        .setting(AppSettings::ArgRequiredElseHelp)
        .global_setting(AppSettings::ColoredHelp);
    let matches = app.get_matches();
    let kg = KeygenTool::from_clap(&matches);
    use KeygenTool::*;
    match kg {
        TestEnc(tstenc) => {
            if let Err(e) = handle_generate_test_enc(tstenc) {
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

// This function takes a string maps roughly the first 32 bytes into a scalar of ArCurve
fn to_field_element<C: Curve>(m: String) -> Value<C> {
    let mut buf = [0u8; 32];
    let len = m.as_bytes().len();
    let rev_bytes:Vec<u8> = m.as_bytes().iter().copied().rev().collect();
    buf[(32-len-1)..31].copy_from_slice(&rev_bytes);
    let s = C::scalar_from_bytes(buf);
    Value::<C>::new(s)
}

// Compute encryption
fn encrypt_msg<C: Curve>(msg: String, pk: &PublicKey<C>, g:&C) -> [Cipher<C>;8] {
    let m = to_field_element(msg);
    let mut csprng = thread_rng();
    let mut ciphers = encrypt_in_chunks_given_generator::<C, ThreadRng>(
        pk,
        &m,
        CHUNK_SIZE,
        g,
        &mut csprng,
    );
    // Start crafting a fake PRF decryption request
    let (encryption_8, _) = ciphers.pop().unwrap();
    let (encryption_7, _) = ciphers.pop().unwrap();
    let (encryption_6, _) = ciphers.pop().unwrap();
    let (encryption_5, _) = ciphers.pop().unwrap();
    let (encryption_4, _) = ciphers.pop().unwrap();
    let (encryption_3, _) = ciphers.pop().unwrap();
    let (encryption_2, _) = ciphers.pop().unwrap();
    let (encryption_1, _) = ciphers.pop().unwrap();
    [
        encryption_1,
        encryption_2,
        encryption_3,
        encryption_4,
        encryption_5,
        encryption_6,
        encryption_7,
        encryption_8,
    ]
}


fn gen_fake_proof<C:Curve>() -> com_enc_eq::Response<C> {
    let mut csprng = thread_rng();
    let sk = SecretKey::generate_all(&mut csprng);
    let public_key = PublicKey::from(&sk);
    let comm_key = CommitmentKey::<C>::generate(&mut csprng);

    let x = Value::generate_non_zero(&mut csprng);
    let h_in_exponent = C::generate(&mut csprng);
    let (cipher, elgamal_randomness) =
        public_key.encrypt_exponent_rand_given_generator(&x, &h_in_exponent, &mut csprng);
    let (commitment, randomness) = comm_key.commit(&x, &mut csprng);
    let secret = ComEncEqSecret {
        value:         x,
        elgamal_rand:  elgamal_randomness,
        pedersen_rand: randomness,
    };
    let prover = ComEncEq {
        cipher,
        commitment,
        pub_key: public_key,
        cmm_key: comm_key,
        encryption_in_exponent_generator: h_in_exponent,
    };
    let ro = RandomOracle::domain([0u8]);
    let proof = prove(&mut ro.split(), &prover, secret, &mut csprng).expect("Proving should succeed.");
    proof.response
}


fn handle_generate_test_enc(tenc: TestEnc) -> Result<(), String> {
    // read global context
    let global_file = tenc.global.unwrap_or_else(|| {
        // read a file from the user, checking that the file they input actually exists.
        let validator = |candidate: &String| -> Result<(), String> {
            if std::path::Path::new(candidate).exists() {
                Ok(())
            } else {
                Err(format!("File {} does not exist. Try again.", candidate))
            }
        };

        let mut input = Input::new();
        input.with_prompt("Enter the path to the global context file");
        // offer a default option if the file exists.
        if std::path::Path::new("global.json").exists() {
            input.default("global.json".to_string());
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

    // read PG public key
    let pg_pub_file = tenc.pg_pub.unwrap_or_else(|| {
        // read a file from the user, checking that the file they input actually exists.
        let validator = |candidate: &String| -> Result<(), String> {
            if std::path::Path::new(candidate).exists() {
                Ok(())
            } else {
                Err(format!("File {} does not exist. Try again.", candidate))
            }
        };

        let mut input = Input::new();
        input.with_prompt("Enter the path to the PG public key file");
        // offer a default option if the file exists.
        if std::path::Path::new("ar-info.json").exists() {
            input.default("ar-info.json".to_string());
        };
        input.validate_with(validator);
        loop {
            match input.interact() {
                Ok(x) => return PathBuf::from(x),
                Err(e) => println!("{}", e),
            }
        }
    });

    let pg_pub: ArInfo<ArCurve> = succeed_or_die!(read_pg_info(pg_pub_file), e => "Could not read PG public key from provided file because {}");

    let msg = tenc.message.unwrap_or_else(|| {
        let mut input = Input::new();
        input.with_prompt("Enter the message to be encrypted");
        loop {
            match input.interact() {
                Ok(x) => return x,
                Err(e) => println!("{}", e),
            }
        }
    });
    
    let enc = encrypt_msg(msg,pg_pub.ar_public_key.get_public_key(),global_ctx.encryption_in_exponent_generator());

    let fake_ip_ar_data = IpArData{
        enc_prf_key_share: enc,
        proof_com_enc_eq: gen_fake_proof(),
    };

    let mut fake_ar_data = BTreeMap::new();
    fake_ar_data.insert(pg_pub.ar_identity, fake_ip_ar_data);

    let fake_ar_record = Versioned::new(VERSION_0, AnonymityRevocationRecord {
        id_cred_pub: ArCurve::zero_point(),
        ar_data: fake_ar_data,
        max_accounts: 0,
        threshold: Threshold(1u8),
    });

    let out_file = tenc.out.unwrap_or_else(|| {
        PathBuf::from(
            Input::new()
                .with_prompt("Output file name")
                .default(format!("pg-test-{}.json", pg_pub.ar_identity))
                .interact()
                .expect("Output file not provided."),
        )
    });

    match write_json_to_file(&out_file, &fake_ar_record) {
        Ok(_) => println!("Wrote test information {}.", out_file.display()),
        Err(e) => {
            return Err(format!(
                "Could not JSON write test information to file because {}",
                e
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {}
