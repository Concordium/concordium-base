use clap::{App, Arg, SubCommand};

use dialoguer::{Checkboxes, Input, Select};
use dodis_yampolskiy_prf::secret as prf;
use elgamal::{public::PublicKey, secret::SecretKey};
use pairing::bls12_381::Bls12;
use rand::*;
use std::convert::*;

use hex::encode;
use id::types::*;
use serde_json::{json, to_string_pretty, Value};

use std::{
    fs::File,
    io::{self, BufReader, Write},
    path::Path,
};

fn write_json_to_file(filepath: &str, js: &Value) -> io::Result<()> {
    let path = Path::new(filepath);
    let mut file = File::create(&path)?;
    file.write_all(to_string_pretty(js).unwrap().as_bytes())
}

fn output_json(js: &Value) -> () {
    println!("{}", to_string_pretty(js).unwrap());
}

fn read_ahi_from_file<P: AsRef<Path>>(path: P) -> io::Result<Value> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let u = serde_json::from_reader(reader)?;
    Ok(u)
}

fn main() {
    let matches = App::new("Prototype client showcasing ID layer interactions.")
        .version("0.123456")
        .author("Concordium")
        .subcommand(
            SubCommand::with_name("create_ahi")
                .about("Create new account holder information.")
                .arg(
                    Arg::with_name("file")
                        .long("file")
                        .value_name("FILE")
                        .short("f")
                        .help("write generated account holder information to file"),
                ),
        )
        .subcommand(SubCommand::with_name("load_ahi"))
        .get_matches();
    if let Some(matches) = matches.subcommand_matches("create_ahi") {
        if let Ok(name) = Input::new()
            .with_prompt("Your unique identifier")
            .interact()
        {
            let mut csprng = thread_rng();
            let secret = SecretKey::generate(&mut csprng);
            let public = PublicKey::from(&secret);
            let id_prf_key = prf::SecretKey::generate(&mut csprng);
            let ah_info = AccHolderInfo::<Bls12> {
                id_ah: name,
                id_cred: IdCredentials {
                    id_cred_sec: secret,
                    id_cred_pub: public,
                },
                id_prf_key,
            };
            let js = json!({
                "name": ah_info.id_ah,
                "idCredPub": encode(ah_info.id_cred.id_cred_pub.to_bytes()),
                "idCredSecret": encode(ah_info.id_cred.id_cred_sec.to_bytes()),
                "idCredPrfKey": encode(ah_info.id_prf_key.to_bytes())
            });
            if let Some(filepath) = matches.value_of("file") {
                match write_json_to_file(filepath, &js) {
                    Ok(()) => println!("Wrote AHI to file."),
                    Err(_) => {
                        println!("Could not write to file. The generated information is");
                        output_json(&js);
                    }
                }
            } else {
                println!("Generated account holder information.");
                output_json(&js);
            }
        } else {
            println!("You need to provide a name. Terminating.");
        }
    }
    if let Some(matches) = matches.subcommand_matches("load_ahi") {
        let path = Path::new("out.json");
        if let Ok(v) = read_ahi_from_file(&path) {
            println!("{}", v);
        }
    }
}
