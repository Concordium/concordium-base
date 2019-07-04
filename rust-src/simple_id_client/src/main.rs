use clap::{App, Arg, SubCommand};

use curve_arithmetic::Pairing;
use dialoguer::{Checkboxes, Input, Select};
use dodis_yampolskiy_prf::secret as prf;
use elgamal::{public::PublicKey, secret::SecretKey};
use pairing::{
    bls12_381::{Bls12, Fr, FrRepr},
    PrimeField,
};
use rand::*;
use std::{convert::*, fmt};

use hex::{decode, encode};
use id::types::*;
use serde_json::{json, to_string_pretty, Value};

use std::{
    fs::File,
    io::{self, BufReader, Write},
    path::Path,
};

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum ExampleAttribute {
    Age(u8),
    Citizenship(u16),
    ///    ExpiryDate(NaiveDateTime),
    MaxAccount(u16),
    Business(bool),
}

type ExampleAttributeList = AttributeList<<Bls12 as Pairing>::ScalarField, ExampleAttribute>;

impl Attribute<<Bls12 as Pairing>::ScalarField> for ExampleAttribute {
    fn to_field_element(&self) -> <Bls12 as Pairing>::ScalarField {
        match self {
            ExampleAttribute::Age(x) => Fr::from_repr(FrRepr::from(*x as u64)).unwrap(),
            ExampleAttribute::Citizenship(c) => Fr::from_repr(FrRepr::from(*c as u64)).unwrap(),
            ExampleAttribute::MaxAccount(x) => Fr::from_repr(FrRepr::from(*x as u64)).unwrap(),
            ExampleAttribute::Business(b) => Fr::from_repr(FrRepr::from(*b as u64)).unwrap(),
        }
    }
}

impl fmt::Display for ExampleAttribute {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ExampleAttribute::Age(x) => write!(f, "(Age, {})", x),
            ExampleAttribute::Citizenship(c) => write!(f, "(Citizenship, {})", c),
            ExampleAttribute::MaxAccount(x) => write!(f, "(MaxAccount, {})", x),
            ExampleAttribute::Business(b) => write!(f, "(Business, {})", b),
        }
    }
}

/// Show the type of the attribute. Used to display the option to the user when
/// selecting the attribute list type.
fn show_example_attribute_type(att: &ExampleAttribute, f: &mut fmt::Formatter) -> fmt::Result {
    match att {
        ExampleAttribute::Age(_) => write!(f, "Age"),
        ExampleAttribute::Citizenship(_) => write!(f, "Citizenship"),
        ExampleAttribute::MaxAccount(_) => write!(f, "MaxAccount"),
        ExampleAttribute::Business(_) => write!(f, "Business"),
    }
}

/// Show fields of the type of fields of the given attribute list.
fn show_attribute_format(variant: u32) -> &'static str {
    match variant {
        0 => "[MaxAccount, Age]",
        1 => "[MaxAccount, Age, Citizenship, Business]",
        _ => unimplemented!("Only two formats of attribute lists supported."),
    }
}

fn read_attribute_list(variant: u32) -> io::Result<Vec<ExampleAttribute>> {
    match variant {
        0 => {
            let max_acc = Input::new()
                .with_prompt("Choose maximum number of accounts")
                .interact()?;
            let age = Input::new().with_prompt("Your age").interact()?;
            Ok(vec![
                ExampleAttribute::MaxAccount(max_acc),
                ExampleAttribute::Age(age),
            ])
        }
        1 => {
            let max_acc = Input::new()
                .with_prompt("Choose maximum number of accounts")
                .interact()?;
            let age = Input::new().with_prompt("Your age").interact()?;
            let citizenship = Input::new().with_prompt("Citizenship").interact()?; // TODO: use drop-down/select with
            let business = Input::new().with_prompt("Are you a business").interact()?;
            Ok(vec![
                ExampleAttribute::MaxAccount(max_acc),
                ExampleAttribute::Age(age),
                ExampleAttribute::Citizenship(citizenship),
                ExampleAttribute::Business(business),
            ])
        }
        _ => panic!("This should not be reachable. Precondition violated."),
    }
}

fn write_json_to_file(filepath: &str, js: &Value) -> io::Result<()> {
    let path = Path::new(filepath);
    let mut file = File::create(&path)?;
    file.write_all(to_string_pretty(js).unwrap().as_bytes())
}

/// Output json to standard output.
fn output_json(js: &Value) -> () {
    println!("{}", to_string_pretty(js).unwrap());
}

fn read_json_from_file<P: AsRef<Path>>(path: P) -> io::Result<Value> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let u = serde_json::from_reader(reader)?;
    Ok(u)
}

fn json_base16_encode(v: &[u8]) -> Value { json!(encode(v)) }

fn json_base16_decode(v: &Value) -> Option<Vec<u8>> { decode(v.as_str()?).ok() }

fn chi_to_json<P: Pairing>(chi: &CredentialHolderInfo<P>) -> Value {
    json!({
        "name": chi.id_ah,
        "idCredPublic": encode(chi.id_cred.id_cred_pub.to_bytes()),
        "idCredSecret": encode(chi.id_cred.id_cred_sec.to_bytes()),
    })
}

fn json_to_chi<P: Pairing>(js: &Value) -> Option<CredentialHolderInfo<P>> {
    let id_cred_pub =
        elgamal::PublicKey::<P::G_2>::from_bytes(&json_base16_decode(&js["idCredPublic"])?).ok()?;
    let id_cred_sec =
        elgamal::SecretKey::<P::G_2>::from_bytes(&json_base16_decode(&js["idCredSecret"])?).ok()?;
    let id_ah = js["name"].as_str()?;
    let info: CredentialHolderInfo<P> = CredentialHolderInfo {
        id_ah:   id_ah.to_owned(),
        id_cred: IdCredentials {
            id_cred_pub,
            id_cred_sec,
        },
    };
    Some(info)
}

fn alist_to_json(
    alist: &AttributeList<<Bls12 as Pairing>::ScalarField, ExampleAttribute>,
) -> Value {
    let alist_vec: Vec<String> = alist.alist.iter().map(|x| x.to_string()).collect();
    json!({
        "variant": alist.variant,
        "items": alist_vec
    })
}

fn aci_to_json(aci: &AccCredentialInfo<Bls12, ExampleAttribute>) -> Value {
    let chi = chi_to_json(&aci.acc_holder_info);
    json!({
        "credentialHolderInformation": chi,
        "prfKey": json_base16_encode(&aci.prf_key.to_bytes()),
        "attributes": alist_to_json(&aci.attributes),
    })
}

// fn json_to_aci<P: Pairing>(js: &Value) -> Option<CredentialHolderInfo<P>> {
//     let id_cred_pub =
//         elgamal::PublicKey::<P::G_2>::from_bytes(&json_base16_decode(&js["
// idCredPublic"])?).ok()?;     let id_cred_sec =
//         elgamal::SecretKey::<P::G_2>::from_bytes(&json_base16_decode(&js["
// idCredSecret"])?).ok()?;     let id_ah = js["name"].as_str()?;
//     let info: CredentialHolderInfo<P> = CredentialHolderInfo {
//         id_ah:   id_ah.to_owned(),
//         id_cred: IdCredentials {
//             id_cred_pub,
//             id_cred_sec,
//         },
//     };
//     Some(info)
// }

fn main() {
    let matches = App::new("Prototype client showcasing ID layer interactions.")
        .version("0.123456")
        .author("Concordium")
        .subcommand(
            SubCommand::with_name("create_chi")
                .about("Create new credential holder information.")
                .arg(
                    Arg::with_name("file")
                        .long("file")
                        .value_name("FILE")
                        .short("f")
                        .help("write generated credential holder information to file"),
                ),
        )
        .subcommand(
            SubCommand::with_name("start_ip")
                .about("Generate data to send to the identity provider to sign and verify.")
                .arg(
                    Arg::with_name("chi")
                        .long("chi")
                        .value_name("FILE")
                        .help("File with input credential holder information.")
                        .required(true),
                )
                .arg(
                    Arg::with_name("private")
                        .long("private")
                        .value_name("FILE")
                        .help("File to write the private ACI data to."),
                )
                .arg(
                    Arg::with_name("public")
                        .long("public")
                        .value_name("FILE")
                        .help("File to write the public data to be sent to the identity provider."),
                ),
        )
        .get_matches();
    if let Some(matches) = matches.subcommand_matches("create_chi") {
        if let Ok(name) = Input::new().with_prompt("Your name").interact() {
            let mut csprng = thread_rng();
            let secret = SecretKey::generate(&mut csprng);
            let public = PublicKey::from(&secret);
            let ah_info = CredentialHolderInfo::<Bls12> {
                id_ah:   name,
                id_cred: IdCredentials {
                    id_cred_sec: secret,
                    id_cred_pub: public,
                },
            };
            let js = chi_to_json(&ah_info);
            if let Some(filepath) = matches.value_of("file") {
                match write_json_to_file(filepath, &js) {
                    Ok(()) => println!("Wrote CHI to file."),
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
    if let Some(matches) = matches.subcommand_matches("start_ip") {
        let path = Path::new(matches.value_of("chi").unwrap());
        if let Ok(v) = read_json_from_file(&path) {
            if let Some(chi) = json_to_chi::<Bls12>(&v) {
                let mut csprng = thread_rng();
                let prf_key = prf::SecretKey::generate(&mut csprng);
                let alist_type = Select::new()
                    .with_prompt("Select attribute list type:")
                    .item(&show_attribute_format(0))
                    .item(&show_attribute_format(1))
                    .default(0)
                    .interact();
                if let Ok(alist_type) = alist_type {
                    if let Ok(alist) = read_attribute_list(alist_type as u32) {
                        let aci = AccCredentialInfo {
                            acc_holder_info: chi,
                            prf_key,
                            attributes: AttributeList::<
                                <Bls12 as Pairing>::ScalarField,
                                ExampleAttribute,
                            > {
                                variant: 0,
                                alist,
                                _phantom: Default::default(),
                            },
                        };
                        output_json(&aci_to_json(&aci));
                    } else {
                        println!("You have to choose an attribute list. Terminating.");
                    }
                } else {
                    println!("You have to choose an attribute list. Terminating.");
                }
            } else {
                println!("Could not parse credential holder information.");
            }
        } else {
            println!("Could not read credential holder information.");
        }
    }
}
