use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};

use eddsa_ed25519 as ed25519;
use id::secret_sharing::*;

use crypto_common::*;

use std::collections::btree_map::BTreeMap;

use curve_arithmetic::{Curve, Pairing};
use dialoguer::{Checkboxes, Input, Select};
use dodis_yampolskiy_prf::secret as prf;
use elgamal::{message::Message, public::PublicKey, secret::SecretKey};
use hex::encode;
use id::{account_holder::*, ffi::*, identity_provider::*, types::*};
use pairing::bls12_381::Bls12;
use ps_sig;

use rand::*;
use serde_json::{json, Value};

use pedersen_scheme::{CommitmentKey, Value as PedersenValue};

use std::{
    cmp::max,
    fs::File,
    io::{self, Error, ErrorKind, Write},
    path::Path,
    str::FromStr,
};

use either::Either::Left;

use client_server_helpers::*;

static IP_PREFIX: &str = "database/identity_provider-";
static IP_NAME_PREFIX: &str = "identity_provider-";
static AR_NAME_PREFIX: &str = "anonymity_revoker-";

fn mk_ip_filename(n: usize) -> String {
    let mut s = IP_PREFIX.to_string();
    s.push_str(&n.to_string());
    s.push_str(".json");
    s
}

fn mk_ip_name(n: usize) -> String {
    let mut s = IP_NAME_PREFIX.to_string();
    s.push_str(&n.to_string());
    s
}

fn mk_ar_filename(m: usize, n: usize) -> String {
    let mut s = IP_PREFIX.to_string();
    s.push_str(&m.to_string());
    s.push_str("_");
    s.push_str(&AR_NAME_PREFIX.to_string());
    // let mut s = AR_PREFIX.to_string();
    s.push_str(&n.to_string());
    s.push_str(".json");
    s
}

fn mk_ar_name(n: usize) -> String {
    let mut s = AR_NAME_PREFIX.to_string();
    s.push_str(&n.to_string());
    s
}

/// Reads the expiry date. Only the day, the expiry time is set at the end of
/// that day.
fn read_expiry_date() -> io::Result<u64> {
    let input: String = Input::new().with_prompt("Expiry date").interact()?;
    parse_expiry_date(&input)
}

/// Given the chosen variant of the attribute list read off the fields from user
/// input. Fails if the user input is not well-formed.
fn read_attribute_list(variant: u16) -> io::Result<Vec<ExampleAttribute>> {
    let mut res = Vec::with_capacity(ATTRIBUTE_LISTS[variant as usize].len());
    for key in ATTRIBUTE_LISTS[variant as usize] {
        let input: String = Input::new().with_prompt(key).interact()?;
        // NB: The index of an attribute must be the same as the one returned in
        // attribute_index. Otherwise there will be strange issues, very likely.
        res.push(
            AttributeKind::from_str(&input).map_err(|e| Error::new(ErrorKind::InvalidData, e))?,
        );
    }
    Ok(res)
}

fn main() {
    let app = App::new("Prototype client showcasing ID layer interactions.")
        .version("0.36787944117")
        .author("Concordium")
        .setting(AppSettings::ArgRequiredElseHelp)
        .global_setting(AppSettings::ColoredHelp)
        .subcommand(
            SubCommand::with_name("create-chi")
                .about("Create new credential holder information.")
                .arg(
                    Arg::with_name("out")
                        .long("out")
                        .value_name("FILE")
                        .short("o")
                        .help("write generated credential holder information to file"),
                ),
        )
        .subcommand(
            SubCommand::with_name("start-ip")
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
        .subcommand(
            SubCommand::with_name("generate-ips")
                .about("Generate given number of identity providers. Public and private keys.")
                .arg(
                    Arg::with_name("num")
                        .long("num")
                        .value_name("N")
                        .short("n")
                        .help("number of identity providers to generate"),
                ),
        )
        .subcommand(
            SubCommand::with_name("generate-global")
                .about("Generate the global context of parameters."),
        )
        .subcommand(
            SubCommand::with_name("ip-sign-pio")
                .about("Act as the identity provider, checking and signing a pre-identity object.")
                .arg(
                    Arg::with_name("pio")
                        .long("pio")
                        .value_name("FILE")
                        .help("File with input pre-identity object information.")
                        .required(true),
                )
                .arg(
                    Arg::with_name("ip-data")
                        .long("ip-data")
                        .value_name("FILE")
                        .help(
                            "File with all information about the identity provider (public and \
                             private).",
                        )
                        .required(true),
                )
                .arg(
                    Arg::with_name("out")
                        .long("out")
                        .short("o")
                        .value_name("FILE")
                        .help("File to write the signed identity object to."),
                ),
        )
        .subcommand(
            SubCommand::with_name("deploy-credential")
                .about(
                    "Take the identity object, select attributes to reveal and create a \
                     credential object to deploy on chain.",
                )
                .arg(
                    Arg::with_name("id-object")
                        .long("id-object")
                        .short("i")
                        .value_name("FILE")
                        .required(true)
                        .help("File with the JSON encoded identity object."),
                )
                .arg(
                    Arg::with_name("private")
                        .long("private")
                        .short("c")
                        .value_name("FILE")
                        .required(true)
                        .help(
                            "File with private credential holder information used to generate the \
                             identity object.",
                        ),
                )
                .arg(
                    Arg::with_name("account")
                        .long("account")
                        .short("a")
                        .value_name("FILE")
                        .help(
                            "File with existing account private info (verification and signature \
                             keys).
If not present a fresh key-pair will be generated.",
                        ),
                )
                .arg(
                    Arg::with_name("bin-out")
                        .long("bin-out")
                        .value_name("FILE")
                        .help("File to output the binary transaction payload to."),
                )
                .arg(
                    Arg::with_name("out")
                        .long("out")
                        .value_name("FILE")
                        .help("File to output the JSON transaction payload to."),
                ),
        )
        .subcommand(
            SubCommand::with_name("revoke-anonymity")
                .about("Take a deployed credential and determine who it belongs to.")
                .arg(
                    Arg::with_name("credential")
                        .long("credential")
                        .short("c")
                        .value_name("FILE")
                        .required(true)
                        .help("File with the JSON encoded credential."),
                )
                .arg(
                    Arg::with_name("ar-private")
                        .long("ar-private")
                        .short("a")
                        .multiple(true)
                        .value_name("FILE(S)")
                        .required(true)
                        .help("File with anonymity revoker's private and public keys."),
                ),
        );
    let matches = app.get_matches();
    let exec_if = |x: &str| matches.subcommand_matches(x);
    exec_if("create-chi").map(handle_create_chi);
    exec_if("start-ip").map(handle_start_ip);
    exec_if("generate-ips").map(handle_generate_ips);
    exec_if("generate-global").map(handle_generate_global);
    exec_if("ip-sign-pio").map(handle_act_as_ip);
    exec_if("deploy-credential").map(handle_deploy_credential);
    exec_if("revoke-anonymity").map(handle_revoke_anonymity);
}

/// Revoke the anonymity of the credential.
fn handle_revoke_anonymity(matches: &ArgMatches) {
    let v: Value = match matches.value_of("credential").map(read_json_from_file) {
        Some(Ok(r)) => r,
        Some(Err(x)) => {
            eprintln!("Could not read credential because {}", x);
            return;
        }
        None => panic!("Should not happen since the argument is mandatory."),
    };
    let revocation_threshold = match v.as_object() {
        None => panic!("could not read credential object"),
        Some(s) => match json_read_u64(s, "revocationThreshold") {
            None => panic!("could not read revocation threshold"),
            Some(r) => r,
        },
    };
    // let revocation_threshold = json_read_u64(v.as_object(),
    // "revocationThreshold")?;
    let ar_data = match v.get("arData").and_then(json_to_chain_ar_data) {
        Some(ar_data) => ar_data,
        None => {
            eprintln!("Could not parse anonymity revocation data.");
            return;
        }
    };

    let ar_values: Vec<_> = match matches.values_of("ar-private") {
        Some(v) => v.collect(),
        None => panic!("Could not read ar-private"),
    };
    let mut ars = vec![];
    for ar_value in ar_values.iter() {
        match read_json_from_file(ar_value) {
            Err(y) => panic!("Could not read from ar file {} {}", ar_value, y),
            Ok(val) => match json_to_private_ar_info(&val) {
                Some(p) => ars.push(p),
                None => {
                    eprintln!("Could not decode the JSON object with private AR data.");
                    return;
                }
            },
        }
    }

    let number_of_ars = ars.len();
    if (number_of_ars as u64) < revocation_threshold {
        eprintln!(
            "insufficient number of anonymity revokers {}, {}",
            number_of_ars, revocation_threshold
        );
        return;
    }
    let mut shares = Vec::with_capacity(ars.len());

    for (ar, private) in ars.into_iter() {
        match ar_data.iter().find(|&x| x.ar_identity == ar.ar_identity) {
            None => {
                eprintln!("AR is not part of the credential");
                return;
            }
            Some(single_ar_data) => {
                let Message { value: m } = private.decrypt(&single_ar_data.enc_id_cred_pub_share);
                shares.push((single_ar_data.id_cred_pub_share_number, m))
            }
        }
    }
    let id_cred_pub = reveal_in_group(&shares);
    println!(
        "IdCredPub of the credential owner is {}",
        encode(&to_bytes(&id_cred_pub))
    );
    println!(
        "Contact the identity provider with this information to get the real-life identity of the \
         user."
    );
}

/// Read the identity object, select attributes to reveal and create a
/// transaction.
fn handle_deploy_credential(matches: &ArgMatches) {
    // we read the signed identity object
    // signature of the identity object and the pre-identity object itself.
    let v = match matches.value_of("id-object").map(read_json_from_file) {
        Some(Ok(v)) => v,
        Some(Err(x)) => {
            eprintln!("Could not read identity object because {}", x);
            return;
        }
        None => panic!("Should not happen since the argument is mandatory."),
    };
    // we first read the signed pre-identity object
    let (ip_sig, pio, ip_info): (ps_sig::Signature<Bls12>, _, _) = {
        if let Some(v) = v.as_object() {
            match v.get("signature").and_then(json_base16_decode) {
                None => {
                    eprintln!("failed to parse signature");
                    return;
                }
                Some(sig) => match v.get("preIdentityObject").and_then(json_to_pio) {
                    None => {
                        eprintln!("failed to parse pio");
                        return;
                    }
                    Some(pio) => match v.get("ipInfo").and_then(IpInfo::from_json) {
                        None => {
                            eprintln!("failed to parse ip info");
                            return;
                        }
                        Some(ip_info) => (sig, pio, ip_info),
                    },
                },
            }
        } else {
            eprintln!("Could not parse JSON.");
            return;
        }
    };

    // we also read the global context from another json file (called
    // global.context). We need commitment keys and other data in there.
    let global_ctx = {
        if let Some(gc) = read_global_context(GLOBAL_CONTEXT) {
            gc
        } else {
            eprintln!("Cannot read global context information database. Terminating.");
            return;
        }
    };

    // now we have all the data ready.
    // we first ask the user to select which credentials they wish to reveal
    let alist = &pio.alist.alist;
    let mut alist_str: Vec<String> = Vec::with_capacity(alist.len());
    for (idx, a) in alist.iter().enumerate() {
        alist_str.push(show_attribute(pio.alist.variant, idx, a));
    }
    // the interface of checkboxes is less than ideal.
    let alist_items: Vec<&str> = alist_str.iter().map(String::as_str).collect();
    let atts: Vec<usize> = match Checkboxes::new()
        .with_prompt("Select which attributes you wish to reveal")
        .items(&alist_items)
        .interact()
    {
        Ok(idxs) => idxs,
        Err(x) => {
            eprintln!("You need to select which attributes you want. {}", x);
            return;
        }
    };

    // from the above and the pre-identity object we make a policy
    let mut revealed_attributes = BTreeMap::new();
    for idx in atts {
        revealed_attributes.insert(idx as u16, alist[idx]);
    }
    let policy = Policy {
        variant:    pio.alist.variant,
        expiry:     pio.alist.expiry,
        policy_vec: revealed_attributes,
        _phantom:   Default::default(),
    };

    // We now generate or read account verification/signature key pair.
    let mut known_acc = false;
    let acc_data = {
        if let Some(acc_data) = matches.value_of("account").and_then(read_account_data) {
            known_acc = true;
            acc_data
        } else {
            let mut keys = BTreeMap::new();
            keys.insert(KeyIndex(0), ed25519::generate_keypair());
            keys.insert(KeyIndex(1), ed25519::generate_keypair());
            keys.insert(KeyIndex(2), ed25519::generate_keypair());

            AccountData {
                keys,
                existing: Left(SignatureThreshold(2)),
            }
        }
    };

    if !known_acc {
        println!(
            "Generated fresh verification and signature key of the account to file \
             account_keys.json"
        );
        write_json_to_file("account_keys.json", &acc_data.to_json()).ok();
    }

    // finally we also read the credential holder information with secret keys
    // which we need to generate CDI.
    // This file should also contain the public keys of the identity provider who
    // signed the object.
    let private_value = match read_json_from_file(
        matches
            .value_of("private")
            .expect("Should not happen because argument is mandatory."),
    ) {
        Ok(v) => v,
        Err(x) => {
            eprintln!("Could not read CHI object because {}", x);
            return;
        }
    };
    let aci = match private_value.get("aci").and_then(json_to_aci) {
        Some(aci) => aci,
        None => {
            eprintln!("Could not read ACI.");
            return;
        }
    };
    let randomness = match private_value.get("randomness").and_then(json_base16_decode) {
        Some(rand) => rand,
        None => {
            eprintln!("Could not read randomness used to generate pre-identity object.");
            return;
        }
    };
    // We ask what regid index they would like to use.
    let x = match Input::new().with_prompt("Index").interact() {
        Ok(x) => x,
        Err(_) => 0, // default index
    };

    // Now we have have everything we need to generate the proofs
    // we have
    // - chi
    // - pio
    // - ip_info
    // - signature of the identity provider
    // - acc_data of the account onto which we are deploying this credential
    //   (private and public)

    let cdi = generate_cdi(
        &ip_info,
        &global_ctx,
        &aci,
        &pio,
        x,
        &ip_sig,
        &policy,
        &acc_data,
        &randomness,
    );

    // Double check that the generated CDI is going to be successfully validated.
    // let checked = verify_cdi(&global_ctx, &ip_info, &cdi);
    // if let Err(e) = checked {
    //     eprintln!(
    //         "Something went terribly wrong and the generated CDI is not valid
    // because {}",         e
    //     );
    //     return;
    // };

    // Now simply output the credential object in the transaction format
    // accepted by the simple-client for sending transactions.

    let js = cdi.to_json();

    if let Some(json_file) = matches.value_of("out") {
        match write_json_to_file(json_file, &js) {
            Ok(_) => println!("Wrote transaction payload to JSON file."),
            Err(e) => {
                eprintln!("Could not JSON write to file because {}", e);
                output_json(&js);
            }
        }
    }
    if let Some(bin_file) = matches.value_of("bin-out") {
        match File::create(&bin_file) {
            // This is a bit stupid, we should write directly to the sink.
            Ok(mut file) => match file.write_all(&to_bytes(&cdi)) {
                Ok(_) => println!("Wrote binary data to provided file."),
                Err(e) => {
                    eprintln!("Could not write binary to file because {}", e);
                }
            },
            Err(e) => {
                eprintln!("Could not write binary to file because {}", e);
            }
        }
    }
}

fn read_account_data<P: AsRef<Path>>(path: P) -> Option<AccountData>
where
    P: std::fmt::Debug, {
    let v = read_json_from_file(path).ok()?;
    Some(AccountData::from_json(&v)?)
}

/// Create a new CHI object (essentially new idCredPub and idCredSec).
fn handle_create_chi(matches: &ArgMatches) {
    let name = {
        if let Ok(name) = Input::new().with_prompt("Your name").interact() {
            name
        } else {
            eprintln!("You need to provide a name. Terminating.");
            return;
        }
    };

    let mut csprng = thread_rng();
    let secret = ExampleCurve::generate_scalar(&mut csprng);
    let ah_info = CredentialHolderInfo::<ExampleCurve> {
        id_ah:   name,
        id_cred: IdCredentials {
            id_cred_sec: PedersenValue { value: secret },
        },
    };

    let js = chi_to_json(&ah_info);
    if let Some(filepath) = matches.value_of("out") {
        match write_json_to_file(filepath, &js) {
            Ok(()) => println!("Wrote CHI to file."),
            Err(_) => {
                eprintln!("Could not write to file. The generated information is");
                output_json(&js);
            }
        }
    } else {
        println!("Generated account holder information.");
        output_json(&js)
    }
}

/// Act as the identity provider. Read the pre-identity object and load the
/// private information of the identity provider, check and sign the
/// pre-identity object to generate the identity object to send back to the
/// account holder.
fn handle_act_as_ip(matches: &ArgMatches) {
    let pio_path = Path::new(matches.value_of("pio").unwrap());
    let pio = match read_json_from_file(&pio_path).as_ref().map(json_to_pio) {
        Ok(Some(pio)) => pio,
        Ok(None) => {
            eprintln!("Could not parse PIO JSON.");
            return;
        }
        Err(e) => {
            eprintln!("Could not read file because {}", e);
            return;
        }
    };
    let ip_data_path = Path::new(matches.value_of("ip-data").unwrap());
    let (ip_info, ip_sec_key) = match read_json_from_file(&ip_data_path)
        .as_ref()
        .map(json_to_ip_data)
    {
        Ok(Some((ip_info, ip_sec_key))) => (ip_info, ip_sec_key),
        Ok(None) => {
            eprintln!("Could not parse identity issuer JSON.");
            return;
        }
        Err(x) => {
            eprintln!("Could not read identity issuer information because {}", x);
            return;
        }
    };

    let vf = verify_credentials(&pio, &ip_info, &ip_sec_key);
    match vf {
        Ok(sig) => {
            println!("Successfully checked pre-identity data.");
            if let Some(signed_out_path) = matches.value_of("out") {
                let js = json!({
                    "preIdentityObject": pio_to_json(&pio),
                    "signature": json_base16_encode(&sig),
                    "ipInfo": IpInfo::to_json(&ip_info)
                });
                if write_json_to_file(signed_out_path, &js).is_ok() {
                    println!("Wrote signed identity object to file.");
                } else {
                    println!(
                        "Could not write Identity object to file. The signature is: {}",
                        json_base16_encode(&sig)
                    );
                }
            } else {
                println!("The signature is: {}", json_base16_encode(&sig));
            }
        }
        Err(r) => eprintln!("Could not verify pre-identity object {:?}", r),
    }
}

fn handle_start_ip(matches: &ArgMatches) {
    let path = Path::new(matches.value_of("chi").unwrap());
    let chi = {
        if let Ok(Some(chi)) = read_json_from_file(&path)
            .as_ref()
            .map(json_to_chi::<ExampleCurve>)
        {
            chi
        } else {
            eprintln!("Could not read credential holder information.");
            return;
        }
    };
    let mut csprng = thread_rng();
    let prf_key = prf::SecretKey::generate(&mut csprng);
    let alists: Vec<String> = ATTRIBUTE_LISTS
        .iter()
        .map(|alist| alist.join(", "))
        .collect();
    let alist_type = {
        match Select::new()
            .with_prompt("Select attribute list type:")
            .items(&alists)
            .default(0)
            .interact()
        {
            Ok(alist_type) => alist_type,
            Err(x) => {
                eprintln!("You have to choose an attribute list. Terminating. {}", x);
                return;
            }
        }
    };
    let expiry_date = match read_expiry_date() {
        Ok(expiry_date) => expiry_date,
        Err(e) => {
            eprintln!("Could not read credential expiry date because {}", e);
            return;
        }
    };
    let alist = {
        match read_attribute_list(alist_type as u16) {
            Ok(alist) => alist,
            Err(x) => {
                eprintln!("Could not read the attribute list because of: {}", x);
                return;
            }
        }
    };
    // the chosen account credential information
    let aci = AccCredentialInfo {
        acc_holder_info: chi,
        prf_key,
        attributes: AttributeList::<<Bls12 as Pairing>::ScalarField, ExampleAttribute> {
            variant: alist_type as u16,
            expiry: expiry_date,
            alist,
            _phantom: Default::default(),
        },
    };

    // now choose an identity provider.
    let ips = {
        if let Some(ips) = read_identity_providers() {
            ips
        } else {
            eprintln!("Cannot read identity providers from the database. Terminating.");
            return;
        }
    };

    // names of identity providers the user can choose from, together with the
    // names of anonymity revokers associated with them
    let mut ips_names = Vec::with_capacity(ips.len());
    for x in ips.iter() {
        ips_names.push(format!(
            "Identity provider {}, {}",
            &x.ip_identity, x.ip_description
        ))
    }

    let ip_info = {
        if let Ok(ip_info_idx) = Select::new()
            .with_prompt("Choose identity provider")
            .items(&ips_names)
            .default(0)
            .interact()
        {
            ips[ip_info_idx].clone()
        } else {
            eprintln!("You have to choose an identity provider. Terminating.");
            return;
        }
    };

    let ar_handles = ip_info.ar_info.0.clone();
    let mrs: Vec<&str> = ar_handles
        .iter()
        .map(|x| x.ar_description.as_str())
        .collect();

    let mut choice_ars = vec![];

    let ar_info = Checkboxes::new()
        .with_prompt("Choose anonymity revokers")
        .items(&mrs)
        .interact()
        .unwrap();
    let num_ars = ar_info.len();
    if ar_info.is_empty() {
        eprintln!("You need to select AR");
        return;
    }
    for idx in ar_info.into_iter() {
        choice_ars.push(ar_handles[idx].ar_identity);
    }

    let threshold = {
        if let Ok(threshold) = Select::new()
            .with_prompt("Revocation threshold")
            .items(&(1..=num_ars).collect::<Vec<usize>>())
            .default(1)
            .interact()
        {
            Threshold((threshold + 1) as u32) // +1 because the indexing of the
                                              // selection starts at 1
        } else {
            let d = max(1, num_ars - 1);
            println!(
                "Selecting default value (= {}) for revocation threshold.",
                d
            );
            Threshold(d as u32)
        }
    };

    let context = make_context_from_ip_info(ip_info, (choice_ars, threshold));
    // and finally generate the pre-identity object
    // we also retrieve the randomness which we must keep private.
    // This randomness must be used
    let (pio, randomness) = generate_pio(&context, &aci);

    // the only thing left is to output all the information

    let aci_js = aci_to_json(&aci);
    let js = json!({
        "aci": aci_js,
        "randomness": json_base16_encode(&randomness)
    });
    if let Some(aci_out_path) = matches.value_of("private") {
        if write_json_to_file(aci_out_path, &js).is_ok() {
            println!("Wrote ACI and randomness to file.");
        } else {
            println!("Could not write ACI data to file. Outputting to standard output.");
            output_json(&js);
        }
    } else {
        output_json(&js);
    }

    let js = pio_to_json(&pio);
    if let Some(pio_out_path) = matches.value_of("public") {
        if write_json_to_file(pio_out_path, &js).is_ok() {
            println!("Wrote PIO data to file.");
        } else {
            println!("Could not write PIO data to file. Outputting to standard output.");
            output_json(&js);
        }
    } else {
        output_json(&js);
    }
}

fn ar_info_to_json<C: Curve>(ar_info: &ArInfo<C>) -> Value {
    json!({
        "arIdentity": ar_info.ar_identity.to_json(),
        "arDescription": ar_info.ar_description.clone(),
        "arPublicKey": json_base16_encode(&ar_info.ar_public_key),
        //"arElgamalGenerator": json_base16_encode(&ar_info.ar_elgamal_generator.curve_to_bytes())
    })
}

fn json_to_private_ar_info<C: Curve>(v: &Value) -> Option<(ArInfo<C>, SecretKey<C>)> {
    let v = v.as_object()?;
    let public = v.get("publicArInfo")?;
    let ar_identity = ArIdentity::from_json(public.get("arIdentity")?)?;
    let ar_description = public.get("arDescription")?.as_str()?.to_owned();
    let ar_public_key = public.get("arPublicKey").and_then(json_base16_decode)?;
    let private = v.get("arPrivateKey").and_then(json_base16_decode)?;
    Some((
        ArInfo {
            ar_identity,
            ar_description,
            ar_public_key,
            // ar_elgamal_generator,
        },
        private,
    ))
}

/// Generate identity providers with public and private information as well as
/// anonymity revokers. For now we generate identity providers with names
/// IP_PREFIX-i.json and its associated anonymity revoker has name
/// AR_PRFEFIX-i.json.
fn handle_generate_ips(matches: &ArgMatches) -> Option<()> {
    let mut csprng = thread_rng();
    let num: usize = matches.value_of("num").unwrap_or("10").parse().ok()?;
    println!("generating {} IPs", num);
    let mut res = Vec::with_capacity(num);
    for id in 0..num {
        // generate an identity provider and for each
        // identity provider three anonymity revokers
        let ip_fname = mk_ip_filename(id);
        let ar0_fname = mk_ar_filename(id, 0);
        let ar1_fname = mk_ar_filename(id, 1);
        let ar2_fname = mk_ar_filename(id, 2);

        // TODO: hard-coded length of the key for now, but should be changed
        // based on the maximum length of the attribute list
        let id_secret_key = ps_sig::secret::SecretKey::generate(20, &mut csprng);
        let id_public_key = ps_sig::public::PublicKey::from(&id_secret_key);

        let ar_base = ExampleCurve::generate(&mut csprng);

        let ar0_secret_key = SecretKey::generate(&ar_base, &mut csprng);
        let ar0_public_key = PublicKey::from(&ar0_secret_key);
        let ar0_info = ArInfo {
            ar_identity:    ArIdentity(0u32),
            ar_description: mk_ar_name(0),
            ar_public_key:  ar0_public_key,
        };

        let js0 = ar_info_to_json(&ar0_info);
        let private_js0 = json!({
            "arPrivateKey": json_base16_encode(&ar0_secret_key),
            "publicArInfo": js0
        });

        let ar1_secret_key = SecretKey::generate(&ar_base, &mut csprng);
        let ar1_public_key = PublicKey::from(&ar1_secret_key);
        let ar1_info = ArInfo {
            ar_identity:    ArIdentity(1u32),
            ar_description: mk_ar_name(1),
            ar_public_key:  ar1_public_key,
            // ar_elgamal_generator: PublicKey::generator(),
        };

        let js1 = ar_info_to_json(&ar1_info);
        let private_js1 = json!({
            "arPrivateKey": json_base16_encode(&ar1_secret_key),
            "publicArInfo": js1
        });

        let ar2_secret_key = SecretKey::generate(&ar_base, &mut csprng);
        let ar2_public_key = PublicKey::from(&ar2_secret_key);
        let ar2_info = ArInfo {
            ar_identity:    ArIdentity(2u32),
            ar_description: mk_ar_name(2),
            ar_public_key:  ar2_public_key,
            // ar_elgamal_generator: PublicKey::generator(),
        };

        let js2 = ar_info_to_json(&ar2_info);
        let private_js2 = json!({
              "arPrivateKey": json_base16_encode(&ar2_secret_key),
              "publicArInfo": js2
        });

        write_json_to_file(&ar0_fname, &private_js0).ok()?;
        write_json_to_file(&ar1_fname, &private_js1).ok()?;
        write_json_to_file(&ar2_fname, &private_js2).ok()?;

        let ip_info = IpInfo {
            ip_identity: IpIdentity(id as u32),
            ip_description: mk_ip_name(id),
            ip_verify_key: id_public_key,
            ar_info: (
                vec![ar0_info, ar1_info, ar2_info],
                CommitmentKey::<ExampleCurve>::generate(&mut csprng),
            ),
            ar_base,
        };
        let js = ip_info.to_json();
        let private_js = json!({
            "idPrivateKey": json_base16_encode(&id_secret_key),
            "publicIdInfo": js
        });
        println!("writing ip_{} in file {}", id, ip_fname);
        write_json_to_file(&ip_fname, &private_js).ok()?;

        res.push(ip_info);
    }
    write_json_to_file(IDENTITY_PROVIDERS, &ip_infos_to_json(&res)).ok()?;
    Some(())
}

/// Generate the global context.
fn handle_generate_global(_matches: &ArgMatches) -> Option<()> {
    let mut csprng = thread_rng();
    let gc = GlobalContext::<ExampleCurve> {
        // we generate the commitment key for 1 value only.
        // Since the scheme supports general vectors of values this is inefficient
        // but is OK for now.
        // The reason we only need 1 value is that we commit to each value separately
        // in the attribute list. This is so that we can reveal items individually.
        on_chain_commitment_key: CommitmentKey::generate(&mut csprng),
    };
    write_json_to_file(GLOBAL_CONTEXT, &gc.to_json()).ok()
}
