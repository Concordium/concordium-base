use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};

use ed25519_dalek as ed25519;
use id::secret_sharing::*;

use crypto_common::*;

use std::collections::btree_map::BTreeMap;

use curve_arithmetic::Curve;
use dialoguer::{Checkboxes, Input, Select};
use dodis_yampolskiy_prf::secret as prf;
use elgamal::{message::Message, public::PublicKey, secret::SecretKey};
use hex::encode;
use id::{account_holder::*, identity_provider::*, types::*};
use pairing::bls12_381::Bls12;
use ps_sig;

use rand::*;

use pedersen_scheme::{CommitmentKey, Value as PedersenValue};

use std::{
    cmp::max,
    convert::TryFrom,
    fs::File,
    io::{self, Write},
    path::Path,
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

fn mk_ip_filename_pub(n: usize) -> String {
    let mut s = IP_PREFIX.to_string();
    s.push_str(&n.to_string());
    s.push_str(".pub.json");
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
                    Arg::with_name("ip-info")
                        .long("ip-info")
                        .value_name("FILE")
                        .required(true)
                        .help(
                            "File with the JSON encoded information about the identity provider.",
                        ),
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
    let credential: CredDeploymentInfo<Bls12, ExampleCurve, ExampleAttribute> =
        match matches.value_of("credential").map(read_json_from_file) {
            Some(Ok(r)) => r,
            Some(Err(x)) => {
                eprintln!("Could not read credential because {}", x);
                return;
            }
            None => panic!("Should not happen since the argument is mandatory."),
        };
    let revocation_threshold = credential.values.threshold;

    let ar_data = credential.values.ar_data;

    // A list of filenames with private info from anonymity revokers.
    let ar_values: Vec<_> = match matches.values_of("ar-private") {
        Some(v) => v.collect(),
        None => panic!("Could not read ar-private"),
    };
    let mut ars: Vec<ArData<ExampleCurve>> = Vec::with_capacity(ar_values.len());
    for ar_value in ar_values.iter() {
        match read_json_from_file(ar_value) {
            Err(y) => {
                eprintln!("Could not read from ar file {} {}", ar_value, y);
                return;
            }
            Ok(val) => ars.push(val),
        }
    }

    let number_of_ars = ars.len();
    let number_of_ars = u32::try_from(number_of_ars)
        .expect("Number of anonymity revokers should not exceed 2^32-1");
    if number_of_ars < revocation_threshold.into() {
        eprintln!(
            "insufficient number of anonymity revokers {}, {:?}",
            number_of_ars, revocation_threshold
        );
        return;
    }
    let mut shares = Vec::with_capacity(ars.len());

    for ar in ars.into_iter() {
        match ar_data
            .iter()
            .find(|&x| x.ar_identity == ar.public_ar_info.ar_identity)
        {
            None => {
                eprintln!("AR is not part of the credential");
                return;
            }
            Some(single_ar_data) => {
                let Message { value: m } = ar
                    .ar_private_key
                    .decrypt(&single_ar_data.enc_id_cred_pub_share);
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
    let id_object = {
        let file = matches
            .value_of("id-object")
            .expect("id-object parameter mandatory.");
        match read_json_from_file::<_, IdentityObject<Bls12, ExampleCurve, ExampleAttribute>>(file)
        {
            Ok(v) => v,
            Err(x) => {
                eprintln!("Could not read identity object because {}", x);
                return;
            }
        }
    };

    let ip_info = match matches.value_of("ip-info").map(read_json_from_file) {
        Some(Ok(v)) => v,
        Some(Err(x)) => {
            eprintln!("Could not read identity provider info because {}", x);
            return;
        }
        None => unreachable!("Mandatory argument."),
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
    // we first ask the user to select which attributes they wish to reveal
    let alist = &id_object.alist.alist;

    let alist_items = alist
        .keys()
        .map(|&x| AttributeStringTag::from(x))
        .collect::<Vec<_>>();
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
    let mut revealed_attributes: BTreeMap<AttributeTag, ExampleAttribute> = BTreeMap::new();
    for idx in atts {
        let idx = AttributeTag(idx as u8);
        match alist.get(&idx) {
            Some(elem) => {
                if revealed_attributes.insert(idx, *elem).is_some() {
                    eprintln!("Duplicate attribute idx.");
                    return;
                }
            }
            None => {
                eprintln!("Selected an attribute which does not exist. Aborting.");
                return;
            }
        }
    }
    let policy = Policy {
        expiry:     id_object.alist.expiry,
        policy_vec: revealed_attributes,
        _phantom:   Default::default(),
    };

    // We now generate or read account verification/signature key pair.
    let mut known_acc = false;
    let acc_data = {
        if let Some(acc_data_file) = matches.value_of("account") {
            match read_json_from_file(acc_data_file) {
                Ok(acc_data) => {
                    known_acc = true;
                    acc_data
                }
                Err(e) => {
                    eprintln!(
                        "Could not read account data from provided file because {}",
                        e
                    );
                    return;
                }
            }
        } else {
            let mut csprng = thread_rng();
            let mut keys = BTreeMap::new();
            keys.insert(KeyIndex(0), ed25519::Keypair::generate(&mut csprng));
            keys.insert(KeyIndex(1), ed25519::Keypair::generate(&mut csprng));
            keys.insert(KeyIndex(2), ed25519::Keypair::generate(&mut csprng));

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
        write_json_to_file("account_keys.json", &acc_data).ok();
    }

    // finally we also read the credential holder information with secret keys
    // which we need to generate CDI.
    // This file should also contain the public keys of the identity provider who
    // signed the object.
    let id_use_data: IdObjectUseData<Bls12, ExampleCurve> = match read_json_from_file(
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
        &id_object,
        &id_use_data,
        x,
        &policy,
        &acc_data,
    );

    let cdi = match cdi {
        Ok(cdi) => cdi,
        Err(x) => {
            eprintln!("Could not generate the credential because {}", x);
            return;
        }
    };

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

    if let Some(json_file) = matches.value_of("out") {
        match write_json_to_file(json_file, &cdi) {
            Ok(_) => println!("Wrote transaction payload to JSON file."),
            Err(e) => {
                eprintln!("Could not JSON write to file because {}", e);
                output_json(&cdi);
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

    if let Some(filepath) = matches.value_of("out") {
        match write_json_to_file(filepath, &ah_info) {
            Ok(()) => println!("Wrote CHI to file."),
            Err(_) => {
                eprintln!("Could not write to file. The generated information is");
                output_json(&ah_info);
            }
        }
    } else {
        println!("Generated account holder information.");
        output_json(&ah_info)
    }
}

/// Act as the identity provider. Read the pre-identity object and load the
/// private information of the identity provider, check and sign the
/// pre-identity object to generate the identity object to send back to the
/// account holder.
fn handle_act_as_ip(matches: &ArgMatches) {
    let pio_path = Path::new(matches.value_of("pio").unwrap());
    let pio = match read_json_from_file::<_, PreIdentityObject<_, _>>(&pio_path) {
        Ok(pio) => pio,
        Err(e) => {
            eprintln!("Could not read file because {}", e);
            return;
        }
    };
    let ip_data_path = Path::new(matches.value_of("ip-data").unwrap());
    let (ip_info, ip_sec_key) =
        match read_json_from_file::<_, IpData<Bls12, ExampleCurve>>(&ip_data_path) {
            Ok(ip_data) => (ip_data.public_ip_info, ip_data.ip_private_key),
            Err(x) => {
                eprintln!("Could not read identity issuer information because {}", x);
                return;
            }
        };

    let expiry_date = match read_expiry_date() {
        Ok(expiry_date) => expiry_date,
        Err(e) => {
            eprintln!("Could not read credential expiry date because {}", e);
            return;
        }
    };

    let tags = {
        match Checkboxes::new()
            .with_prompt("Select attributes:")
            .items(&ATTRIBUTE_NAMES)
            .interact()
        {
            Ok(idxs) => idxs,
            Err(x) => {
                eprintln!("You have to choose some attributes. Terminating. {}", x);
                return;
            }
        }
    };

    let alist = {
        let mut alist: BTreeMap<AttributeTag, ExampleAttribute> = BTreeMap::new();
        for idx in tags {
            match Input::new().with_prompt(ATTRIBUTE_NAMES[idx]).interact() {
                Err(e) => {
                    eprintln!("You need to provide integer input: {}", e);
                    return;
                }
                Ok(s) => {
                    let _ = alist.insert(AttributeTag(idx as u8), s);
                }
            }
        }
        alist
    };

    let attributes = AttributeList {
        expiry: expiry_date,
        alist,
        _phantom: Default::default(),
    };
    let vf = verify_credentials(&pio, &ip_info, &attributes, &ip_sec_key);

    match vf {
        Ok(signature) => {
            let id_object = IdentityObject {
                pre_identity_object: pio,
                alist: attributes,
                signature,
            };
            println!("Successfully checked pre-identity data.");
            if let Some(signed_out_path) = matches.value_of("out") {
                if write_json_to_file(signed_out_path, &id_object).is_ok() {
                    println!("Wrote signed identity object to file.");
                } else {
                    println!(
                        "Could not write Identity object to file. The signature is: {}",
                        base16_encode_string(&id_object.signature)
                    );
                }
            } else {
                println!(
                    "The signature is: {}",
                    base16_encode_string(&id_object.signature)
                );
            }
        }
        Err(r) => eprintln!("Could not verify pre-identity object {:?}", r),
    }
}

fn handle_start_ip(matches: &ArgMatches) {
    let path = Path::new(matches.value_of("chi").unwrap());
    let chi = {
        if let Ok(chi) = read_json_from_file(&path) {
            chi
        } else {
            eprintln!("Could not read credential holder information.");
            return;
        }
    };
    let mut csprng = thread_rng();
    let prf_key = prf::SecretKey::generate(&mut csprng);

    // the chosen account credential information
    let aci = AccCredentialInfo {
        cred_holder_info: chi,
        prf_key,
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

    // FIXME: THis clone is unnecessary.
    let ar_handles = ip_info.ip_ars.ars.clone();
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

    let context = make_context_from_ip_info(ip_info, ChoiceArParameters {
        ar_identities: choice_ars,
        threshold,
    });
    // and finally generate the pre-identity object
    // we also retrieve the randomness which we must keep private.
    // This randomness must be used
    let (pio, randomness) = generate_pio(&context, &aci);

    // the only thing left is to output all the information

    let id_use_data = IdObjectUseData { aci, randomness };
    if let Some(aci_out_path) = matches.value_of("private") {
        if write_json_to_file(aci_out_path, &id_use_data).is_ok() {
            println!("Wrote ACI and randomness to file.");
        } else {
            println!("Could not write ACI data to file. Outputting to standard output.");
            output_json(&id_use_data);
        }
    } else {
        output_json(&id_use_data);
    }

    if let Some(pio_out_path) = matches.value_of("public") {
        if write_json_to_file(pio_out_path, &pio).is_ok() {
            println!("Wrote PIO data to file.");
        } else {
            println!("Could not write PIO data to file. Outputting to standard output.");
            output_json(&pio);
        }
    } else {
        output_json(&pio);
    }
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
        let ip_fname_pub = mk_ip_filename_pub(id);
        let ar0_fname = mk_ar_filename(id, 0);
        let ar1_fname = mk_ar_filename(id, 1);
        let ar2_fname = mk_ar_filename(id, 2);

        // TODO: hard-coded length of the key for now, but should be changed
        // based on the maximum length of the attribute list
        let id_secret_key = ps_sig::secret::SecretKey::<Bls12>::generate(20, &mut csprng);
        let id_public_key = ps_sig::public::PublicKey::from(&id_secret_key);

        let ar_base = ExampleCurve::generate(&mut csprng);

        let ar0_secret_key = SecretKey::generate(&ar_base, &mut csprng);
        let ar0_public_key = PublicKey::from(&ar0_secret_key);
        let ar0_info = ArInfo {
            ar_identity:    ArIdentity(0u32),
            ar_description: mk_ar_name(0),
            ar_public_key:  ar0_public_key,
        };

        let private_js0 = ArData {
            public_ar_info: ar0_info,
            ar_private_key: ar0_secret_key,
        };

        let ar1_secret_key = SecretKey::generate(&ar_base, &mut csprng);
        let ar1_public_key = PublicKey::from(&ar1_secret_key);
        let ar1_info = ArInfo {
            ar_identity:    ArIdentity(1u32),
            ar_description: mk_ar_name(1),
            ar_public_key:  ar1_public_key,
            // ar_elgamal_generator: PublicKey::generator(),
        };

        let private_js1 = ArData {
            public_ar_info: ar1_info,
            ar_private_key: ar1_secret_key,
        };

        let ar2_secret_key = SecretKey::generate(&ar_base, &mut csprng);
        let ar2_public_key = PublicKey::from(&ar2_secret_key);
        let ar2_info = ArInfo {
            ar_identity:    ArIdentity(2u32),
            ar_description: mk_ar_name(2),
            ar_public_key:  ar2_public_key,
            // ar_elgamal_generator: PublicKey::generator(),
        };

        let private_js2 = ArData {
            public_ar_info: ar2_info,
            ar_private_key: ar2_secret_key,
        };

        write_json_to_file(&ar0_fname, &private_js0).ok()?;
        write_json_to_file(&ar1_fname, &private_js1).ok()?;
        write_json_to_file(&ar2_fname, &private_js2).ok()?;

        let ip_info = IpInfo {
            ip_identity:    IpIdentity(id as u32),
            ip_description: mk_ip_name(id),
            ip_verify_key:  id_public_key,
            ip_ars:         IpAnonymityRevokers {
                ars: vec![
                    private_js0.public_ar_info,
                    private_js1.public_ar_info,
                    private_js2.public_ar_info,
                ],
                ar_cmm_key: CommitmentKey::<ExampleCurve>::generate(&mut csprng),
                ar_base,
            },
        };
        let full_info = IpData {
            ip_private_key: id_secret_key,
            public_ip_info: ip_info,
        };
        println!("writing ip_{} in file {}", id, ip_fname);
        write_json_to_file(&ip_fname, &full_info).ok()?;
        println!("writing ip_{} public data in file {}", id, ip_fname_pub);
        write_json_to_file(&ip_fname_pub, &full_info.public_ip_info).ok()?;

        res.push(full_info.public_ip_info);
    }
    write_json_to_file(IDENTITY_PROVIDERS, &res).ok()?;
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
    write_json_to_file(GLOBAL_CONTEXT, &gc).ok()
}
