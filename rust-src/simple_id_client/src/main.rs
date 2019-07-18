use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};

use ed25519_dalek as ed25519;
use eddsa_ed25519 as ed25519_wrapper;

use curve_arithmetic::{Curve, Pairing};
use dialoguer::{Checkboxes, Input, Select};
use dodis_yampolskiy_prf::secret as prf;
use elgamal::{cipher::Cipher, public::PublicKey, secret::SecretKey};
use hex::{decode, encode};
use id::{account_holder::*, chain::verify_cdi, ffi::*, identity_provider::*, types::*};
use pairing::bls12_381::Bls12;
use ps_sig;

use chrono::NaiveDateTime;

use std::io::Cursor;

use rand::*;
use serde_json::{json, to_string_pretty, Value};

use pedersen_scheme::{commitment::Commitment, key as pedersen_key};

use sigma_protocols::{com_enc_eq, com_eq, com_eq_different_groups};

use std::{
    fs::File,
    io::{self, BufReader, Error, ErrorKind, Write},
    path::Path,
};

type ExampleCurve = <Bls12 as Pairing>::G_1;

macro_rules! m_json_decode {
    ($val:expr, $key:expr) => {
        &mut Cursor::new(&json_base16_decode($val.get($key)?)?)
    };
}

static GLOBAL_CONTEXT: &str = "database/global.json";
static IP_PREFIX: &str = "database/identity_provider-";
static AR_PREFIX: &str = "database/anonymity_revoker-";
static IP_NAME_PREFIX: &str = "identity_provider-";
static AR_NAME_PREFIX: &str = "anonymity_revoker-";
static IDENTITY_PROVIDERS: &str = "database/identity_providers.json";

fn read_global_context() -> Option<GlobalContext<ExampleCurve>> {
    if let Ok(Some(gc)) = read_json_from_file(GLOBAL_CONTEXT)
        .as_ref()
        .map(json_to_global_context)
    {
        Some(gc)
    } else {
        None
    }
}

fn read_identity_providers() -> Option<Vec<IpInfo<Bls12, <Bls12 as Pairing>::G_1>>> {
    if let Ok(Some(ips)) = read_json_from_file(IDENTITY_PROVIDERS)
        .as_ref()
        .map(json_to_ip_infos)
    {
        Some(ips)
    } else {
        None
    }
}

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

fn mk_ar_filename(n: usize) -> String {
    let mut s = AR_PREFIX.to_string();
    s.push_str(&n.to_string());
    s.push_str(".json");
    s
}

fn mk_ar_name(n: usize) -> String {
    let mut s = AR_NAME_PREFIX.to_string();
    s.push_str(&n.to_string());
    s
}

type ExampleAttribute = AttributeKind;

type ExampleAttributeList = AttributeList<<Bls12 as Pairing>::ScalarField, ExampleAttribute>;

/// Show fields of the type of fields of the given attribute list.
fn show_attribute_format(variant: u16) -> &'static str {
    match variant {
        0 => "[ExpiryDate, MaxAccount, Age]",
        1 => "[ExpiryDate, MaxAccount, Age, Citizenship, Business]",
        _ => unimplemented!("Only two formats of attribute lists supported."),
    }
}

fn show_attribute(variant: u16, idx: usize, att: &ExampleAttribute) -> String {
    match (variant, idx) {
        (0, 0) => format!("MaxAccount({})", att.to_u64()).to_string(),
        (0, 1) => format!("Age({})", att.to_u64()).to_string(),
        (1, 0) => format!("MaxAccount({})", att.to_u64()).to_string(),
        (1, 1) => format!("Age({})", att.to_u64()).to_string(),
        (1, 2) => format!("Citizenship({})", att.to_u64()).to_string(),
        (1, 3) => format!("Business({})", att.to_u64() != 0).to_string(),
        (_, _) => panic!("This should not happen. Precondition violated."),
    }
}

fn read_max_account() -> io::Result<ExampleAttribute> {
    let options = vec![10, 25, 50, 100, 200, 255];
    let select = Select::new()
        .with_prompt("Choose maximum number of accounts")
        .items(&options)
        .default(0)
        .interact()?;
    Ok(AttributeKind::U8(options[select]))
}

fn parse_expiry_date(input: &str) -> io::Result<u64> {
    let mut input = input.to_owned();
    input.push_str(" 23:59:59");
    let dt = NaiveDateTime::parse_from_str(&input, "%d %B %Y %H:%M:%S")
        .map_err(|x| Error::new(ErrorKind::Other, x.to_string()))?;
    Ok(dt.timestamp() as u64)
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
    let max_acc = read_max_account()?;
    let age = Input::new().with_prompt("Your age").interact()?;
    match variant {
        0 => Ok(vec![max_acc, AttributeKind::U8(age)]),
        1 => {
            let citizenship = Input::new().with_prompt("Citizenship").interact()?; // TODO: use drop-down/select with
            let business = Input::new().with_prompt("Are you a business").interact()?;
            Ok(vec![
                max_acc,
                AttributeKind::U8(age),
                AttributeKind::U16(citizenship),
                AttributeKind::U8(if business { 1 } else { 0 }),
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
fn output_json(js: &Value) {
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

fn chi_to_json<C: Curve, T: Curve<Scalar = C::Scalar>>(chi: &CredentialHolderInfo<C, T>) -> Value {
    json!({
        "name": chi.id_ah,
        "idCredPublicIP": encode(chi.id_cred.id_cred_pub_ip.curve_to_bytes()),
        "idCredPublic": encode(chi.id_cred.id_cred_pub.curve_to_bytes()),
        "idCredSecret": encode(C::scalar_to_bytes(&chi.id_cred.id_cred_sec)),
    })
}

fn json_to_chi<C: Curve, T: Curve<Scalar = C::Scalar>>(
    js: &Value,
) -> Option<CredentialHolderInfo<C, T>> {
    let id_cred_pub_ip = T::bytes_to_curve(m_json_decode!(js, "idCredPublicIP")).ok()?;
    let id_cred_pub = C::bytes_to_curve(m_json_decode!(js, "idCredPublic")).ok()?;
    let id_cred_sec = C::bytes_to_scalar(m_json_decode!(js, "idCredSecret")).ok()?;
    let id_ah = js["name"].as_str()?;
    let info: CredentialHolderInfo<C, T> = CredentialHolderInfo {
        id_ah:   id_ah.to_owned(),
        id_cred: IdCredentials {
            id_cred_sec,
            id_cred_pub,
            id_cred_pub_ip,
        },
    };
    Some(info)
}

fn alist_to_json(alist: &ExampleAttributeList) -> Value {
    match alist.variant {
        0 => json!({
            "variant": alist.variant,
            "expiryDate": alist.expiry,
            "maxAccount": alist.alist[0].to_u64(),
            "age": alist.alist[1].to_u64(),
        }),
        1 => json!({
            "variant": alist.variant,
            "expiryDate": alist.expiry,
            "maxAccount": alist.alist[0].to_u64(),
            "age": alist.alist[1].to_u64(),
            "citizenship": alist.alist[2].to_u64(),
            "business": alist.alist[3].to_u64() == 1,
        }),
        _ => Value::Null,
    }
}

fn json_to_alist(v: &Value) -> Option<ExampleAttributeList> {
    let obj = v.as_object()?;
    let variant = obj.get("variant").and_then(Value::as_u64)?;
    let expiry = obj.get("expiryDate").and_then(Value::as_u64)?;
    match variant {
        0 => {
            let max_account = obj.get("maxAccount").and_then(Value::as_u64)?;
            let age = obj.get("age").and_then(Value::as_u64)?;
            let alist = vec![
                AttributeKind::U8(max_account as u8),
                AttributeKind::U8(age as u8),
            ];
            Some(AttributeList {
                variant: variant as u16,
                expiry,
                alist,
                _phantom: Default::default(),
            })
        }
        1 => {
            let max_account = obj.get("maxAccount").and_then(Value::as_u64)?;
            let age = obj.get("age").and_then(Value::as_u64)?;
            let citizenship = obj.get("citizenship").and_then(Value::as_u64)?;
            let business = obj.get("business").and_then(Value::as_bool)?;
            let alist = vec![
                AttributeKind::U8(max_account as u8),
                AttributeKind::U8(age as u8),
                AttributeKind::U16(citizenship as u16),
                AttributeKind::U8(if business { 1 } else { 0 }),
            ];
            Some(AttributeList {
                variant: variant as u16,
                expiry,
                alist,
                _phantom: Default::default(),
            })
        }
        _ => None,
    }
}

fn aci_to_json(aci: &AccCredentialInfo<Bls12, <Bls12 as Pairing>::G_1, ExampleAttribute>) -> Value {
    let chi = chi_to_json(&aci.acc_holder_info);
    json!({
        "credentialHolderInformation": chi,
        "prfKey": json_base16_encode(&aci.prf_key.to_bytes()),
        "attributes": alist_to_json(&aci.attributes),
    })
}

fn json_to_aci(
    v: &Value,
) -> Option<AccCredentialInfo<Bls12, <Bls12 as Pairing>::G_1, ExampleAttribute>> {
    let obj = v.as_object()?;
    let chi = json_to_chi(obj.get("credentialHolderInformation")?)?;
    let prf_key = prf::SecretKey::from_bytes(m_json_decode!(obj, "prfKey")).ok()?;
    let attributes = json_to_alist(obj.get("attributes")?)?;
    Some(AccCredentialInfo {
        acc_holder_info: chi,
        prf_key,
        attributes,
    })
}

fn global_context_to_json(global: &GlobalContext<ExampleCurve>) -> Value {
    json!({"dLogBaseChain": json_base16_encode(&global.dlog_base_chain.curve_to_bytes()),
           "onChainCommitmentKey": json_base16_encode(&global.on_chain_commitment_key.to_bytes()),
    })
}

fn json_to_global_context(v: &Value) -> Option<GlobalContext<ExampleCurve>> {
    let obj = v.as_object()?;
    let dlog_base_bytes = obj.get("dLogBaseChain").and_then(json_base16_decode)?;
    let dlog_base_chain =
        <<Bls12 as Pairing>::G_1 as Curve>::bytes_to_curve(&mut Cursor::new(&dlog_base_bytes))
            .ok()?;
    let cmk_bytes = obj
        .get("onChainCommitmentKey")
        .and_then(json_base16_decode)?;
    let cmk = pedersen_key::CommitmentKey::from_bytes(&mut Cursor::new(&cmk_bytes)).ok()?;
    let gc = GlobalContext {
        dlog_base_chain,
        on_chain_commitment_key: cmk,
    };
    Some(gc)
}

fn json_to_ip_info(ip_val: &Value) -> Option<IpInfo<Bls12, <Bls12 as Pairing>::G_1>> {
    let ip_val = ip_val.as_object()?;
    let ip_identity = ip_val.get("ipIdentity")?.as_str()?;
    let ip_verify_key = ps_sig::PublicKey::from_bytes(&mut Cursor::new(&json_base16_decode(
        ip_val.get("ipVerifyKey")?,
    )?))
    .ok()?;
    let id_ar_name = ip_val.get("arName")?.as_str()?;
    let id_ar_public_key =
        elgamal::PublicKey::from_bytes(m_json_decode!(ip_val, "arPublicKey")).ok()?;
    let id_ar_elgamal_generator =
        Curve::bytes_to_curve(m_json_decode!(ip_val, "arElgamalGenerator")).ok()?;
    Some(IpInfo {
        ip_identity: ip_identity.to_owned(),
        ip_verify_key,
        ar_info: ArInfo {
            ar_name:              id_ar_name.to_owned(),
            ar_public_key:        id_ar_public_key,
            ar_elgamal_generator: id_ar_elgamal_generator,
        },
    })
}

fn json_to_ip_infos(v: &Value) -> Option<Vec<IpInfo<Bls12, <Bls12 as Pairing>::G_1>>> {
    let ips_arr = v.as_array()?;
    ips_arr.iter().map(json_to_ip_info).collect()
}

fn ip_info_to_json(ipinfo: &IpInfo<Bls12, <Bls12 as Pairing>::G_1>) -> Value {
    json!({
                                   "ipIdentity": ipinfo.ip_identity,
                                   "ipVerifyKey": json_base16_encode(&ipinfo.ip_verify_key.to_bytes()),
                                   "arName": ipinfo.ar_info.ar_name,
                                   "arPublicKey": json_base16_encode(&ipinfo.ar_info.ar_public_key.to_bytes()),
                                   "arElgamalGenerator": json_base16_encode(&ipinfo.ar_info.ar_elgamal_generator.curve_to_bytes())
    })
}

fn ip_infos_to_json(ipinfos: &[IpInfo<Bls12, <Bls12 as Pairing>::G_1>]) -> Value {
    let arr: Vec<Value> = ipinfos.iter().map(ip_info_to_json).collect();
    json!(arr)
}

fn ip_ar_data_to_json<C: Curve>(ar_data: &IpArData<C>) -> Value {
    json!({
        "arName": ar_data.ar_name.clone(),
        "prfKeyEncryption": json_base16_encode(&ar_data.prf_key_enc.to_bytes()),
    })
}

fn json_to_ip_ar_data(v: &Value) -> Option<IpArData<ExampleCurve>> {
    let ar_name = v.get("arName")?.as_str()?;
    let prf_key_enc = Cipher::from_bytes(m_json_decode!(v, "prfKeyEncryption")).ok()?;
    Some(IpArData {
        ar_name: ar_name.to_owned(),
        prf_key_enc,
    })
}

fn chain_ar_data_to_json<C: Curve>(ar_data: &ChainArData<C>) -> Value {
    json!({
        "arName": ar_data.ar_name.clone(),
        "idCredPubEnc": json_base16_encode(&ar_data.id_cred_pub_enc.to_bytes()),
    })
}

// fn json_to_chain_ar_data(v: &Value) -> Option<ChainArData<ExampleCurve>> {
//     let ar_name = v.get("arName")?.as_str()?;
//     let id_cred_pub_enc = Cipher::from_bytes(m_json_decode!(v,
// "idCredPubEnc")).ok()?;     Some(ChainArData {
//         ar_name: ar_name.to_owned(),
//         id_cred_pub_enc,
//     })
// }

fn pio_to_json(pio: &PreIdentityObject<Bls12, ExampleCurve, ExampleAttribute>) -> Value {
    json!({
        "accountHolderName": pio.id_ah,
        "idCredPubIp": json_base16_encode(&pio.id_cred_pub_ip.curve_to_bytes()),
        "ipArData": ip_ar_data_to_json(&pio.ip_ar_data),
        "attributeList": alist_to_json(&pio.alist),
        "pokSecCred": json_base16_encode(&pio.pok_sc.to_bytes()),
        "idCredSecCommitment": json_base16_encode(&pio.cmm_sc.to_bytes()),
        "prfKeyCommitmentWithID": json_base16_encode(&pio.cmm_prf.to_bytes()),
        "prfKeyCommitmentWithAR": json_base16_encode(&pio.snd_cmm_prf.to_bytes()),
        "proofEncryptionPrf": json_base16_encode(&pio.proof_com_enc_eq.to_bytes()),
        "proofCommitmentsSame": json_base16_encode(&pio.proof_com_eq.to_bytes())
    })
}

fn json_to_pio(v: &Value) -> Option<PreIdentityObject<Bls12, ExampleCurve, ExampleAttribute>> {
    let id_ah = v.get("accountHolderName")?.as_str()?.to_owned();
    let id_cred_pub_ip = ExampleCurve::bytes_to_curve(m_json_decode!(v, "idCredPubIp")).ok()?;
    let ip_ar_data = json_to_ip_ar_data(v.get("ipArData")?)?;
    let alist = json_to_alist(v.get("attributeList")?)?;
    let pok_sc = com_eq::ComEqProof::from_bytes(&mut Cursor::new(&json_base16_decode(
        v.get("pokSecCred")?,
    )?))
    .ok()?;
    let cmm_sc = Commitment::from_bytes(m_json_decode!(v, "idCredSecCommitment")).ok()?;
    let cmm_prf = Commitment::from_bytes(m_json_decode!(v, "prfKeyCommitmentWithID")).ok()?;
    let snd_cmm_prf = Commitment::from_bytes(m_json_decode!(v, "prfKeyCommitmentWithAR")).ok()?;
    let proof_com_enc_eq = com_enc_eq::ComEncEqProof::from_bytes(&mut Cursor::new(
        &json_base16_decode(v.get("proofEncryptionPrf")?)?,
    ))
    .ok()?;
    let proof_com_eq = com_eq_different_groups::ComEqDiffGrpsProof::from_bytes(&mut Cursor::new(
        &json_base16_decode(v.get("proofCommitmentsSame")?)?,
    ))
    .ok()?;
    Some(PreIdentityObject {
        id_ah,
        id_cred_pub_ip,
        ip_ar_data,
        alist,
        pok_sc,
        cmm_sc,
        cmm_prf,
        snd_cmm_prf,
        proof_com_enc_eq,
        proof_com_eq,
    })
}

fn main() {
    let app = App::new("Prototype client showcasing ID layer interactions.")
        .version("0. 0.36787944117")
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
        );
    let matches = app.get_matches();
    let exec_if = |x: &str| matches.subcommand_matches(x);
    exec_if("create-chi").map(handle_create_chi);
    exec_if("start-ip").map(handle_start_ip);
    exec_if("generate-ips").map(handle_generate_ips);
    exec_if("generate-global").map(handle_generate_global);
    exec_if("ip-sign-pio").map(handle_act_as_ip);
    exec_if("deploy-credential").map(handle_deploy_credential);
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
            match (
                v.get("signature").and_then(json_base16_decode),
                v.get("preIdentityObject").and_then(json_to_pio),
                v.get("ipInfo").and_then(json_to_ip_info),
            ) {
                (Some(sig_bytes), Some(pio), Some(ip_info)) => {
                    if let Ok(ip_sig) = ps_sig::Signature::from_bytes(&mut Cursor::new(&sig_bytes))
                    {
                        (ip_sig, pio, ip_info)
                    } else {
                        eprintln!("Malformed input.");
                        return;
                    }
                }
                (_, _, _) => {
                    eprintln!("Could not parse JSON.");
                    return;
                }
            }
        } else {
            eprintln!("Could not parse JSON.");
            return;
        }
    };

    // we also read the global context from another json file (called
    // global.context). We need commitment keys and other data in there.
    let global_ctx = {
        if let Some(gc) = read_global_context() {
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
        .with_prompt("Select which attributes you wish to reveal.")
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
    let mut revealed_attributes = Vec::with_capacity(atts.len());
    for idx in atts {
        revealed_attributes.push((idx as u16, alist[idx]))
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
            let kp = ed25519_wrapper::generate_keypair();
            AccountData {
                sign_key:   kp.secret,
                verify_key: kp.public,
            }
        }
    };
    if !known_acc {
        println!(
            "Generated fresh verification and signature key of the account to file \
             account_keys.json"
        );
        write_json_to_file("account_keys.json", &account_data_to_json(&acc_data)).ok();
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
    let aci = match private_value.get("ACI").and_then(json_to_aci) {
        Some(aci) => aci,
        None => {
            eprintln!("Could not read ACI.");
            return;
        }
    };
    let randomness = match private_value
        .get("randomness")
        .and_then(|x| json_base16_decode(&x))
        .and_then(|bytes| SigRetrievalRandomness::<Bls12>::from_bytes(&mut Cursor::new(&bytes)))
    {
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
    let checked = verify_cdi(&global_ctx, &ip_info, &cdi);
    if let Err(e) = checked {
        eprintln!(
            "Something went terribly wrong and the generated CDI is not valid because {}",
            e
        );
        return;
    };

    // Now simply output the credential object in the transaction format
    // accepted by the simple-client for sending transactions.

    let values = &cdi.values;

    let js = json!({
        "schemeId": if values.acc_scheme_id == SchemeId::Ed25519 {"Ed25519"} else {"CL"},
        "verifyKey": json_base16_encode(&values.acc_pub_key.to_bytes()),
        "regId": json_base16_encode(&values.reg_id.curve_to_bytes()),
        "ipIdentity": values.ip_identity.clone(),
        "arData": chain_ar_data_to_json(&values.ar_data),
        "policy": policy_to_json(&values.policy),
        // NOTE: Since proofs encode their own length we do not output those first 4 bytes
        "proofs": json_base16_encode(&cdi.proofs.to_bytes()[4..]),
    });
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
            Ok(mut file) => match file.write_all(&cdi.to_bytes()) {
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

fn policy_to_json<C: Curve, AttributeType: Attribute<C::Scalar>>(
    policy: &Policy<C, AttributeType>,
) -> Value {
    let revealed: Vec<Value> = policy
        .policy_vec
        .iter()
        .map(|(idx, value)| json!({"index": idx, "value": json_base16_encode(&value.to_bytes())}))
        .collect();
    json!({
        "variant": policy.variant,
        "expiry": policy.expiry,
        "revealedItems": revealed
    })
}

fn read_account_data<P: AsRef<Path>>(path: P) -> Option<AccountData> {
    let v = read_json_from_file(path).ok()?;
    json_to_account_data(&v)
}

fn json_to_account_data(v: &Value) -> Option<AccountData> {
    let v = v.as_object()?;
    let verify_key =
        ed25519::PublicKey::from_bytes(&v.get("verifyKey").and_then(json_base16_decode)?).ok()?;
    let sign_key =
        ed25519::SecretKey::from_bytes(&v.get("signKey").and_then(json_base16_decode)?).ok()?;
    Some(AccountData {
        verify_key,
        sign_key,
    })
}

fn account_data_to_json(acc: &AccountData) -> Value {
    json!({
        "verifyKey": json_base16_encode(acc.verify_key.as_bytes()),
        "signKey": json_base16_encode(acc.sign_key.as_bytes()),
    })
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
    let public = ExampleCurve::one_point().mul_by_scalar(&secret);
    let ah_info = CredentialHolderInfo::<ExampleCurve, ExampleCurve> {
        id_ah:   name,
        id_cred: IdCredentials {
            id_cred_sec:    secret,
            id_cred_pub:    public,
            id_cred_pub_ip: public,
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

/// load private and public information on identity providers
/// Private and public data on an identity provider.
type IpData = (
    IpInfo<Bls12, <Bls12 as Pairing>::G_1>,
    ps_sig::SecretKey<Bls12>,
);

fn json_to_ip_data(v: &Value) -> Option<IpData> {
    let id_cred_sec = ps_sig::SecretKey::from_bytes(&mut Cursor::new(&json_base16_decode(
        v.get("idPrivateKey")?,
    )?))
    .ok()?;
    let ip_info = json_to_ip_info(v.get("publicIdInfo")?)?;
    Some((ip_info, id_cred_sec))
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
    // we also read the global context from another json file (called
    // global.context) This has some parameters for encryption.
    // let global_ctx = {
    //     if let Some(gc) = read_global_context() {
    //         gc
    //     } else {
    //         eprintln!("Cannot read global context information database.
    // Terminating.");         return;
    //     }
    // };
    // FIXME: Clone should not be necessary. Refactor.
    let ctx = make_context_from_ip_info(ip_info.clone());

    let vf = verify_credentials(&pio, ctx, &ip_sec_key);
    match vf {
        Ok(sig) => {
            println!("Successfully checked pre-identity data.");
            let sig_bytes = &sig.to_bytes();
            if let Some(signed_out_path) = matches.value_of("out") {
                let js = json!({
                    "preIdentityObject": pio_to_json(&pio),
                    "signature": json_base16_encode(sig_bytes),
                    "ipInfo": ip_info_to_json(&ip_info)
                });
                if write_json_to_file(signed_out_path, &js).is_ok() {
                    println!("Wrote signed identity object to file.");
                } else {
                    println!(
                        "Could not write Identity object to file. The signature is: {}",
                        encode(sig_bytes)
                    );
                }
            } else {
                println!("The signature is: {}", encode(sig_bytes));
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
            .map(json_to_chi::<ExampleCurve, ExampleCurve>)
        {
            chi
        } else {
            eprintln!("Could not read credential holder information.");
            return;
        }
    };
    let mut csprng = thread_rng();
    let prf_key = prf::SecretKey::generate(&mut csprng);
    let alist_type = {
        match Select::new()
            .with_prompt("Select attribute list type:")
            .item(&show_attribute_format(0))
            .item(&show_attribute_format(1))
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

    // we also read the global context from another json file
    // let global_ctx = {
    //     if let Some(gc) = read_global_context() {
    //         gc
    //     } else {
    //         eprintln!("Cannot read global context information database.
    // Terminating.");         return;
    //     }
    // };

    // names of identity providers the user can choose from, together with the
    // names of anonymity revokers associated with them
    let mut ips_names = Vec::with_capacity(ips.len());
    for x in ips.iter() {
        ips_names.push(format!(
            "Identity provider {}, its anonymity revoker is {}",
            &x.ip_identity, &x.ar_info.ar_name
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

    let context = make_context_from_ip_info(ip_info);
    // and finally generate the pre-identity object
    // we also retrieve the randomness which we must keep private.
    // This randomness must be used
    let (pio, randomness) = generate_pio(&context, &aci);

    // the only thing left is to output all the information

    let aci_js = aci_to_json(&aci);
    let js = json!({
        "ACI": aci_js,
        "randomness": json_base16_encode(&randomness.to_bytes())
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
        "arName": ar_info.ar_name,
        "arPublicKey": json_base16_encode(&ar_info.ar_public_key.to_bytes()),
        "arElgamalGenerator": json_base16_encode(&ar_info.ar_elgamal_generator.curve_to_bytes())
    })
}

/// Generate identity providers with public and private information as well as
/// anonymity revokers. For now we generate identity providers with names
/// IP_PREFIX-i.json and its associated anonymity revoker has name
/// AR_PRFEFIX-i.json.
fn handle_generate_ips(matches: &ArgMatches) -> Option<()> {
    let mut csprng = thread_rng();
    let num: usize = matches.value_of("num").unwrap_or("10").parse().ok()?;
    let mut res = Vec::with_capacity(num);
    for id in 0..num {
        let ip_fname = mk_ip_filename(id);
        let ar_fname = mk_ar_filename(id);

        // TODO: hard-coded for now, at most 8 items in the attribute list
        // (because signature length 10)
        let id_secret_key = ps_sig::secret::SecretKey::generate(10, &mut csprng);
        let id_public_key = ps_sig::public::PublicKey::from(&id_secret_key);

        let ar_secret_key = SecretKey::generate(&mut csprng);
        let ar_public_key = PublicKey::from(&ar_secret_key);
        let ar_info = ArInfo {
            ar_name: mk_ar_name(id),
            ar_public_key,
            ar_elgamal_generator: PublicKey::generator(),
        };

        let js = ar_info_to_json(&ar_info);
        let private_js = json!({
            "arPrivateKey": json_base16_encode(&ar_secret_key.to_bytes()),
            "publicArInfo": js
        });
        write_json_to_file(&ar_fname, &private_js).ok()?;

        let ip_info = IpInfo {
            ip_identity: mk_ip_name(id),
            ip_verify_key: id_public_key,
            ar_info,
        };
        let js = ip_info_to_json(&ip_info);
        let private_js = json!({
            "idPrivateKey": json_base16_encode(&id_secret_key.to_bytes()),
            "publicIdInfo": js
        });
        write_json_to_file(&ip_fname, &private_js).ok()?;

        res.push(ip_info);
    }
    write_json_to_file(IDENTITY_PROVIDERS, &ip_infos_to_json(&res)).ok()?;
    Some(())
}

/// Generate the global context.
fn handle_generate_global(_matches: &ArgMatches) -> Option<()> {
    let mut csprng = thread_rng();
    let gc = GlobalContext {
        dlog_base_chain: ExampleCurve::one_point(),
        // we generate the commitment key for 1 value only.
        // Since the scheme supports general vectors of values this is inefficient
        // but is OK for now.
        // The reason we only need 1 value is that we commit to each value separately
        // in the attribute list. This is so that we can reveal items individually.
        on_chain_commitment_key: pedersen_key::CommitmentKey::generate(1, &mut csprng),
    };
    write_json_to_file(GLOBAL_CONTEXT, &global_context_to_json(&gc)).ok()
}
