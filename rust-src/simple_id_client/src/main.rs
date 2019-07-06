use clap::{App, Arg, ArgMatches, SubCommand};

use curve_arithmetic::{Curve, Pairing};
use dialoguer::{Input, Select};
use dodis_yampolskiy_prf::secret as prf;
use elgamal::{cipher::Cipher, public::PublicKey, secret::SecretKey};
use hex::{decode, encode};
use id::{identity_provider::*, types::*};
use pairing::{
    bls12_381::{Bls12, Fr, FrRepr},
    PrimeField,
};
use ps_sig;

use chrono::NaiveDateTime;

use std::io::Cursor;

use rand::*;
use serde_json::{json, to_string_pretty, Value};

use pedersen_scheme::{
    commitment::Commitment, key::CommitmentKey as PedersenKey, value as pedersen,
};

use sigma_protocols::{com_enc_eq, com_eq_different_groups, dlog};

use std::{
    fs::File,
    io::{self, BufReader, Error, ErrorKind, Write},
    path::Path,
};

static GLOBAL_CONTEXT: &'static str = "database/global.json";
static IP_PREFIX: &'static str = "database/identity_provider-";
static AR_PREFIX: &'static str = "database/anonymity_revoker-";
static IP_NAME_PREFIX: &'static str = "identity_provider-";
static AR_NAME_PREFIX: &'static str = "anonymity_revoker-";
static IDENTITY_PROVIDERS: &'static str = "database/identity_providers.json";

fn read_global_context() -> Option<GlobalContext<Bls12>> {
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

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ExampleAttribute {
    Age(u8),
    Citizenship(u16),
    ExpiryDate(NaiveDateTime),
    MaxAccount(u16),
    Business(bool),
}

type ExampleAttributeList = AttributeList<<Bls12 as Pairing>::ScalarField, ExampleAttribute>;

impl Attribute<<Bls12 as Pairing>::ScalarField> for ExampleAttribute {
    fn to_field_element(&self) -> <Bls12 as Pairing>::ScalarField {
        match self {
            ExampleAttribute::Age(x) => Fr::from_repr(FrRepr::from(u64::from(*x))).unwrap(),
            ExampleAttribute::Citizenship(c) => Fr::from_repr(FrRepr::from(u64::from(*c))).unwrap(),
            // TODO: note that using timestamp on naivedate is ambiguous because it does not account
            // for the time zone the date is in.
            ExampleAttribute::ExpiryDate(d) => {
                Fr::from_repr(FrRepr::from(d.timestamp() as u64)).unwrap()
            }
            ExampleAttribute::MaxAccount(x) => Fr::from_repr(FrRepr::from(u64::from(*x))).unwrap(),
            ExampleAttribute::Business(b) => Fr::from_repr(FrRepr::from(u64::from(*b))).unwrap(),
        }
    }
}

fn example_attribute_to_json(att: &ExampleAttribute) -> Value {
    match att {
        ExampleAttribute::Age(x) => json!({"age": *x}),
        ExampleAttribute::Citizenship(c) => json!({ "citizenship": c }),
        ExampleAttribute::ExpiryDate(d) => json!({"expiryDate": d.format("%d %B %Y").to_string()}),
        ExampleAttribute::MaxAccount(x) => json!({ "maxAccount": x }),
        ExampleAttribute::Business(b) => json!({ "business": b }),
    }
}

/// Show fields of the type of fields of the given attribute list.
fn show_attribute_format(variant: u32) -> &'static str {
    match variant {
        0 => "[MaxAccount, ExpiryDate, Age]",
        1 => "[MaxAccount, ExpiryDate, Age, Citizenship, Business]",
        _ => unimplemented!("Only two formats of attribute lists supported."),
    }
}

fn read_max_account() -> io::Result<ExampleAttribute> {
    let options = vec![10, 25, 50, 100, 200, 255];
    let select = Select::new()
        .with_prompt("Choose maximum number of accounts")
        .items(&options)
        .default(0)
        .interact()?;
    Ok(ExampleAttribute::MaxAccount(options[select]))
}

fn parse_expiry_date(input: &str) -> io::Result<ExampleAttribute> {
    let mut input = input.to_owned();
    input.push_str(" 23:59:59");
    let dt = NaiveDateTime::parse_from_str(&input, "%d %B %Y %H:%M:%S")
        .map_err(|x| Error::new(ErrorKind::Other, x.to_string()))?;
    Ok(ExampleAttribute::ExpiryDate(dt))
}

/// Reads the expiry date. Only the day, the expiry time is set at the end of
/// that day.
fn read_expiry_date() -> io::Result<ExampleAttribute> {
    let input: String = Input::new().with_prompt("Expiry date").interact()?;
    parse_expiry_date(&input)
}

/// Given the chosen variant of the attribute list read off the fields from user
/// input. Fails if the user input is not well-formed.
fn read_attribute_list(variant: u32) -> io::Result<Vec<ExampleAttribute>> {
    let max_acc = read_max_account()?;
    let expiry_date = read_expiry_date()?;
    let age = Input::new().with_prompt("Your age").interact()?;
    match variant {
        0 => Ok(vec![max_acc, ExampleAttribute::Age(age), expiry_date]),
        1 => {
            let citizenship = Input::new().with_prompt("Citizenship").interact()?; // TODO: use drop-down/select with
            let business = Input::new().with_prompt("Are you a business").interact()?;
            Ok(vec![
                max_acc,
                expiry_date,
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

fn chi_to_json<P: Pairing>(chi: &CredentialHolderInfo<P>) -> Value {
    json!({
        "name": chi.id_ah,
        "idCredPublic": encode(chi.id_cred.id_cred_pub.to_bytes()),
        "idCredSecret": encode(chi.id_cred.id_cred_sec.to_bytes()),
    })
}

fn json_to_chi<P: Pairing>(js: &Value) -> Option<CredentialHolderInfo<P>> {
    let id_cred_pub =
        elgamal::PublicKey::<P::G_1>::from_bytes(&json_base16_decode(&js["idCredPublic"])?).ok()?;
    let id_cred_sec =
        elgamal::SecretKey::<P::G_1>::from_bytes(&json_base16_decode(&js["idCredSecret"])?).ok()?;
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

fn json_to_example_attribute(v: &Value) -> Option<ExampleAttribute> {
    let mp = v.as_object()?;
    if let Some(age) = mp.get("age") {
        Some(ExampleAttribute::Age(age.as_u64()? as u8))
    } else if let Some(citizenship) = mp.get("citizenship") {
        Some(ExampleAttribute::Citizenship(citizenship.as_u64()? as u16))
    } else if let Some(expiry_date) = mp.get("expiryDate") {
        let str = expiry_date.as_str()?;
        let r = parse_expiry_date(&str).ok()?;
        Some(r)
    } else if let Some(max_account) = mp.get("maxAccount") {
        Some(ExampleAttribute::MaxAccount(max_account.as_u64()? as u16))
    } else if let Some(business) = mp.get("business") {
        Some(ExampleAttribute::Business(business.as_u64()? != 0))
    } else {
        None
    }
}

fn alist_to_json(alist: &ExampleAttributeList) -> Value {
    let alist_vec: Vec<Value> = alist.alist.iter().map(example_attribute_to_json).collect();
    json!({
        "variant": alist.variant,
        "items": alist_vec
    })
}

fn json_to_alist(v: &Value) -> Option<ExampleAttributeList> {
    let obj = v.as_object()?;
    let variant = obj.get("variant")?;
    let items_val = obj.get("items")?;
    let items = items_val.as_array()?;
    let alist_vec: Option<Vec<ExampleAttribute>> =
        items.iter().map(json_to_example_attribute).collect();
    Some(AttributeList {
        variant:  variant.as_u64()? as u32,
        alist:    alist_vec?,
        _phantom: Default::default(),
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

fn json_to_aci(v: &Value) -> Option<AccCredentialInfo<Bls12, ExampleAttribute>> {
    let obj = v.as_object()?;
    let chi = json_to_chi(obj.get("credentialHolderInformation")?)?;
    let prf_key = prf::SecretKey::from_bytes(&json_base16_decode(obj.get("prfKey")?)?).ok()?;
    let attributes = json_to_alist(obj.get("attributes")?)?;
    Some(AccCredentialInfo {
        acc_holder_info: chi,
        prf_key,
        attributes,
    })
}

struct Context<P: Pairing, C: Curve> {
    /// Information on the anonymity revoker
    pub ar_info: ArInfo<C>,
    /// base point of the dlog proof (account holder knows secret credentials
    /// corresponding to the public credentials), shared at least between id
    /// provider and the account holder
    pub dlog_base: P::G_1,
    /// Commitment key shared by the identity provider and the account holder.
    /// It is used to generate commitments to the prf key.
    pub commitment_key_id: PedersenKey<P::G_1>,
    /// Commitment key shared by the anonymity revoker, identity provider, and
    /// account holder. Used to commit to the prf key of the account holder in
    /// the same group as the encryption of the prf key as given to the
    /// anonymity revoker.
    pub commitment_key_ar: PedersenKey<C>,
}

struct GlobalContext<P: Pairing> {
    /// Base point of the dlog proof.
    dlog_base: P::G_1,
}

/// Make a context in which the account holder can produce a pre-identity object
/// to send to the identity provider. Also requires access to the global context
/// of parameters, e.g., dlog-proof base point.
fn make_context_from_ip_info<P: Pairing, C: Curve>(
    ip_info: &IpInfo<P, C>,
    global: &GlobalContext<P>,
) -> Context<P, C> {
    // TODO: Check with Bassel that these parameters are correct.
    let commitment_key_id =
        PedersenKey(vec![ip_info.id_verify_key.0[0]], ip_info.id_verify_key.0[1]);
    let commitment_key_ar = PedersenKey(
        vec![ip_info.ar_info.ar_elgamal_generator],
        ip_info.ar_info.ar_public_key.0,
    );
    Context {
        ar_info: ip_info.ar_info.clone(),
        dlog_base: global.dlog_base,
        commitment_key_id,
        commitment_key_ar,
    }
}

fn global_context_to_json(global: &GlobalContext<Bls12>) -> Value {
    json!({"dLogBase": json_base16_encode(&global.dlog_base.curve_to_bytes())})
}

fn json_to_global_context(v: &Value) -> Option<GlobalContext<Bls12>> {
    let obj = v.as_object()?;
    let gc = GlobalContext {
        dlog_base: <<Bls12 as Pairing>::G_1 as Curve>::bytes_to_curve(&json_base16_decode(
            obj.get("dLogBase")?,
        )?)
        .ok()?,
    };
    Some(gc)
}

fn json_to_ip_info(ip_val: &Value) -> Option<IpInfo<Bls12, <Bls12 as Pairing>::G_1>> {
    let id_identity = ip_val.get("idIdentity")?.as_str()?;
    let id_verify_key = ps_sig::PublicKey::from_bytes(&mut Cursor::new(&json_base16_decode(
        ip_val.get("idVerifyKey")?,
    )?))
    .ok()?;
    let id_ar_name = ip_val.get("arName")?.as_str()?;
    let id_ar_public_key =
        elgamal::PublicKey::from_bytes(&json_base16_decode(ip_val.get("arPublicKey")?)?).ok()?;
    let id_ar_elgamal_generator =
        Curve::bytes_to_curve(&json_base16_decode(ip_val.get("arElgamalGenerator")?)?).ok()?;
    Some(IpInfo {
        id_identity: id_identity.to_owned(),
        id_verify_key,
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
                                   "idIdentity": ipinfo.id_identity.clone(),
                                   "idVerifyKey": json_base16_encode(&ipinfo.id_verify_key.to_bytes()),
                                   "arName": ipinfo.ar_info.ar_name.clone(),
                                   "arPublicKey": json_base16_encode(&ipinfo.ar_info.ar_public_key.to_bytes()),
                                   "arElgamalGenerator": json_base16_encode(&ipinfo.ar_info.ar_elgamal_generator.curve_to_bytes())
    })
}

fn ip_infos_to_json(ipinfos: &[IpInfo<Bls12, <Bls12 as Pairing>::G_1>]) -> Value {
    let arr: Vec<Value> = ipinfos.iter().map(ip_info_to_json).collect();
    json!(arr)
}

/// Generate PreIdentityObject out of the account holder information,
/// the chosen anonymity revoker information, and the necessary contextual
/// information (group generators, shared commitment keys, etc).
fn generate_pio<
    P: Pairing,
    AttributeType: Attribute<P::ScalarField>,
    C: Curve<Scalar = P::ScalarField>,
>(
    context: &Context<P, C>,
    aci: &AccCredentialInfo<P, AttributeType>,
) -> PreIdentityObject<P, AttributeType, C>
where
    AttributeType: Clone, {
    let mut csprng = thread_rng();
    let id_ah = aci.acc_holder_info.id_ah.clone();
    let id_cred_pub = aci.acc_holder_info.id_cred.id_cred_pub;
    let prf::SecretKey(prf_key_scalar) = aci.prf_key;
    // FIXME: The next item will change to encrypt by chunks to enable anonymity
    // revocation.
    let (prf_key_enc, prf_key_enc_rand) = context
        .ar_info
        .ar_public_key
        .encrypt_exponent_rand(&mut csprng, &prf_key_scalar);
    let id_ar_data = ArData {
        ar_name:  context.ar_info.ar_name.clone(),
        e_reg_id: prf_key_enc,
    };
    let alist = aci.attributes.clone();
    let pok_sc = dlog::prove_dlog(
        &mut csprng,
        &id_cred_pub.0,
        &aci.acc_holder_info.id_cred.id_cred_sec.0,
        &context.dlog_base,
    );
    let (cmm_prf, rand_cmm_prf) = context
        .commitment_key_id
        .commit(&pedersen::Value(vec![prf_key_scalar]), &mut csprng);
    let (snd_cmm_prf, rand_snd_cmm_prf) = context
        .commitment_key_ar
        .commit(&pedersen::Value(vec![prf_key_scalar]), &mut csprng);
    // now generate the proof that the commitment hidden in snd_cmm_prf is to
    // the same prf key as the one encrypted in id_ar_data via anonymity revokers
    // public key.
    let proof_com_enc_eq = {
        let public = (prf_key_enc.0, prf_key_enc.1, snd_cmm_prf.0);
        // TODO: Check that this order of secret values is correct!
        // FIXME: I think this is consistent with the way the protocol in the whitepaper
        // is written, but is different from what Bassel said it should be.
        let secret = (prf_key_enc_rand, prf_key_scalar, rand_snd_cmm_prf);
        let base = (
            context.ar_info.ar_elgamal_generator,
            context.ar_info.ar_public_key.0,
            context.commitment_key_ar.0[0],
            context.commitment_key_ar.1,
        );
        com_enc_eq::prove_com_enc_eq(&mut csprng, &public, &secret, &base)
    };
    let proof_com_eq = {
        let public = (cmm_prf.0, snd_cmm_prf.0);
        // TODO: Check that this is the correct order of secret values.
        let secret = (prf_key_scalar, rand_cmm_prf, rand_snd_cmm_prf);
        let coeff = (
            (context.commitment_key_id.0[0], context.commitment_key_id.1),
            (context.commitment_key_ar.0[0], context.commitment_key_ar.1),
        );
        com_eq_different_groups::prove_com_eq_diff_grps(&mut csprng, &public, &secret, &coeff)
    };
    PreIdentityObject {
        id_ah,
        id_cred_pub,
        id_ar_data,
        alist,
        pok_sc,
        cmm_prf,
        snd_cmm_prf,
        proof_com_enc_eq,
        proof_com_eq,
    }
}

fn ar_data_to_json<C: Curve>(ar_data: &ArData<C>) -> Value {
    json!({
        "arName": ar_data.ar_name.clone(),
        "prfKeyEncryption": json_base16_encode(&ar_data.e_reg_id.to_bytes())
    })
}

fn json_to_ar_data(v: &Value) -> Option<ArData<<Bls12 as Pairing>::G_1>> {
    let ar_name = v.get("arName")?.as_str()?;
    let e_reg_id = Cipher::from_bytes(&json_base16_decode(v.get("prfKeyEncryption")?)?).ok()?;
    Some(ArData {
        ar_name: ar_name.to_owned(),
        e_reg_id,
    })
}

fn pio_to_json(pio: &PreIdentityObject<Bls12, ExampleAttribute, <Bls12 as Pairing>::G_1>) -> Value {
    json!({
        "accountHolderName": pio.id_ah,
        "idCredPub": json_base16_encode(&pio.id_cred_pub.to_bytes()),
        "idArData": ar_data_to_json(&pio.id_ar_data),
        "attributeList": alist_to_json(&pio.alist),
        "pokSecCred": json_base16_encode(&pio.pok_sc.to_bytes()),
        "prfKeyCommitmentWithID": json_base16_encode(&pio.cmm_prf.to_bytes()),
        "prfKeyCommitmentWithAR": json_base16_encode(&pio.snd_cmm_prf.to_bytes()),
        "proofEncryptionPrf": json_base16_encode(&pio.proof_com_enc_eq.to_bytes()),
        "proofCommitmentsSame": json_base16_encode(&pio.proof_com_eq.to_bytes())
    })
}

fn json_to_pio(
    v: &Value,
) -> Option<PreIdentityObject<Bls12, ExampleAttribute, <Bls12 as Pairing>::G_1>> {
    let id_ah = v.get("accountHolderName")?.as_str()?.to_owned();
    let id_cred_pub = PublicKey::from_bytes(&json_base16_decode(v.get("idCredPub")?)?).ok()?;
    let id_ar_data = json_to_ar_data(v.get("idArData")?)?;
    let alist = json_to_alist(v.get("attributeList")?)?;
    let pok_sc =
        dlog::DlogProof::from_bytes(&mut Cursor::new(&json_base16_decode(v.get("pokSecCred")?)?))
            .ok()?;
    let cmm_prf =
        Commitment::from_bytes(&json_base16_decode(v.get("prfKeyCommitmentWithID")?)?).ok()?;
    let snd_cmm_prf =
        Commitment::from_bytes(&json_base16_decode(v.get("prfKeyCommitmentWithAR")?)?).ok()?;
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
        id_cred_pub,
        id_ar_data,
        alist,
        pok_sc,
        cmm_prf,
        snd_cmm_prf,
        proof_com_enc_eq,
        proof_com_eq,
    })
}

fn main() {
    let matches = App::new("Prototype client showcasing ID layer interactions.")
        .version("0. 0.36787944117")
        .author("Concordium")
        .subcommand(
            SubCommand::with_name("create_chi")
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
        .subcommand(
            SubCommand::with_name("generate_ips")
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
            SubCommand::with_name("generate_global")
                .about("Generate the global context of parameters."),
        )
        .subcommand(
            SubCommand::with_name("ip_sign_pio")
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
        .get_matches();
    if let Some(matches) = matches.subcommand_matches("create_chi") {
        if let Ok(name) = Input::new().with_prompt("Your name").interact() {
            let mut csprng = thread_rng();
            let secret = SecretKey::generate(&mut csprng);
            let public = PublicKey::from(&secret);
            let ah_info = CredentialHolderInfo::<Bls12> {
                id_ah:   name,
                id_cred: IdCredentials {
                    id_cred_sec: secret.clone(),
                    id_cred_pub: public,
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
                output_json(&js);
            }
        } else {
            eprintln!("You need to provide a name. Terminating.");
        }
    }
    if let Some(matches) = matches.subcommand_matches("start_ip") {
        handle_start_ip(matches);
    }
    if let Some(matches) = matches.subcommand_matches("generate_ips") {
        handle_generate_ips(matches);
    }
    if let Some(matches) = matches.subcommand_matches("generate_global") {
        handle_generate_global(matches);
    }
    if let Some(matches) = matches.subcommand_matches("ip_sign_pio") {
        handle_act_as_ip(matches);
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
    let global_ctx = {
        if let Some(gc) = read_global_context() {
            gc
        } else {
            eprintln!("Cannot read global context information database. Terminating.");
            return;
        }
    };
    let ctx = make_context_from_ip_info(&ip_info, &global_ctx);

    let aux_data = AuxData {
        id_cred_base:   ctx.dlog_base,
        ps_public_key:  ip_info.id_verify_key.clone(),
        ps_secret_key:  ip_sec_key,
        comm_2_params:  CommitmentParams((ctx.commitment_key_ar.0[0], ctx.commitment_key_ar.1)),
        elgamal_params: ElgamalParams((
            ctx.ar_info.ar_elgamal_generator,
            ctx.ar_info.ar_public_key.0,
        )),
        ar_info:        ctx.ar_info,
    };
    let vf = verify_credentials(&pio, aux_data);
    match vf {
        Ok(sig) => {
            println!("Successfully checked pre-identity data.");
            let sig_bytes = &sig.to_bytes();
            if let Some(signed_out_path) = matches.value_of("out") {
                let js = json!({
                    "preIdentityObject": pio_to_json(&pio),
                    "signature": json_base16_encode(sig_bytes)
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
            .map(json_to_chi::<Bls12>)
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
    let alist = {
        match read_attribute_list(alist_type as u32) {
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
            variant: 0,
            alist,
            _phantom: Default::default(),
        },
    };

    // now choose an identity provider we load the identity providers from the
    // database.
    let ips = {
        if let Some(ips) = read_identity_providers() {
            ips
        } else {
            eprintln!("Cannot read identity providers from the database. Terminating.");
            return;
        }
    };
    // we also read the global context from another json file
    let global_ctx = {
        if let Some(gc) = read_global_context() {
            gc
        } else {
            eprintln!("Cannot read global context information database. Terminating.");
            return;
        }
    };

    // names of identity providers the user can choose from, together with the
    // names of anonymity revokers associated with them
    let ips_names: Vec<_> = ips
        .iter()
        .map(|x| {
            format!(
                "Identity provider {}, its anonymity revoker is {}",
                &x.id_identity, &x.ar_info.ar_name
            )
        })
        .collect();
    let ip_info = {
        if let Ok(ip_info_idx) = Select::new()
            .with_prompt("Choose identity provider")
            .items(&ips_names)
            .default(0)
            .interact()
        {
            &ips[ip_info_idx]
        } else {
            eprintln!("You have to choose an identity provider. Terminating.");
            return;
        }
    };

    let context = make_context_from_ip_info(ip_info, &global_ctx);
    // and finally generate the pre-identity object
    let pio = generate_pio(&context, &aci);

    // the only thing left is to output all the information

    let js = aci_to_json(&aci);
    if let Some(aci_out_path) = matches.value_of("private") {
        if write_json_to_file(aci_out_path, &js).is_ok() {
            println!("Wrote ACI data to file.");
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
            id_identity: mk_ip_name(id),
            id_verify_key: id_public_key,
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
    // let mut csprng = thread_rng();
    let gc = GlobalContext {
        dlog_base: PublicKey::generator(),
    };
    write_json_to_file(GLOBAL_CONTEXT, &global_context_to_json(&gc)).ok()
}
