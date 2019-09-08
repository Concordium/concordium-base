use curve_arithmetic::{Curve, Pairing};
use dodis_yampolskiy_prf::secret as prf;
use ed25519_dalek as ed25519;
use elgamal::cipher::Cipher;
use hex::{decode, encode};
use id::{ffi::*, types::*};
use pairing::bls12_381::Bls12;
use ps_sig;

use chrono::NaiveDateTime;

use serde_json::{json, to_string_pretty, Map, Value};

use pedersen_scheme::{commitment::Commitment, key as pedersen_key};

use sigma_protocols::{com_enc_eq, com_eq, com_eq_different_groups};

use std::{
    convert::TryFrom,
    fmt::Display,
    fs::File,
    io::{self, BufReader, Cursor, Error, ErrorKind, Write},
    path::Path,
    str::FromStr,
};

pub type ExampleCurve = <Bls12 as Pairing>::G_1;

pub type ExampleAttribute = AttributeKind;

pub type ExampleAttributeList = AttributeList<<Bls12 as Pairing>::ScalarField, ExampleAttribute>;

macro_rules! m_json_decode {
    ($val:expr, $key:expr) => {
        &mut Cursor::new(&json_base16_decode($val.get($key)?)?)
    };
}

pub static GLOBAL_CONTEXT: &str = "database/global.json";
pub static IDENTITY_PROVIDERS: &str = "database/identity_providers.json";

pub fn read_global_context(filename: &str) -> Option<GlobalContext<ExampleCurve>> {
    if let Ok(Some(gc)) = read_json_from_file(filename)
        .as_ref()
        .map(json_to_global_context)
    {
        Some(gc)
    } else {
        None
    }
}

pub fn read_identity_providers() -> Option<Vec<IpInfo<Bls12, <Bls12 as Pairing>::G_1>>> {
    if let Ok(Some(ips)) = read_json_from_file(IDENTITY_PROVIDERS)
        .as_ref()
        .map(json_to_ip_infos)
    {
        Some(ips)
    } else {
        None
    }
}

/// Show fields of the type of fields of the given attribute list.
pub fn show_attribute_format(variant: u16) -> &'static str {
    match variant {
        0 => "[ExpiryDate, MaxAccount, Age]",
        1 => "[ExpiryDate, MaxAccount, Age, Citizenship, Business]",
        _ => unimplemented!("Only two formats of attribute lists supported."),
    }
}

pub fn show_attribute(variant: u16, idx: usize, att: &ExampleAttribute) -> String {
    format!("{}: {}", ATTRIBUTE_LISTS[variant as usize][idx], att)
}

pub fn parse_expiry_date(input: &str) -> io::Result<u64> {
    let mut input = input.to_owned();
    input.push_str(" 23:59:59");
    let dt = NaiveDateTime::parse_from_str(&input, "%d %B %Y %H:%M:%S")
        .map_err(|x| Error::new(ErrorKind::Other, x.to_string()))?;
    Ok(dt.timestamp() as u64)
}

pub fn write_json_to_file(filepath: &str, js: &Value) -> io::Result<()> {
    let path = Path::new(filepath);
    let mut file = File::create(&path)?;
    file.write_all(to_string_pretty(js).unwrap().as_bytes())
}

/// Output json to standard output.
pub fn output_json(js: &Value) {
    println!("{}", to_string_pretty(js).unwrap());
}

pub fn read_json_from_file<P: AsRef<Path>>(path: P) -> io::Result<Value> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let u = serde_json::from_reader(reader)?;
    Ok(u)
}

pub fn json_base16_encode(v: &[u8]) -> Value { json!(encode(v)) }

pub fn json_base16_decode(v: &Value) -> Option<Vec<u8>> { decode(v.as_str()?).ok() }

pub fn chi_to_json<C: Curve, T: Curve<Scalar = C::Scalar>>(
    chi: &CredentialHolderInfo<C, T>,
) -> Value {
    json!({
        "name": chi.id_ah,
        "idCredPublicIP": encode(chi.id_cred.id_cred_pub_ip.curve_to_bytes()),
        "idCredPublic": encode(chi.id_cred.id_cred_pub.curve_to_bytes()),
        "idCredSecret": encode(C::scalar_to_bytes(&chi.id_cred.id_cred_sec)),
    })
}

pub fn json_to_chi<C: Curve, T: Curve<Scalar = C::Scalar>>(
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

pub fn json_to_account_data(v: &Value) -> Option<AccountData> {
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

pub fn account_data_to_json(acc: &AccountData) -> Value {
    json!({
        "verifyKey": json_base16_encode(acc.verify_key.as_bytes()),
        "signKey": json_base16_encode(acc.sign_key.as_bytes()),
    })
}

pub fn aci_to_json(
    aci: &AccCredentialInfo<Bls12, <Bls12 as Pairing>::G_1, ExampleAttribute>,
) -> Value {
    let chi = chi_to_json(&aci.acc_holder_info);
    json!({
        "credentialHolderInformation": chi,
        "prfKey": json_base16_encode(&aci.prf_key.to_bytes()),
        "attributes": alist_to_json(&aci.attributes),
    })
}

pub fn json_to_aci(
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

pub fn global_context_to_json(global: &GlobalContext<ExampleCurve>) -> Value {
    json!({"dLogBaseChain": json_base16_encode(&global.dlog_base_chain.curve_to_bytes()),
           "onChainCommitmentKey": json_base16_encode(&global.on_chain_commitment_key.to_bytes()),
    })
}

pub fn json_read_u32(v: &Map<String, Value>, key: &str) -> Option<u32> {
    u32::try_from(v.get(key)?.as_u64()?).ok()
}

pub fn json_read_u8(v: &Map<String, Value>, key: &str) -> Option<u8> {
    u8::try_from(v.get(key)?.as_u64()?).ok()
}

pub fn json_to_global_context(v: &Value) -> Option<GlobalContext<ExampleCurve>> {
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

pub fn policy_to_json<C: Curve, AttributeType: Attribute<C::Scalar>>(
    policy: &Policy<C, AttributeType>,
) -> Value
where
    AttributeType: Display, {
    let revealed: Vec<Value> = policy
        .policy_vec
        .iter()
        .map(|(idx, value)| json!({"index": idx, "value": format!("{}", value)}))
        .collect();
    json!({
        "variant": policy.variant,
        "expiry": policy.expiry,
        "revealedItems": revealed
    })
}

pub fn json_to_ip_info(ip_val: &Value) -> Option<IpInfo<Bls12, <Bls12 as Pairing>::G_1>> {
    let ip_val = ip_val.as_object()?;
    let ip_identity = json_read_u32(ip_val, "ipIdentity")?;
    let ip_description = ip_val.get("ipDescription")?.as_str()?;
    let ip_verify_key = ps_sig::PublicKey::from_bytes(&mut Cursor::new(&json_base16_decode(
        ip_val.get("ipVerifyKey")?,
    )?))
    .ok()?;
    let id_ar_identity = json_read_u32(ip_val, "arIdentity")?;
    let id_ar_description = ip_val.get("arDescription")?.as_str()?;
    let id_ar_public_key =
        elgamal::PublicKey::from_bytes(m_json_decode!(ip_val, "arPublicKey")).ok()?;
    let id_ar_elgamal_generator =
        Curve::bytes_to_curve(m_json_decode!(ip_val, "arElgamalGenerator")).ok()?;
    Some(IpInfo {
        ip_identity,
        ip_description: ip_description.to_owned(),
        ip_verify_key,
        ar_info: ArInfo {
            ar_identity:          id_ar_identity,
            ar_description:       id_ar_description.to_owned(),
            ar_public_key:        id_ar_public_key,
            ar_elgamal_generator: id_ar_elgamal_generator,
        },
    })
}

pub fn json_to_ip_infos(v: &Value) -> Option<Vec<IpInfo<Bls12, ExampleCurve>>> {
    let ips_arr = v.as_array()?;
    ips_arr.iter().map(json_to_ip_info).collect()
}

pub fn ip_info_to_json(ipinfo: &IpInfo<Bls12, <Bls12 as Pairing>::G_1>) -> Value {
    json!({
                                   "ipIdentity": ipinfo.ip_identity,
                                   "ipDescription": ipinfo.ip_description,
                                   "ipVerifyKey": json_base16_encode(&ipinfo.ip_verify_key.to_bytes()),
                                   "arIdentity": ipinfo.ar_info.ar_identity,
                                   "arDescription": ipinfo.ar_info.ar_description,
                                   "arPublicKey": json_base16_encode(&ipinfo.ar_info.ar_public_key.to_bytes()),
                                   "arElgamalGenerator": json_base16_encode(&ipinfo.ar_info.ar_elgamal_generator.curve_to_bytes())
    })
}

pub fn ip_infos_to_json(ipinfos: &[IpInfo<Bls12, <Bls12 as Pairing>::G_1>]) -> Value {
    let arr: Vec<Value> = ipinfos.iter().map(ip_info_to_json).collect();
    json!(arr)
}

pub fn ip_ar_data_to_json<C: Curve>(ar_data: &IpArData<C>) -> Value {
    json!({
        "arIdentity": ar_data.ar_identity,
        "arDescription": ar_data.ar_description.clone(),
        "prfKeyEncryption": json_base16_encode(&ar_data.prf_key_enc.to_bytes()),
    })
}

pub fn json_to_ip_ar_data(v: &Value) -> Option<IpArData<ExampleCurve>> {
    let ar_identity = json_read_u32(v.as_object()?, "arIdentity")?;
    let ar_description = v.as_object()?.get("arDescription")?.as_str()?;
    let prf_key_enc = Cipher::from_bytes(m_json_decode!(v, "prfKeyEncryption")).ok()?;
    Some(IpArData {
        ar_identity,
        ar_description: ar_description.to_owned(),
        prf_key_enc,
    })
}

pub fn chain_ar_data_to_json<C: Curve>(ar_data: &ChainArData<C>) -> Value {
    json!({
        "arIdentity": ar_data.ar_identity,
        "idCredPubEnc": json_base16_encode(&ar_data.id_cred_pub_enc.to_bytes()),
    })
}

pub fn json_to_chain_ar_data(v: &Value) -> Option<ChainArData<ExampleCurve>> {
    let ar_identity = json_read_u32(v.as_object()?, "arIdentity")?;
    let id_cred_pub_enc = Cipher::from_bytes(m_json_decode!(v, "idCredPubEnc")).ok()?;
    Some(ChainArData {
        ar_identity,
        id_cred_pub_enc,
    })
}

pub fn pio_to_json(pio: &PreIdentityObject<Bls12, ExampleCurve, ExampleAttribute>) -> Value {
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

pub fn json_to_pio(v: &Value) -> Option<PreIdentityObject<Bls12, ExampleCurve, ExampleAttribute>> {
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

/// Private and public data on an identity provider.
pub type IpData = (IpInfo<Bls12, ExampleCurve>, ps_sig::SecretKey<Bls12>);

pub fn json_to_ip_data(v: &Value) -> Option<IpData> {
    let id_cred_sec = ps_sig::SecretKey::from_bytes(&mut Cursor::new(&json_base16_decode(
        v.get("idPrivateKey")?,
    )?))
    .ok()?;
    let ip_info = json_to_ip_info(v.get("publicIdInfo")?)?;
    Some((ip_info, id_cred_sec))
}

pub fn ip_data_to_json(v: &IpData) -> Value {
    json!({
        "idPrivateKey": json_base16_encode(&v.1.to_bytes()),
        "publicIdInfo": ip_info_to_json(&v.0)
    })
}

static ALIST_BASIC_PERSON: &[&str] = &[
    "maxAccount",
    "creationTime",
    "birthYear",
    "residenceCountryCode",
];

static ALIST_ACCREDITED_INVESTOR: &[&str] = &[
    "maxAccount",
    "creationTime",
    "residenceCountryCode",
    "assetsOwnedLB",
];

static ALIST_DRIVER: &[&str] = &[
    "maxAccount",
    "creationTime",
    "birthYear",
    "residenceCountryCode",
    "drivingLicenseCountryCode",
    "drivingLicenseIssueDate",
    "drivingLicenseExpiry",
    "drivingLicenseCategories",
];

static ALIST_BASIC_COMPANY: &[&str] = &[
    "maxAccount",
    "creationTime",
    "registrationCountryCode",
    "isEUVAT",
    "VATNumber",
];

static ALIST_BASIC_VEHICLE: &[&str] = &[
    "maxAccount",
    "creationTime",
    "brandId",
    "registrationCountryCode",
    "vehicleClass",
    "numPassengerSeats",
    "modelYear",
    "productionYear",
    "modelId",
    "engineType",
    "engineSize",
    "VIN",
];

static ALIST_BASIC_IOT: &[&str] = &[
    "maxAccount",
    "creationTime",
    "deviceType",
    "deviceManufacturer",
    "deviceSerial",
    "deviceSpecific1",
    "deviceSpecific2",
    "deviceSpecific3",
];

pub static ATTRIBUTE_LISTS: &[&[&str]] = &[
    ALIST_BASIC_PERSON,
    ALIST_ACCREDITED_INVESTOR,
    ALIST_DRIVER,
    ALIST_BASIC_COMPANY,
    ALIST_BASIC_VEHICLE,
    ALIST_BASIC_IOT,
];

// index of the attribute in the list, if such a thing exists
pub fn attribute_index(variant: u16, s: &str) -> Option<u16> {
    let variant = variant as usize;
    if variant < ATTRIBUTE_LISTS.len() {
        let i = ATTRIBUTE_LISTS[variant].iter().position(|x| *x == s)?;
        Some(i as u16)
    } else {
        None
    }
}

pub fn alist_to_json(alist: &ExampleAttributeList) -> Value {
    let mut mp = Map::with_capacity(2);
    mp.insert("variant".to_owned(), Value::from(alist.variant.to_string()));
    mp.insert(
        "expiryDate".to_owned(),
        Value::from(alist.expiry.to_string()),
    );
    if (alist.variant as usize) < ATTRIBUTE_LISTS.len()
        && alist.alist.len() == ATTRIBUTE_LISTS[alist.variant as usize].len()
    {
        let keys = ATTRIBUTE_LISTS[alist.variant as usize];
        for (i, v) in alist.alist.iter().enumerate() {
            mp.insert(keys[i].to_string(), Value::from(v.to_string()));
        }
        Value::Object(mp)
    } else {
        Value::Null
    }
}

/// Either parse a string wrapped uint or an uint itself.
pub fn parse_u64(v: &Value) -> Option<u64> {
    v.as_u64().or_else(|| u64::from_str(v.as_str()?).ok())
}

pub fn json_to_alist(v: &Value) -> Option<ExampleAttributeList> {
    let obj = v.as_object()?;
    // either parse a string wrapped int or an int itself.
    let variant = obj.get("variant").and_then(parse_u64)?;
    // either parse a string wrapped int or an int itself.
    let expiry = obj.get("expiryDate").and_then(parse_u64)?;
    if (variant as usize) < ATTRIBUTE_LISTS.len() {
        let keys = ATTRIBUTE_LISTS[variant as usize];
        let mut alist = Vec::with_capacity(keys.len());
        for key in keys {
            let val = v.get(key)?;
            if let Some(u) = parse_u64(val) {
                alist.push(AttributeKind::from(u))
            } else {
                alist.push(AttributeKind::from_str(val.as_str()?).ok()?)
            }
        }
        Some(AttributeList {
            variant: variant as u16,
            expiry,
            alist,
            _phantom: Default::default(),
        })
    } else {
        None
    }
}
