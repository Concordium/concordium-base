use dodis_yampolskiy_prf::secret as prf;
use elgamal::cipher::Cipher;
use hex::{decode, encode};
use id::{ffi::*, secret_sharing::*, types::*};
use pairing::bls12_381::Bls12;
use ps_sig;

use chrono::NaiveDateTime;

use serde_json::{json, to_string_pretty, Map, Value};

use pedersen_scheme::{commitment::Commitment, key as pedersen_key, Value as PedersenValue};

use curve_arithmetic::curve_arithmetic::*;
use id::sigma_protocols::{com_enc_eq::*, com_eq, com_eq_different_groups, dlog};

use std::{
    convert::TryFrom,
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
        eprintln!("illformed ips file");
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

pub fn read_json_from_file<P: AsRef<Path>>(path: P) -> io::Result<Value>
where
    P: std::fmt::Debug, {
    let file = File::open(path)?;

    let reader = BufReader::new(file);
    let u = serde_json::from_reader(reader)?;
    Ok(u)
}

pub fn json_base16_encode(v: &[u8]) -> Value { json!(encode(v)) }

pub fn json_base16_decode(v: &Value) -> Option<Vec<u8>> { decode(v.as_str()?).ok() }

pub fn chi_to_json<C: Curve>(chi: &CredentialHolderInfo<C>) -> Value {
    json!({
        "name": chi.id_ah,
        "idCredSecret": encode(C::scalar_to_bytes(&chi.id_cred.id_cred_sec)),
    })
}

pub fn json_to_chi<C: Curve>(js: &Value) -> Option<CredentialHolderInfo<C>> {
    let id_cred_sec = PedersenValue {
        value: C::bytes_to_scalar(m_json_decode!(js, "idCredSecret")).ok()?,
    };
    let id_ah = js["name"].as_str()?;
    let info: CredentialHolderInfo<C> = CredentialHolderInfo {
        id_ah:   id_ah.to_owned(),
        id_cred: IdCredentials { id_cred_sec },
    };
    Some(info)
}

pub fn aci_to_json(aci: &AccCredentialInfo<ExampleCurve, ExampleAttribute>) -> Value {
    let chi = chi_to_json(&aci.acc_holder_info);
    json!({
        "credentialHolderInformation": chi,
        "prfKey": json_base16_encode(&aci.prf_key.to_bytes()),
        "attributes": alist_to_json(&aci.attributes),
    })
}

pub fn json_to_aci(
    v: &Value,
) -> Option<AccCredentialInfo<<Bls12 as Pairing>::G_1, ExampleAttribute>> {
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

pub fn json_read_u32(v: &Map<String, Value>, key: &str) -> Option<u32> {
    u32::try_from(v.get(key)?.as_u64()?).ok()
}

pub fn json_read_u64(v: &Map<String, Value>, key: &str) -> Option<u64> { v.get(key)?.as_u64() }

pub fn json_read_u8(v: &Map<String, Value>, key: &str) -> Option<u8> {
    u8::try_from(v.get(key)?.as_u64()?).ok()
}

pub fn json_to_global_context(v: &Value) -> Option<GlobalContext<ExampleCurve>> {
    let obj = v.as_object()?;
    let cmk_bytes = obj
        .get("onChainCommitmentKey")
        .and_then(json_base16_decode)?;
    let cmk = pedersen_key::CommitmentKey::from_bytes(&mut Cursor::new(&cmk_bytes)).ok()?;
    let gc = GlobalContext {
        on_chain_commitment_key: cmk,
    };
    Some(gc)
}

pub fn json_to_ip_infos(v: &Value) -> Option<Vec<IpInfo<Bls12, ExampleCurve>>> {
    let ips_arr = v.as_array()?;
    ips_arr.iter().map(IpInfo::from_json).collect()
}

pub fn ip_infos_to_json(ipinfos: &[IpInfo<Bls12, <Bls12 as Pairing>::G_1>]) -> Value {
    let arr: Vec<Value> = ipinfos.iter().map(IpInfo::to_json).collect();
    json!(arr)
}

pub fn ip_ar_data_to_json<C: Curve>(ar_data: &IpArData<C>) -> Value {
    json!({
        "arIdentity": ar_data.ar_identity.to_json(),
        "encPrfKeyShare": json_base16_encode(&ar_data.enc_prf_key_share.to_bytes()),
        "prfKeyShareNumber": ar_data.prf_key_share_number.to_json(),
        "proofComEncEq" : json_base16_encode(&ar_data.proof_com_enc_eq.to_bytes()),
    })
}

pub fn json_to_ip_ar_data(v: &Value) -> Option<IpArData<ExampleCurve>> {
    let ar_identity = ArIdentity::from_json(v.get("arIdentity")?)?;
    // let ar_description = v.as_object()?.get("arDescription")?.as_str()?;
    let enc_prf_key_share = Cipher::from_bytes(m_json_decode!(v, "encPrfKeyShare")).ok()?;
    let prf_key_share_number = ShareNumber::from_json(v.get("prfKeyShareNumber")?)?;
    let proof_com_enc_eq = ComEncEqProof::from_bytes(m_json_decode!(v, "proofComEncEq")).ok()?;

    Some(IpArData {
        ar_identity,
        enc_prf_key_share,
        prf_key_share_number,
        proof_com_enc_eq,
    })
}

pub fn chain_ar_data_to_json<C: Curve>(ar_data: &[ChainArData<C>]) -> Value {
    let arr: Vec<Value> = ar_data.iter().map(ChainArData::to_json).collect();
    json!(arr)
}

pub fn json_to_chain_ar_data(v: &Value) -> Option<Vec<ChainArData<ExampleCurve>>> {
    let ar_data_arr = v.as_array()?;
    ar_data_arr.iter().map(ChainArData::from_json).collect()
}

pub fn pio_to_json(pio: &PreIdentityObject<Bls12, ExampleCurve, ExampleAttribute>) -> Value {
    let arr: Vec<Value> = pio.ip_ar_data.iter().map(ip_ar_data_to_json).collect();
    let prf_arr: Vec<Value> = pio
        .cmm_prf_sharing_coeff
        .iter()
        .map(|x| json_base16_encode(&x.to_bytes()))
        .collect();
    json!({
        "accountHolderName": pio.id_ah,
        "idCredPub": json_base16_encode(&pio.id_cred_pub.curve_to_bytes()),
        "ipArData": json!(arr),
        "choiceArData":pio.choice_ar_parameters.0.iter().map(|&x| ArIdentity::to_json(x)).collect::<Vec<Value>>(),
        "revocationThreshold":pio.choice_ar_parameters.1.to_json(),
        "attributeList": alist_to_json(&pio.alist),
        "pokSecCred": json_base16_encode(&pio.pok_sc.to_bytes()),
        "sndPokSecCred": json_base16_encode(&pio.snd_pok_sc.to_bytes()),
        "idCredSecCommitment": json_base16_encode(&pio.cmm_sc.to_bytes()),
        "proofCommitmentsToIdCredSecSame": json_base16_encode(&pio.proof_com_eq_sc.to_bytes()),
        "prfKeyCommitmentWithID": json_base16_encode(&pio.cmm_prf.to_bytes()),
        "prfKeySharingCoeffCommitments": json!(prf_arr),
        "proofCommitmentsSame": json_base16_encode(&pio.proof_com_eq.to_bytes()),
    })
}

pub fn json_to_pio(v: &Value) -> Option<PreIdentityObject<Bls12, ExampleCurve, ExampleAttribute>> {
    let id_ah = v.get("accountHolderName")?.as_str()?.to_owned();
    let id_cred_pub = ExampleCurve::bytes_to_curve(m_json_decode!(v, "idCredPub")).ok()?;
    let ip_ar_data_arr: &Vec<Value> = v.get("ipArData")?.as_array()?;
    let ip_ar_data: Vec<IpArData<ExampleCurve>> = ip_ar_data_arr
        .iter()
        .map(json_to_ip_ar_data)
        .collect::<Option<Vec<IpArData<ExampleCurve>>>>(
    )?;
    let choice_ar_data: Vec<ArIdentity> = v
        .get("choiceArData")?
        .as_array()?
        .iter()
        .map(ArIdentity::from_json)
        .collect::<Option<Vec<ArIdentity>>>()?;
    let revocation_threshold: Threshold = Threshold::from_json(v.get("revocationThreshold")?)?;
    let alist = json_to_alist(v.get("attributeList")?)?;
    let pok_sc =
        dlog::DlogProof::from_bytes(&mut Cursor::new(&json_base16_decode(v.get("pokSecCred")?)?))
            .ok()?;
    let snd_pok_sc = com_eq::ComEqProof::from_bytes(&mut Cursor::new(&json_base16_decode(
        v.get("sndPokSecCred")?,
    )?))
    .ok()?;
    let cmm_sc = Commitment::from_bytes(m_json_decode!(v, "idCredSecCommitment")).ok()?;
    let proof_com_eq_sc = com_eq::ComEqProof::from_bytes(&mut Cursor::new(&json_base16_decode(
        v.get("proofCommitmentsToIdCredSecSame")?,
    )?))
    .ok()?;
    let cmm_prf = Commitment::from_bytes(m_json_decode!(v, "prfKeyCommitmentWithID")).ok()?;
    let cmm_prf_values: Vec<Value> = v.get("prfKeySharingCoeffCommitments")?.as_array()?.clone();
    let mut cmm_prf_sharing_coeff = vec![];
    for item in cmm_prf_values.iter() {
        match Commitment::from_bytes(&mut Cursor::new(json_base16_decode(item)?.as_slice())) {
            Err(_) => return None,
            Ok(x) => cmm_prf_sharing_coeff.push(x),
        }
    }

    let proof_com_eq = com_eq_different_groups::ComEqDiffGrpsProof::from_bytes(&mut Cursor::new(
        &json_base16_decode(v.get("proofCommitmentsSame")?)?,
    ))
    .ok()?;
    Some(PreIdentityObject {
        id_ah,
        id_cred_pub,
        ip_ar_data,
        choice_ar_parameters: (choice_ar_data, revocation_threshold),
        alist,
        pok_sc,
        snd_pok_sc,
        cmm_sc,
        proof_com_eq_sc,
        cmm_prf,
        cmm_prf_sharing_coeff,
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
    let ip_info = IpInfo::from_json(v.get("publicIdInfo")?)?;
    Some((ip_info, id_cred_sec))
}

pub fn ip_data_to_json(v: &IpData) -> Value {
    json!({
        "idPrivateKey": json_base16_encode(&v.1.to_bytes()),
        "publicIdInfo": v.0.to_json()
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
