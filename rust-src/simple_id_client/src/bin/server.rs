use pairing::bls12_381::Bls12;
use ps_sig as pssig;

use dodis_yampolskiy_prf::secret as prf;
use ed25519_dalek as ed25519;
use id::{account_holder::*, identity_provider::*, types::*};
use ps_sig::SigRetrievalRandomness;
use std::collections::btree_map::BTreeMap;

use client_server_helpers::*;
use curve_arithmetic::Curve;

use rand::*;
use serde_json::{json, to_string_pretty, Value};

use clap::{App, AppSettings, Arg};
use id::secret_sharing::Threshold;
use pedersen_scheme::Value as PedersenValue;
use std::cmp::max;

use either::Either::{Left, Right};
use std::collections::HashMap;

// server imports
#[macro_use]
extern crate rouille;

/// Public and **private** data about identity providers.
type IpInfos = HashMap<IpIdentity, IpData>;

struct ServerState {
    /// Public and private information about the identity providers.
    /// This also contains information about
    ip_infos: IpInfos,
    /// Global parameters, such as various commitment keys, global parameters
    /// for sigma proofs, etc.
    global_params: GlobalContext<ExampleCurve>,
}

fn respond_global_params(_request: &rouille::Request, s: &ServerState) -> rouille::Response {
    let response = to_string_pretty(&s.global_params.to_json()).unwrap();
    rouille::Response::text(response)
}

fn respond_ips(_request: &rouille::Request, s: &ServerState) -> rouille::Response {
    let response: Vec<Value> = s.ip_infos.iter().map(|id| (id.1).0.to_json()).collect();
    rouille::Response::json(&json!(response))
}

fn parse_id_object_input_json(
    v: &Value,
) -> Option<(
    IpIdentity,
    String,
    Threshold,
    Vec<ArIdentity>,
    ExampleAttributeList,
)> {
    let ip_id = IpIdentity::from_json(v.get("ipIdentity")?)?;
    let user_name = v.get("name")?.as_str()?.to_owned();
    let ar_values = v.get("anonymityRevokers")?.as_array()?;
    let ars: Vec<ArIdentity> = ar_values
        .iter()
        .map(ArIdentity::from_json)
        .collect::<Option<Vec<ArIdentity>>>()?;
    // default threshold is one less than the amount of anonymity revokers
    // if the field "threshold" is not present this is what we take.
    let threshold = match v.get("threshold") {
        None => Threshold(max(1, ars.len() - 1) as u32),
        Some(v) => Threshold::from_json(v)?,
    };
    let alist = json_to_alist(v.get("attributes")?)?;
    Some((ip_id, user_name, threshold, ars, alist))
}

fn respond_id_object(request: &rouille::Request, s: &ServerState) -> rouille::Response {
    let v: Value = try_or_400!(rouille::input::json_input(request));
    let (ip_info, name, threshold, ar_list, attributes) = {
        if let Some((ip_id, name, threshold, ar_list, att)) = parse_id_object_input_json(&v) {
            match s.ip_infos.get(&ip_id) {
                Some(ip_info) => (ip_info, name, threshold, ar_list, att),
                None => return rouille::Response::empty_400(),
            }
        } else {
            return rouille::Response::empty_400();
        }
    };

    let mut csprng = thread_rng();
    // generate the prf key
    let prf_key = prf::SecretKey::generate(&mut csprng);

    let secret = ExampleCurve::generate_scalar(&mut csprng);
    let chi = CredentialHolderInfo::<ExampleCurve> {
        id_ah:   name,
        id_cred: IdCredentials {
            id_cred_sec: PedersenValue { value: secret },
        },
    };

    let aci = AccCredentialInfo {
        cred_holder_info: chi,
        prf_key,
        attributes,
    };

    let (ip_info, ip_sec_key) = ip_info;

    let context = make_context_from_ip_info(ip_info.clone(), (ar_list, threshold));
    let (pio, randomness) = generate_pio(&context, &aci);

    let vf = verify_credentials(&pio, &ip_info, &ip_sec_key);
    match vf {
        Ok(sig) => {
            let response = json!({
                "preIdentityObject": pio_to_json(&pio),
                "signature": json_base16_encode(&sig),
                "ipIdentity": ip_info.ip_identity.to_json(),
                "privateData": json!({
                    "aci": aci_to_json(&aci),
                    "pioRandomness": json_base16_encode(&randomness)
                })
            });
            rouille::Response::json(&response)
        }
        Err(_) => rouille::Response::empty_400(),
    }
}

type GenerateCredentialData = (
    IpIdentity,
    PreIdentityObject<Bls12, ExampleCurve, ExampleAttribute>,
    pssig::Signature<Bls12>,
    SigRetrievalRandomness<Bls12>,
    AccCredentialInfo<ExampleCurve, ExampleAttribute>,
    BTreeMap<u16, ExampleAttribute>,
    u8,
);

fn parse_generate_credential_input_json(v: &Value) -> Option<GenerateCredentialData> {
    let ip_id = IpIdentity::from_json(v.get("ipIdentity")?)?;
    let sig = v.get("signature").and_then(json_base16_decode)?;
    let pio = json_to_pio(v.get("preIdentityObject")?)?;
    let private = v.get("privateData")?;
    let randomness = private.get("pioRandomness").and_then(json_base16_decode)?;
    let aci = json_to_aci(private.get("aci")?)?;
    let policy_items = {
        if let Some(items) = v.get("revealedItems") {
            read_revealed_items(pio.alist.variant, &pio.alist.alist, items)?
        } else {
            BTreeMap::new()
        }
    };
    let n_acc = json_read_u8(v.as_object()?, "accountNumber")?;
    Some((ip_id, pio, sig, randomness, aci, policy_items, n_acc))
}

fn respond_generate_credential(request: &rouille::Request, s: &ServerState) -> rouille::Response {
    let v: Value = try_or_400!(rouille::input::json_input(request));

    let (ip_info, pio, sig, sig_randomness, aci, policy, n_acc) = {
        if let Some((ip_id, pio, sig, sig_randomness, aci, items, n_acc)) =
            parse_generate_credential_input_json(&v)
        {
            match s.ip_infos.get(&ip_id) {
                Some(ref ip_info) => {
                    let policy: Policy<ExampleCurve, ExampleAttribute> = Policy {
                        variant:    pio.alist.variant,
                        expiry:     pio.alist.expiry,
                        policy_vec: items,
                        _phantom:   Default::default(),
                    };
                    (&ip_info.0, pio, sig, sig_randomness, aci, policy, n_acc)
                }
                None => return rouille::Response::empty_400(),
            }
        } else {
            return rouille::Response::empty_400();
        }
    };
    // if account data is present then use it.
    let acc_data = {
        if let Some(acc_data) = v.get("accountData").and_then(AccountData::from_json) {
            acc_data
        } else {
            let mut keys = BTreeMap::new();
            let mut csprng = thread_rng();
            keys.insert(KeyIndex(0), ed25519::Keypair::generate(&mut csprng));
            keys.insert(KeyIndex(1), ed25519::Keypair::generate(&mut csprng));
            keys.insert(KeyIndex(2), ed25519::Keypair::generate(&mut csprng));

            AccountData {
                keys,
                existing: Left(SignatureThreshold(2)),
            }
        }
    };

    let cdi = generate_cdi(
        ip_info,
        &s.global_params,
        &aci,
        &pio,
        n_acc,
        &sig,
        &policy,
        &acc_data,
        &sig_randomness,
    );

    let cdi_json = cdi.to_json();

    let address = match acc_data.existing {
        Left(_) => AccountAddress::new(&cdi.values.reg_id),
        Right(addr) => addr,
    };

    let response = json!({
        "credential": cdi_json,
        "accountData": acc_data.to_json(),
        "accountAddress": address.to_json(),
    });
    rouille::Response::json(&response)
}

fn read_revealed_items(
    variant: u16,
    alist: &[ExampleAttribute],
    v: &Value,
) -> Option<BTreeMap<u16, ExampleAttribute>> {
    let arr: &Vec<Value> = v.as_array()?;
    let result = arr.iter().flat_map(|v| {
        let s = v.as_str()?;
        let idx = attribute_index(variant, s)?;
        if (idx as usize) < alist.len() {
            Some((idx, alist[idx as usize]))
        } else {
            None
        }
    });
    Some(result.collect())
}

// TODO: Pass filename as parameter
fn read_ip_infos(filename: &str) -> Option<IpInfos> {
    let v = read_json_from_file(filename).ok()?;
    let v = v.as_array()?;
    let mut r = HashMap::with_capacity(v.len());
    for js in v.iter() {
        let data = json_to_ip_data(js)?;
        r.insert(data.0.ip_identity, data);
    }
    Some(r)
}

pub fn main() {
    let app = App::new("Server exposing creation of identity objects and credentials")
        .version("0.31830988618")
        .author("Concordium")
        .setting(AppSettings::ColoredHelp)
        .arg(
            Arg::with_name("global")
                .short("G")
                .long("global")
                .default_value(GLOBAL_CONTEXT)
                .value_name("FILE")
                .help("File with crypographic parameters."),
        )
        .arg(
            Arg::with_name("ips")
                .short("I")
                .long("ips")
                .default_value("database/identity_providers_public_private.json")
                .value_name("FILE")
                .help("File with public and private information on IPs and ARs."),
        )
        .arg(
            Arg::with_name("address")
                .short("a")
                .long("address")
                .default_value("localhost:8000")
                .value_name("HOST")
                .help("Address on which the server is listening."),
        );

    let matches = app.get_matches();

    let gc_file = matches.value_of("global").unwrap_or(GLOBAL_CONTEXT);
    let ips_file = matches
        .value_of("ips")
        .unwrap_or("database/identity_providers_public_private.json");

    let address = matches.value_of("address").unwrap_or("localhost:8000");

    let gc = {
        if let Some(gc) = read_global_context(gc_file) {
            gc
        } else {
            eprintln!(
                "Could not read global cryptographic parameters from {}. Aborting.",
                gc_file
            );
            return;
        }
    };

    let ips = {
        if let Some(ips) = read_ip_infos(ips_file) {
            ips
        } else {
            eprintln!(
                "Could not read identity providers file {}. Aborting.",
                ips_file
            );
            return;
        }
    };
    let ip_infos = ips;
    let global_params = gc;
    let ss = ServerState {
        ip_infos,
        global_params,
    };

    rouille::start_server(address, move |request| {
        router!(request,
                // get global cryptographic parameters
                (GET) (/globalparams) => { respond_global_params(request, &ss) },
                // get public identity provider info
                (GET) (/ips) => { respond_ips(request, &ss) },
                // Given an attribute list generate a freshly signed identity object, together
                // with all the private data the account holder would normally generate themselves.
                (POST) (/identity_object) => { respond_id_object(request, &ss) },
                // Generate a credential to be deployed on the chain.
                (POST) (/generate_credential) => { respond_generate_credential(request, &ss) },
                _ => rouille::Response::empty_404()
        )
    });
}
