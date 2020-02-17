use pairing::bls12_381::Bls12;

use dodis_yampolskiy_prf::secret as prf;
use ed25519_dalek as ed25519;
use id::{account_holder::*, identity_provider::*, types::*};
use std::collections::btree_map::BTreeMap;

use client_server_helpers::*;
use curve_arithmetic::Curve;

use rand::*;
use serde_json::{from_value as from_json, json, to_string_pretty, Value};

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
type IpInfos = HashMap<IpIdentity, IpData<Bls12, ExampleCurve>>;

struct ServerState {
    /// Public and private information about the identity providers.
    /// This also contains information about
    ip_infos: IpInfos,
    /// Global parameters, such as various commitment keys, global parameters
    /// for sigma proofs, etc.
    global_params: GlobalContext<ExampleCurve>,
}

fn respond_global_params(_request: &rouille::Request, s: &ServerState) -> rouille::Response {
    let response = to_string_pretty(&s.global_params).unwrap();
    rouille::Response::text(response)
}

fn respond_ips(_request: &rouille::Request, s: &ServerState) -> rouille::Response {
    let response: Vec<IpInfo<_, _>> = s
        .ip_infos
        .iter()
        .map(|id| (id.1).public_ip_info.clone())
        .collect();
    rouille::Response::json(&response)
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
    let ip_id = from_json(v.get("ipIdentity")?.clone()).ok()?;
    let user_name = v.get("name")?.as_str()?.to_owned();
    let ar_values = v.get("anonymityRevokers")?.as_array()?;
    let ars: Vec<ArIdentity> = ar_values
        .iter()
        .cloned()
        .map(|x| from_json(x).ok())
        .collect::<Option<Vec<ArIdentity>>>()?;
    // default threshold is one less than the amount of anonymity revokers
    // if the field "threshold" is not present this is what we take.
    let threshold = match v.get("threshold") {
        None => Threshold(max(1, ars.len() - 1) as u32),
        Some(v) => from_json(v.clone()).ok()?,
    };
    let alist = v
        .get("attributes")
        .and_then(|x| from_json(x.clone()).ok())?;
    Some((ip_id, user_name, threshold, ars, alist))
}

macro_rules! respond_log {
    ($req:expr, $msg:expr) => {{
        rouille::log(&$req, ::std::io::stderr(), || {
            rouille::Response::text($msg).with_status_code(400)
        })
    }};
}

fn respond_id_object(request: &rouille::Request, s: &ServerState) -> rouille::Response {
    let v: Value = try_or_400!(rouille::input::json_input(request));
    let (ip_info, name, threshold, ar_identities, attributes) = {
        if let Some((ip_id, name, threshold, ar_list, att)) = parse_id_object_input_json(&v) {
            match s.ip_infos.get(&ip_id) {
                Some(ip_info) => (ip_info, name, threshold, ar_list, att),
                None => return respond_log!(request, "Could not find identity provider."),
            }
        } else {
            return respond_log!(request, "Could not parse ID request.");
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
    };

    let IpData {
        public_ip_info: ip_info,
        ip_private_key: ip_sec_key,
    } = ip_info;

    let context = match make_context_from_ip_info(ip_info.clone(), ChoiceArParameters {
        ar_identities,
        threshold,
    }) {
        Some(x) => x,
        None => return respond_log!(request, "Could not make context"),
    };
    let (pio, randomness) = generate_pio(&context, &aci);

    let vf = verify_credentials(&pio, &ip_info, &attributes, &ip_sec_key);
    match vf {
        Ok(sig) => {
            let id_use_data = IdObjectUseData { aci, randomness };
            let id_object = IdentityObject {
                pre_identity_object: pio,
                signature:           sig,
                alist:               attributes,
            };
            let response = json!({
                "identityObject": id_object,
                "ipIdentity": ip_info.ip_identity,
                "idUseData": id_use_data,
            });
            rouille::Response::json(&response)
        }
        Err(e) => respond_log!(request, format!("Could not generate credential: {:?}", e)),
    }
}

type GenerateCredentialData = (
    IpIdentity,
    IdentityObject<Bls12, ExampleCurve, ExampleAttribute>,
    IdObjectUseData<Bls12, ExampleCurve>,
    BTreeMap<AttributeTag, ExampleAttribute>, // revealed attributes
    u8,
);

fn parse_generate_credential_input_json(v: &Value) -> Option<GenerateCredentialData> {
    let ip_id = from_json(v.get("ipIdentity")?.clone()).ok()?;
    let id_object: IdentityObject<Bls12, ExampleCurve, ExampleAttribute> = v
        .get("identityObject")
        .and_then(|x| from_json(x.clone()).ok())?;
    let private: IdObjectUseData<Bls12, ExampleCurve> =
        v.get("idUseData").and_then(|x| from_json(x.clone()).ok())?;
    let policy_items = {
        if let Some(items) = v.get("revealedAttributes") {
            from_json(items.clone()).ok()?
        } else {
            BTreeMap::new()
        }
    };
    let n_acc = v.get("accountNumber").and_then(Value::as_u64)?;
    if n_acc > 255 {
        return None;
    }
    let n_acc = n_acc as u8;
    Some((ip_id, id_object, private, policy_items, n_acc))
}

fn respond_generate_credential(request: &rouille::Request, s: &ServerState) -> rouille::Response {
    let v: Value = try_or_400!(rouille::input::json_input(request));

    let (ip_info, id_object, id_use_data, policy, n_acc) = {
        if let Some((ip_id, id_object, id_use_data, items, n_acc)) =
            parse_generate_credential_input_json(&v)
        {
            match s.ip_infos.get(&ip_id) {
                Some(ref ip_info) => {
                    let policy: Policy<ExampleCurve, ExampleAttribute> = Policy {
                        expiry:     id_object.alist.expiry,
                        policy_vec: items,
                        _phantom:   Default::default(),
                    };
                    (
                        &ip_info.public_ip_info,
                        id_object,
                        id_use_data,
                        policy,
                        n_acc,
                    )
                }
                None => return rouille::Response::empty_400(),
            }
        } else {
            return rouille::Response::empty_400();
        }
    };
    // if account data is present then use it.
    let acc_data = {
        if let Some(acc_data) = v.get("accountData") {
            match from_json(acc_data.clone()) {
                Ok(acc_data) => acc_data,
                Err(e) => {
                    return respond_log!(request, format!("Could not parse account data {}.", e))
                }
            }
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
        &id_object,
        &id_use_data,
        n_acc,
        &policy,
        &acc_data,
    );

    let cdi = match cdi {
        Ok(cdi) => cdi,
        Err(e) => return respond_log!(request, format!("Could not generate credential {}", e)),
    };

    let address = match acc_data.existing {
        Left(_) => AccountAddress::new(&cdi.values.reg_id),
        Right(addr) => addr,
    };

    let response = json!({
        "credential": cdi,
        "accountData": acc_data,
        "accountAddress": address,
    });
    rouille::Response::json(&response)
}

// TODO: Pass filename as parameter
fn read_ip_infos(filename: &str) -> Option<IpInfos> {
    let infos: Vec<IpData<_, _>> = read_json_from_file(filename).ok()?;
    let mut map = HashMap::with_capacity(infos.len());
    for info in infos {
        let _ = map.insert(info.public_ip_info.ip_identity, info);
    }
    Some(map)
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
