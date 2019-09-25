use pairing::bls12_381::Bls12;
use ps_sig as pssig;

use dodis_yampolskiy_prf::secret as prf;
use eddsa_ed25519 as ed25519_wrapper;
use id::{account_holder::*, identity_provider::*, types::*};

use client_server_helpers::*;
use curve_arithmetic::Curve;

use rand::*;
use serde_json::{json, to_string_pretty, Value};

use clap::{App, AppSettings, Arg};
use std::io::Cursor;

// server imports
#[macro_use]
extern crate rouille;

/// Public and **private** data about identity providers.
type IpInfos = Vec<IpData>;

struct ServerState {
    /// Public and private information about the identity providers.
    /// This also contains information about
    ip_infos: IpInfos,
    /// Global parameters, such as various commitment keys, global parameters
    /// for sigma proofs, etc.
    global_params: GlobalContext<ExampleCurve>,
}

fn respond_global_params(_request: &rouille::Request, s: &ServerState) -> rouille::Response {
    let response = to_string_pretty(&global_context_to_json(&s.global_params)).unwrap();
    rouille::Response::text(response)
}

fn respond_ips(_request: &rouille::Request, s: &ServerState) -> rouille::Response {
    let response: Vec<Value> = s.ip_infos.iter().map(|id| ip_info_to_json(&id.0)).collect();
    rouille::Response::json(&json!(response))
}

fn parse_id_object_input_json(v: &Value) -> Option<(u32, String, Vec<u64>, ExampleAttributeList)> {
    let ip_id = json_read_u32(v.as_object()?, "ipIdentity")?;
    let user_name = v.get("name")?.as_str()?.to_owned();
    let ar_values = v.get("anonymityRevokers")?.as_array()?;
    let ars:Vec<u64> = ar_values.iter().map(parse_u64).collect::<Option<Vec<u64>>>()?;
    let alist = json_to_alist(v.get("attributes")?)?;
    Some((ip_id, user_name, ars.clone(), alist))
}

fn respond_id_object(request: &rouille::Request, s: &ServerState) -> rouille::Response {
    let v: Value = try_or_400!(rouille::input::json_input(request));
    let (ip_id, name, ar_list, attributes) = {
        if let Some((ip_id, name, ar_list, att)) = parse_id_object_input_json(&v) {
            if (ip_id as usize) < s.ip_infos.len() {
                (ip_id as usize, name, ar_list, att)
            } else {
                return rouille::Response::empty_400();
            }
        } else {
            return rouille::Response::empty_400();
        }
    };

    let mut csprng = thread_rng();
    // generate the prf key
    let prf_key = prf::SecretKey::generate(&mut csprng);

    let secret = ExampleCurve::generate_scalar(&mut csprng);
    let public = ExampleCurve::one_point().mul_by_scalar(&secret);
    let chi = CredentialHolderInfo::<ExampleCurve> {
        id_ah:   name,
        id_cred: IdCredentials {
            id_cred_sec:    secret,
            id_cred_pub:    public,
        },
    };

    let aci = AccCredentialInfo {
        acc_holder_info: chi,
        prf_key,
        attributes,
    };

    let (ip_info, ip_sec_key) = &s.ip_infos[ip_id];

    let context = make_context_from_ip_info(ip_info.clone(), (ar_list, 1));
    let (pio, randomness) = generate_pio(&context, &aci);

    let vf = verify_credentials(&pio, &ip_info, &ip_sec_key);
    match vf {
        Ok(sig) => {
            let response = json!({
                "preIdentityObject": pio_to_json(&pio),
                "signature": json_base16_encode(&sig.to_bytes()),
                "ipIdentity": ip_id,
                "privateData": json!({
                    "aci": aci_to_json(&aci),
                    "pioRandomness": json_base16_encode(&randomness.to_bytes())
                })
            });
            rouille::Response::json(&response)
        }
        Err(_) => rouille::Response::empty_400(),
    }
}

type GenerateCredentialData = (
    u32,
    PreIdentityObject<Bls12, ExampleCurve, ExampleAttribute>,
    pssig::Signature<Bls12>,
    SigRetrievalRandomness<Bls12>,
    AccCredentialInfo<ExampleCurve, ExampleAttribute>,
    Vec<(u16, ExampleAttribute)>,
    u8,
);

fn parse_generate_credential_input_json(v: &Value) -> Option<GenerateCredentialData> {
    let ip_id = json_read_u32(v.as_object()?, "ipIdentity")?;
    let sig =
        pssig::Signature::from_bytes(&mut Cursor::new(&json_base16_decode(v.get("signature")?)?))
            .ok()?;
    let pio = json_to_pio(v.get("preIdentityObject")?)?;
    let private = v.get("privateData")?;
    let randomness = SigRetrievalRandomness::from_bytes(&mut Cursor::new(&json_base16_decode(
        private.get("pioRandomness")?,
    )?))?;
    let aci = json_to_aci(private.get("aci")?)?;
    let policy_items = {
        if let Some(items) = v.get("revealedItems") {
            read_revealed_items(pio.alist.variant, &pio.alist.alist, items)?
        } else {
            vec![]
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
            if (ip_id as usize) < s.ip_infos.len() {
                let policy: Policy<ExampleCurve, ExampleAttribute> = Policy {
                    variant:    pio.alist.variant,
                    expiry:     pio.alist.expiry,
                    policy_vec: items,
                    _phantom:   Default::default(),
                };
                (
                    &s.ip_infos[ip_id as usize].0,
                    pio,
                    sig,
                    sig_randomness,
                    aci,
                    policy,
                    n_acc,
                )
            } else {
                return rouille::Response::empty_400();
            }
        } else {
            return rouille::Response::empty_400();
        }
    };
    // if account data is present then use it.
    let acc_data = {
        if let Some(acc_data) = v.get("accountKeyPair").and_then(json_to_account_data) {
            acc_data
        } else {
            let kp = ed25519_wrapper::generate_keypair();
            AccountData {
                sign_key:   kp.secret,
                verify_key: kp.public,
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
    // let checked = verify_cdi(&s.global_params, ip_info, &cdi);
    let values = &cdi.values;
    let cdi_json = json!({
        "schemeId": if values.acc_scheme_id == SchemeId::Ed25519 {"Ed25519"} else {"CL"},
        "verifyKey": json_base16_encode(&values.acc_pub_key.to_bytes()),
        "regId": json_base16_encode(&values.reg_id.curve_to_bytes()),
        "ipIdentity": values.ip_identity,
        "arData": chain_ar_data_to_json(&values.ar_data),
        "policy": policy_to_json(&values.policy),
        // NOTE: Since proofs encode their own length we do not output those first 4 bytes
        "proofs": json_base16_encode(&cdi.proofs.to_bytes()[4..]),
    });

    let response = json!({
        "credential": cdi_json,
        "accountKeyPair": account_data_to_json(&acc_data)
    });
    rouille::Response::json(&response)
}

fn read_revealed_items(
    variant: u16,
    alist: &[ExampleAttribute],
    v: &Value,
) -> Option<Vec<(u16, ExampleAttribute)>> {
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
    v.iter().map(json_to_ip_data).collect()
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
