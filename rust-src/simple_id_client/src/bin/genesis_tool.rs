use clap::{App, AppSettings, Arg, SubCommand};

use client_server_helpers::*;
use curve_arithmetic::{Curve, Pairing};
use dodis_yampolskiy_prf::secret as prf;
use eddsa_ed25519 as ed25519;
use id::{account_holder::*, ffi::*, identity_provider::*, secret_sharing::Threshold, types::*};
use pairing::bls12_381::{Bls12, G1};
use std::collections::btree_map::BTreeMap;

use rand::*;

use pedersen_scheme::Value as PedersenValue;

use serde_json::json;
use std::path::Path;

use ec_vrf_ed25519 as vrf;

use aggregate_sig as agg;

type ExampleCurve = G1;

type ExampleAttribute = AttributeKind;

type ExampleAttributeList = AttributeList<<Bls12 as Pairing>::ScalarField, ExampleAttribute>;

fn main() {
    let app =
        App::new("Generate bakers with accounts for inclusion in genesis or just beta accounts.")
            .version("0.31830988618")
            .author("Concordium")
            .setting(AppSettings::ArgRequiredElseHelp)
            .global_setting(AppSettings::ColoredHelp)
            .arg(
                Arg::with_name("ip-data")
                    .long("ip-data")
                    .value_name("FILE")
                    .help(
                        "File with all information about the identity provider that is going to \
                         sign all the credentials.",
                    )
                    .required(false)
                    .global(true),
            )
            .arg(
                Arg::with_name("global")
                    .long("global")
                    .value_name("FILE")
                    .help("File with global parameters.")
                    .default_value(GLOBAL_CONTEXT)
                    .required(false)
                    .global(true),
            )
            .subcommand(
                SubCommand::with_name("create-bakers")
                    .about("Create new bakers.")
                    .arg(
                        Arg::with_name("num")
                            .long("num")
                            .value_name("N")
                            .help("Number of bakers to generate.")
                            .required(true),
                    )
                    .arg(
                        Arg::with_name("num_finalizers")
                            .long("num_finalizers")
                            .help("The amount of finalizers to generate. Defaults to all bakers.")
                            .required(false),
                    ),
            )
            .subcommand(
                SubCommand::with_name("create-accounts")
                    .about("Create beta accounts.")
                    .arg(
                        Arg::with_name("num")
                            .long("num")
                            .value_name("N")
                            .help("Number of accounts to generate.")
                            .required(true),
                    ),
            );

    let matches = app.get_matches();

    let mut csprng = thread_rng();

    // Load identity provider and anonymity revokers.
    let ip_data_path = Path::new(matches.value_of("ip-data").unwrap());
    let (ip_info, ip_secret_key) = match read_json_from_file(&ip_data_path)
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

    let context = make_context_from_ip_info(
        ip_info.clone(),
        (
            // use all anonymity revokers.
            ip_info.ar_info.0.iter().map(|ar| ar.ar_identity).collect(),
            // all but one threshold
            Threshold((ip_info.ar_info.0.len() - 1) as _),
        ),
    );

    // we also read the global context from another json file (called
    // global.context). We need commitment keys and other data in there.
    let global_ctx = {
        if let Some(gc) = read_global_context(
            matches
                .value_of("global")
                .expect("We have a default value, so should exist."),
        ) {
            gc
        } else {
            eprintln!("Cannot read global context information database. Terminating.");
            return;
        }
    };

    // Roughly one year
    let year = std::time::Duration::from_secs(365 * 24 * 60 * 60);

    let generate_account = |csprng: &mut rand::ThreadRng, user_name: String| {
        let secret = ExampleCurve::generate_scalar(csprng);
        let public = ExampleCurve::one_point().mul_by_scalar(&secret);
        let ah_info = CredentialHolderInfo::<ExampleCurve> {
            id_ah:   user_name,
            id_cred: IdCredentials {
                id_cred_sec: PedersenValue::new(secret),
                id_cred_pub: public,
            },
        };

        // Choose prf key.
        let prf_key = prf::SecretKey::generate(csprng);

        // Choose variant of the attribute list.
        // Baker accounts will have the maximum allowed variant.
        let variant = 1 << 15;

        // Expire in 1 year from now.
        let year_from_now = std::time::SystemTime::now()
            .checked_add(year)
            .expect("A year from now should not overflow.");
        let expiry_date = year_from_now
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Duration in a year should be valid.")
            .as_secs();

        // no credentials
        let alist = Vec::new();
        let aci = AccCredentialInfo {
            acc_holder_info: ah_info,
            prf_key,
            attributes: ExampleAttributeList {
                variant,
                expiry: expiry_date,
                alist,
                _phantom: Default::default(),
            },
        };

        let (pio, randomness) = generate_pio(&context, &aci);

        let sig_ok = verify_credentials(&pio, &ip_info, &ip_secret_key);

        let ip_sig = sig_ok.expect("There is an error in signing");

        let policy = Policy {
            variant,
            expiry: expiry_date,
            policy_vec: BTreeMap::new(),
            _phantom: Default::default(),
        };
        let account_kp = ed25519::generate_keypair();
        let acc_data = AccountData {
            sign_key:   account_kp.secret,
            verify_key: account_kp.public,
        };
        let cdi = generate_cdi(
            &ip_info,
            &global_ctx,
            &aci,
            &pio,
            53,
            &ip_sig,
            &policy,
            &acc_data,
            &randomness,
        );

        let credential_json = json!({
            "schemeId": "Ed25519",
            "verifyKey": json_base16_encode(&cdi.values.acc_pub_key.to_bytes()),
            "regId": json_base16_encode(&cdi.values.reg_id.curve_to_bytes()),
            "ipIdentity": cdi.values.ip_identity.to_json(),
            "revocationThreshold": cdi.values.threshold.to_json(),
            "arData": chain_ar_data_to_json(&cdi.values.ar_data),
            "policy": policy_to_json(&cdi.values.policy),
            // NOTE: Since proofs encode their own length we do not output those first 4 bytes
            "proofs": json_base16_encode(&cdi.proofs.to_bytes()[4..]),
        });
        let address_json = AccountAddress::new(SchemeId::Ed25519, &acc_data.verify_key).to_json();
        // output private account data
        let account_data_json = json!({
            "schemeId": "Ed25519",
            "address": address_json.clone(),
            "signKey": json_base16_encode(&acc_data.sign_key.to_bytes()),
            "verifyKey": json_base16_encode(&acc_data.verify_key.to_bytes()),
            "credential": credential_json,
            "aci": aci_to_json(&aci),
        });
        let verify_key_json = json_base16_encode(&account_kp.public.to_bytes());
        (
            account_data_json,
            credential_json,
            address_json,
            verify_key_json,
        )
    };

    if let Some(matches) = matches.subcommand_matches("create-bakers") {
        let num_bakers = match matches.value_of("num").unwrap().parse() {
            Ok(n) => n,
            Err(err) => {
                eprintln!("Could not parse the number of bakers: {}", err);
                return;
            }
        };

        let num_finalizers = match matches.value_of("num_finalizers") {
            None => num_bakers,
            Some(arg) => match arg.parse() {
                Ok(n) => n,
                Err(err) => {
                    eprintln!("Could not parse the number of bakers: {}", err);
                    return;
                }
            },
        };

        let mut bakers = Vec::with_capacity(num_bakers);
        for baker in 0..num_bakers {
            let (account_data_json, credential_json, address_json, verify_key_json) =
                generate_account(&mut csprng, format!("Baker-{}-account", baker));
            if let Err(err) =
                write_json_to_file(&format!("baker-{}-account.json", baker), &account_data_json)
            {
                eprintln!(
                    "Could not output account data for baker {}, because {}.",
                    baker, err
                );
            }

            // vrf keypair
            let vrf_key = vrf::generate_keypair();
            // signature keypair
            let sign_key = ed25519::generate_keypair();

            let agg_sign_key = agg::SecretKey::<Bls12>::generate(&mut csprng);
            let agg_verify_key = agg::PublicKey::from_secret(agg_sign_key);

            // Output baker vrf and election keys in a json file.
            let baker_data_json = json!({
                "electionPrivateKey": json_base16_encode(&vrf_key.secret.to_bytes()),
                "electionVerifyKey": json_base16_encode(&vrf_key.public.to_bytes()),
                "signatureSignKey": json_base16_encode(&sign_key.secret.to_bytes()),
                "signatureVerifyKey": json_base16_encode(&sign_key.public.to_bytes()),
                "aggregateSignKey": json_base16_encode(&agg_sign_key.to_bytes()),
                "aggregateVerifyKey": json_base16_encode(&agg_verify_key.to_bytes()),
            });

            if let Err(err) = write_json_to_file(
                &format!("baker-{}-credentials.json", baker),
                &baker_data_json,
            ) {
                eprintln!(
                    "Could not output baker credential for baker {}, because {}.",
                    baker, err
                );
            }

            // Finally store a json value storing public data for this baker.
            let public_baker_data = json!({
                "electionVerifyKey": json_base16_encode(&vrf_key.public.to_bytes()),
                "signatureVerifyKey": json_base16_encode(&sign_key.public.to_bytes()),
                "aggregateVerifyKey": json_base16_encode(&agg_verify_key.to_bytes()),
                "finalizer": baker < num_finalizers,
                "account": json!({
                    "schemeId": "Ed25519",
                    "address": address_json,
                    "verifyKey": verify_key_json,
                    "balance": 1_000_000_000_000u64,
                    "credential": credential_json
                })
            });
            bakers.push(public_baker_data);
        }

        // finally output all of the bakers in one file. This is used to generate
        // genesis.
        if let Err(err) = write_json_to_file("bakers.json", &json!(bakers)) {
            eprintln!("Could not output bakers.json file because {}.", err)
        }
    }

    if let Some(matches) = matches.subcommand_matches("create-accounts") {
        let num_accounts = match matches.value_of("num").unwrap().parse() {
            Ok(n) => n,
            Err(err) => {
                eprintln!("Could not parse the number of bakers: {}", err);
                return;
            }
        };
        let mut accounts = Vec::with_capacity(num_accounts);
        for acc_num in 0..num_accounts {
            let (account_data_json, credential_json, address_json, verify_key_json) =
                generate_account(&mut csprng, format!("Beta-{}-account", acc_num));
            let public_account_data = json!({
                  "schemeId": "Ed25519",
                  "address": address_json,
                  "verifyKey": verify_key_json,
                  "balance": 1_000_000_000_000u64,
                  "credential": credential_json
            });
            accounts.push(public_account_data);

            if let Err(err) = write_json_to_file(
                &format!("beta-account-{}.json", acc_num),
                &json!(account_data_json),
            ) {
                eprintln!(
                    "Could not output beta-account-{}.json file because {}.",
                    acc_num, err
                )
            }
        }
        // finally output all of the public account data in one file. This is used to
        // generate genesis.
        if let Err(err) = write_json_to_file("beta-accounts.json", &json!(accounts)) {
            eprintln!("Could not output beta-accounts.json file because {}.", err)
        }
    }
}
