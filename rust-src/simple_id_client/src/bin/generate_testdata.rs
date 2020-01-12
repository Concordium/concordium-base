use clap::{App, AppSettings, Arg};

use client_server_helpers::*;
use curve_arithmetic::{Curve, Pairing};
use dodis_yampolskiy_prf::secret as prf;
use eddsa_ed25519 as ed25519;
use id::{account_holder::*, ffi::*, identity_provider::*, secret_sharing::Threshold, types::*};
use pairing::bls12_381::{Bls12, G1};
use std::collections::btree_map::BTreeMap;

use rand::*;

use pedersen_scheme::Value as PedersenValue;

use std::path::Path;

use std::{fs::File, io::Write};

use either::Either::Left;

type ExampleCurve = G1;

type ExampleAttribute = AttributeKind;

type ExampleAttributeList = AttributeList<<Bls12 as Pairing>::ScalarField, ExampleAttribute>;

fn main() {
    let app = App::new("Generate test credentials.")
        .version("0.36787944117")
        .author("Concordium")
        .setting(AppSettings::ArgRequiredElseHelp)
        .global_setting(AppSettings::ColoredHelp)
        .arg(
            Arg::with_name("ip-data")
                .long("ip-data")
                .value_name("FILE")
                .help("File with all information about the identity provider (public and private).")
                .required(true),
        );

    let matches = app.get_matches();

    let mut csprng = thread_rng();

    let secret = ExampleCurve::generate_scalar(&mut csprng);
    let public = ExampleCurve::one_point().mul_by_scalar(&secret);
    let ah_info = CredentialHolderInfo::<ExampleCurve> {
        id_ah:   "ACCOUNT_HOLDER".to_owned(),
        id_cred: IdCredentials {
            id_cred_sec: PedersenValue::new(secret),
            id_cred_pub: public,
        },
    };

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

    // Choose prf key.
    let prf_key = prf::SecretKey::generate(&mut csprng);

    // Choose variant of the attribute list. Should not matter for this use case.
    let variant = 13;
    let expiry_date = 123_123_123; //
    let alist = vec![AttributeKind::from(55), AttributeKind::from(31)];
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

    let context = make_context_from_ip_info(
        ip_info.clone(),
        (
            ip_info.ar_info.0.iter().map(|ar| ar.ar_identity).collect(), /* use all anonymity
                                                                          * revokers. */
            Threshold((ip_info.ar_info.0.len() - 1) as _), // all but one threshold
        ),
    );
    let (pio, randomness) = generate_pio(&context, &aci);

    let sig_ok = verify_credentials(&pio, &ip_info, &ip_secret_key);

    // First test, check that we have a valid signature.
    assert!(sig_ok.is_ok());

    let ip_sig = sig_ok.unwrap();

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

    let policy = Policy {
        variant,
        expiry: expiry_date,
        policy_vec: {
            let mut tree = BTreeMap::new();
            tree.insert(1u16, AttributeKind::from(31));
            tree
        },
        _phantom: Default::default(),
    };
    {
        // output testdata.bin for basic verification checking.
        let mut keys = BTreeMap::new();
        keys.insert(KeyIndex(0), ed25519::generate_keypair());
        keys.insert(KeyIndex(1), ed25519::generate_keypair());
        keys.insert(KeyIndex(2), ed25519::generate_keypair());

        let acc_data = AccountData {
            keys,
            existing: Left(SignatureThreshold(2)),
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

        let mut out = Vec::new();
        let gc_bytes = global_ctx.to_bytes();
        out.extend_from_slice(&(gc_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&gc_bytes);
        let ip_info_bytes = ip_info.to_bytes();
        out.extend_from_slice(&(ip_info_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&ip_info_bytes);
        out.extend_from_slice(&cdi.to_bytes());
        let file = File::create("testdata.bin");
        if let Err(err) = file.unwrap().write_all(&out) {
            eprintln!(
                "Could not output binary file testdata.bin, because {}.",
                err
            );
        } else {
            println!("Output binary file testdata.bin.");
        }
    }

    // generate account credentials, parametrized
    let generate = |maybe_acc_data, acc_num, idx| {
        let acc_data = if let Some(acc_data) = maybe_acc_data {
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
        };
        let cdi = generate_cdi(
            &ip_info,
            &global_ctx,
            &aci,
            &pio,
            acc_num,
            &ip_sig,
            &policy,
            &acc_data,
            &randomness,
        );
        let js = cdi.to_json();

        if let Err(err) = write_json_to_file(&format!("credential-{}.json", idx), &js) {
            eprintln!("Could not output credential = {}, because {}.", idx, err);
        } else {
            println!("Output credential {}.", idx);
        }
        acc_data
    };

    let _ = generate(None, 0, 1);
    let _ = generate(None, 1, 2);
    let _ = generate(None, 2, 3);
    // duplicate reg_id
    let _ = generate(None, 2, 4);
    // use same account keypair
    let acc_data = generate(None, 4, 5);
    let _ = generate(Some(acc_data), 5, 6);
    let _ = generate(None, 6, 7);
}
