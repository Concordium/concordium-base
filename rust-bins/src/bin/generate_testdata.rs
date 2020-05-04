use clap::{App, AppSettings, Arg};

use client_server_helpers::*;
use curve_arithmetic::{Curve, Pairing};
use dodis_yampolskiy_prf::secret as prf;
use ed25519_dalek as ed25519;
use id::{account_holder::*, ffi::*, identity_provider::*, secret_sharing::Threshold, types::*};
use pairing::bls12_381::{Bls12, G1};
use std::collections::btree_map::BTreeMap;

use crypto_common::*;

use rand::*;

use pedersen_scheme::Value as PedersenValue;

use std::path::Path;

use std::{fs::File, io::Write};

use either::Either::{Left, Right};

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
    let ah_info = CredentialHolderInfo::<ExampleCurve> {
        id_cred: IdCredentials {
            id_cred_sec: PedersenValue::new(secret),
        },
    };

    // Load identity provider and anonymity revokers.
    let ip_data_path = Path::new(matches.value_of("ip-data").unwrap());
    let (ip_info, ip_secret_key) =
        match read_json_from_file::<_, IpData<Bls12, ExampleCurve>>(&ip_data_path) {
            Ok(IpData {
                ip_secret_key,
                public_ip_info,
                ..
            }) => (public_ip_info, ip_secret_key),
            Err(x) => {
                eprintln!("Could not read identity issuer information because {}", x);
                return;
            }
        };

    // Choose prf key.
    let prf_key = prf::SecretKey::generate(&mut csprng);

    // Choose variant of the attribute list. Should not matter for this use case.
    let alist = {
        let mut alist = BTreeMap::new();
        let _ = alist.insert(AttributeTag::from(0u8), AttributeKind::from(55));
        let _ = alist.insert(AttributeTag::from(1u8), AttributeKind::from(31));
        alist
    };

    let aci = AccCredentialInfo {
        cred_holder_info: ah_info,
        prf_key,
    };

    let valid_to = YearMonth::new(2022, 5).unwrap(); // May 2022
    let created_at = YearMonth::new(2020, 5).unwrap(); // May 2020
    let attributes = ExampleAttributeList {
        valid_to,
        created_at,
        max_accounts: 238,
        alist,
        _phantom: Default::default(),
    };

    let context = make_context_from_ip_info(ip_info.clone(), ChoiceArParameters {
        // use all anonymity revokers.
        ar_identities: ip_info.ip_ars.ars.iter().map(|ar| ar.ar_identity).collect(),
        // all but one threshold
        threshold: Threshold((ip_info.ip_ars.ars.len() - 1) as _),
    })
    .expect("Constructed AR data is valid.");
    let (pio, randomness) = generate_pio(&context, &aci);

    let sig_ok = verify_credentials(&pio, &ip_info, &attributes, &ip_secret_key);

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

    let id_object = IdentityObject {
        pre_identity_object: pio,
        alist:               attributes,
        signature:           ip_sig,
    };
    let id_object_use_data = IdObjectUseData { aci, randomness };

    let policy = Policy {
        valid_to,
        created_at,
        policy_vec: {
            let mut tree = BTreeMap::new();
            tree.insert(AttributeTag::from(1u8), AttributeKind::from(31));
            tree
        },
        _phantom: Default::default(),
    };
    {
        // output testdata.bin for basic verification checking.
        let mut keys = BTreeMap::new();
        keys.insert(KeyIndex(0), ed25519::Keypair::generate(&mut csprng));
        keys.insert(KeyIndex(1), ed25519::Keypair::generate(&mut csprng));
        keys.insert(KeyIndex(2), ed25519::Keypair::generate(&mut csprng));

        let acc_data = AccountData {
            keys,
            existing: Left(SignatureThreshold(2)),
        };

        let cdi_1 = generate_cdi(
            &ip_info,
            &global_ctx,
            &id_object,
            &id_object_use_data,
            53,
            &policy,
            &acc_data,
        )
        .expect("We should have generated valid data.");

        // Generate the second credential for an existing account (the one
        // created by the first credential)
        let acc_data_2 = AccountData {
            keys:     acc_data.keys,
            existing: Right(AccountAddress::new(&cdi_1.values.reg_id)),
        };

        let cdi_2 = generate_cdi(
            &ip_info,
            &global_ctx,
            &id_object,
            &id_object_use_data,
            53,
            &policy,
            &acc_data_2,
        )
        .expect("We should have generated valid data.");

        let acc_keys = AccountKeys {
            keys:      acc_data_2
                .keys
                .iter()
                .map(|(&idx, kp)| (idx, VerifyKey::from(kp.public)))
                .collect(),
            threshold: SignatureThreshold(2),
        };

        // Created versioned CDIs
        let versioned_cdi_1 = Versioned::new(VERSION_CREDENTIAL, cdi_1);
        let versioned_cdi_2 = Versioned::new(VERSION_CREDENTIAL, cdi_2);

        let mut out = Vec::new();
        let gc_bytes = to_bytes(&global_ctx);
        out.put(&(gc_bytes.len() as u32));
        out.write_all(&gc_bytes).unwrap();
        let ip_info_bytes = to_bytes(&ip_info);
        out.put(&(ip_info_bytes.len() as u32));
        out.write_all(&ip_info_bytes).unwrap();
        // output the first credential
        let vcdi1_bytes = to_bytes(&versioned_cdi_1);
        out.put(&(vcdi1_bytes.len() as u32));
        out.write_all(&vcdi1_bytes).unwrap();
        // and account keys and then the second credential
        out.put(&acc_keys);
        let vcdi2_bytes = to_bytes(&versioned_cdi_2);
        out.put(&(vcdi2_bytes.len() as u32));
        out.write_all(&vcdi2_bytes).unwrap();

        // finally we add a completely new set of keys to have a simple negative test
        let acc_keys_3 = {
            let mut keys = BTreeMap::new();
            keys.insert(
                KeyIndex(0),
                VerifyKey::from(ed25519::Keypair::generate(&mut csprng).public),
            );
            keys.insert(
                KeyIndex(1),
                VerifyKey::from(ed25519::Keypair::generate(&mut csprng).public),
            );
            keys.insert(
                KeyIndex(2),
                VerifyKey::from(ed25519::Keypair::generate(&mut csprng).public),
            );

            AccountKeys {
                keys,
                threshold: SignatureThreshold(2),
            }
        };
        out.put(&acc_keys_3);

        let file = File::create("testdata.bin");
        if let Err(err) = file.unwrap().write_all(&out) {
            eprintln!(
                "Could not output binary file testdata.bin, because {}.",
                err
            );
        } else {
            println!("Output binary file testdata.bin.");
        }

        // We also output the cdi in JSON and binary, to test compatiblity with
        // the haskell serialization

        if let Err(err) = write_json_to_file("cdi.json", &versioned_cdi_1) {
            eprintln!("Could not output JSON file cdi.json, because {}.", err);
        } else {
            println!("Output cdi.json.");
        }

        let cdi_file = File::create("cdi.bin");
        if let Err(err) = cdi_file.unwrap().write_all(&to_bytes(&versioned_cdi_1)) {
            eprintln!("Could not output binary file cdi.bin, because {}.", err);
        } else {
            println!("Output binary file cdi.bin.");
        }
    }

    // generate account credentials, parametrized
    let mut generate = |maybe_acc_data, acc_num, idx| {
        let acc_data = if let Some(acc_data) = maybe_acc_data {
            acc_data
        } else {
            let mut keys = BTreeMap::new();
            keys.insert(KeyIndex(0), ed25519::Keypair::generate(&mut csprng));
            keys.insert(KeyIndex(1), ed25519::Keypair::generate(&mut csprng));
            keys.insert(KeyIndex(2), ed25519::Keypair::generate(&mut csprng));

            AccountData {
                keys,
                existing: Left(SignatureThreshold(2)),
            }
        };

        let cdi = generate_cdi(
            &ip_info,
            &global_ctx,
            &id_object,
            &id_object_use_data,
            acc_num,
            &policy,
            &acc_data,
        )
        .expect("We should have generated valid data.");
        let acc_addr = AccountAddress::new(&cdi.values.reg_id);
        let versioned_cdi = Versioned::new(VERSION_CREDENTIAL, cdi);

        if let Err(err) = write_json_to_file(&format!("credential-{}.json", idx), &versioned_cdi) {
            eprintln!("Could not output credential = {}, because {}.", idx, err);
        } else {
            println!("Output credential {}.", idx);
        }
        // return the account data that can be used to deploy more credentials
        // to the same account.
        AccountData {
            existing: Right(acc_addr),
            ..acc_data
        }
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
