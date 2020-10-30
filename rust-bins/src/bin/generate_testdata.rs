use clap::AppSettings;
use client_server_helpers::*;
use crypto_common::*;
use curve_arithmetic::Pairing;
use dodis_yampolskiy_prf::secret as prf;
use ed25519_dalek as ed25519;
use either::Either::{Left, Right};
use id::{account_holder::*, ffi::*, identity_provider::*, secret_sharing::Threshold, types::*};
use pairing::bls12_381::{Bls12, G1};
use rand::*;
use std::{collections::btree_map::BTreeMap, fs::File, io::Write, path::PathBuf};
use structopt::StructOpt;

type ExampleCurve = G1;

type ExampleAttribute = AttributeKind;

type ExampleAttributeList = AttributeList<<Bls12 as Pairing>::ScalarField, ExampleAttribute>;

#[derive(StructOpt)]
#[structopt(
    version = "0.36787944117",
    author = "Concordium",
    about = "Generate test credentials."
)]
struct GenerateTestData {
    #[structopt(
        long = "ip-data",
        help = "File with all information about the identity provider (public and private)."
    )]
    ip_data: PathBuf,
    #[structopt(
        long = "global",
        help = "File with global parameters.",
        default_value = GLOBAL_CONTEXT
    )]
    global: PathBuf,
    #[structopt(
        long = "ars",
        help = "File with a list of anonymity revokers..",
        default_value = "database/anonymity_revokers.json"
    )]
    anonymity_revokers: PathBuf,
}

fn main() {
    let args = {
        let app = GenerateTestData::clap()
            .setting(AppSettings::ArgRequiredElseHelp)
            .global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        GenerateTestData::from_clap(&matches)
    };

    let mut csprng = thread_rng();

    // all known anonymity revokers.
    let ars_infos = {
        if let Ok(ars) = read_anonymity_revokers(args.anonymity_revokers) {
            ars
        } else {
            eprintln!("Cannot read anonymity revokers from the database. Terminating.");
            return;
        }
    };

    let global_ctx = {
        if let Some(gc) = read_global_context(args.global) {
            gc
        } else {
            eprintln!("Cannot read global context information database. Terminating.");
            return;
        }
    };

    let ah_info = CredentialHolderInfo::<ExampleCurve> {
        id_cred: IdCredentials::generate(&mut csprng),
    };

    // Load identity provider and anonymity revokers.
    let (ip_info, ip_secret_key, ip_cdi_secret_key) =
        match read_json_from_file::<_, IpData<Bls12>>(args.ip_data) {
            Ok(IpData {
                ip_secret_key,
                public_ip_info,
                ip_cdi_secret_key,
            }) => (public_ip_info, ip_secret_key, ip_cdi_secret_key),
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

    let context = IPContext::new(&ip_info, &ars_infos.anonymity_revokers, &global_ctx);
    let initial_acc_data = InitialAccountData {
        keys:      {
            let mut keys = BTreeMap::new();
            keys.insert(KeyIndex(0), ed25519::Keypair::generate(&mut csprng));
            keys.insert(KeyIndex(1), ed25519::Keypair::generate(&mut csprng));
            keys.insert(KeyIndex(2), ed25519::Keypair::generate(&mut csprng));
            keys
        },
        threshold: SignatureThreshold(2),
    };
    // Threshold is all anonymity revokers.
    let (pio, randomness) = generate_pio(
        &context,
        Threshold(ars_infos.anonymity_revokers.len() as u8),
        &aci,
        &initial_acc_data,
    )
    .expect("Generating the pre-identity object should succeed.");

    let pub_info_for_ip = pio.pub_info_for_ip.clone();

    let ver_ok = verify_credentials(
        &pio,
        context,
        &attributes,
        &ip_secret_key,
        &ip_cdi_secret_key,
    );

    // First test, check that we have a valid signature.
    assert!(ver_ok.is_ok());

    let (ip_sig, _) = ver_ok.unwrap();

    let id_object = IdentityObject {
        pre_identity_object: pio,
        alist:               attributes.clone(),
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

        let cdi_1 = create_credential(
            context,
            &id_object,
            &id_object_use_data,
            53,
            policy.clone(),
            &acc_data,
        )
        .expect("We should have generated valid data.");

        // Generate the second credential for an existing account (the one
        // created by the first credential)
        let acc_data_2 = AccountData {
            keys:     acc_data.keys,
            existing: Right(AccountAddress::new(&cdi_1.values.reg_id)),
        };

        let cdi_2 = create_credential(
            context,
            &id_object,
            &id_object_use_data,
            53,
            policy.clone(),
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

        let mut out = Vec::new();
        let gc_bytes = to_bytes(&global_ctx);
        out.put(&(gc_bytes.len() as u32));
        out.write_all(&gc_bytes).unwrap();
        let ip_info_bytes = to_bytes(&ip_info);
        out.put(&(ip_info_bytes.len() as u32));
        out.write_all(&ip_info_bytes).unwrap();
        let ars_len = ars_infos.anonymity_revokers.len();
        out.put(&(ars_len as u64)); // length of the list, expected big-endian in Haskell.
        for ar in ars_infos.anonymity_revokers.values() {
            let ar_bytes = to_bytes(ar);
            out.put(&(ar_bytes.len() as u32));
            out.write_all(&ar_bytes).unwrap();
        }

        // output the first credential
        let cdi1_bytes = to_bytes(&cdi_1);
        out.put(&(cdi1_bytes.len() as u32));
        out.write_all(&cdi1_bytes).unwrap();
        // and account keys and then the second credential
        out.put(&acc_keys);
        let cdi2_bytes = to_bytes(&cdi_2);
        out.put(&(cdi2_bytes.len() as u32));
        out.write_all(&cdi2_bytes).unwrap();

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

        // Create an initial cdi and output it
        let icdi = create_initial_cdi(&ip_info, pub_info_for_ip, &attributes, &ip_cdi_secret_key);
        let icdi_bytes = to_bytes(&icdi);
        out.put(&(icdi_bytes.len() as u32));
        out.write_all(&icdi_bytes).unwrap();

        let file = File::create("testdata.bin");
        if let Err(err) = file.unwrap().write_all(&out) {
            eprintln!(
                "Could not output binary file testdata.bin, because {}.",
                err
            );
        } else {
            println!("Output binary file testdata.bin.");
        }

        // We also output a versioned CDI in JSON and binary, to test compatiblity with
        // the haskell serialization
        let ver_cdi_1 = Versioned::new(VERSION_0, cdi_1);
        if let Err(err) = write_json_to_file("cdi.json", &ver_cdi_1) {
            eprintln!("Could not output JSON file cdi.json, because {}.", err);
        } else {
            println!("Output cdi.json.");
        }

        let cdi_file = File::create("cdi.bin");
        if let Err(err) = cdi_file.unwrap().write_all(&to_bytes(&ver_cdi_1)) {
            eprintln!("Could not output binary file cdi.bin, because {}.", err);
        } else {
            println!("Output binary file cdi.bin.");
        }

        // As for CDI we output an ICDI json and binary to test compatibility between
        // haskell and rust serialization
        let ver_icdi = Versioned::new(VERSION_0, icdi);
        if let Err(err) = write_json_to_file("icdi.json", &ver_icdi) {
            eprintln!("Could not output JSON file icdi.json, because {}.", err);
        } else {
            println!("Output icdi.json.");
        }

        let icdi_file = File::create("icdi.bin");
        if let Err(err) = icdi_file.unwrap().write_all(&to_bytes(&ver_icdi)) {
            eprintln!("Could not output binary file icdi.bin, because {}.", err);
        } else {
            println!("Output binary file icdi.bin.");
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

        let cdi = create_credential(
            context,
            &id_object,
            &id_object_use_data,
            acc_num,
            policy.clone(),
            &acc_data,
        )
        .expect("We should have generated valid data.");
        let acc_addr = AccountAddress::new(&cdi.values.reg_id);
        let versioned_cdi = Versioned::new(VERSION_0, cdi);

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

    let mut generate_initial = |prf, idx, ip_secret| {
        let initial_acc_data = {
            let mut keys = BTreeMap::new();
            keys.insert(KeyIndex(0), ed25519::Keypair::generate(&mut csprng));
            keys.insert(KeyIndex(1), ed25519::Keypair::generate(&mut csprng));
            keys.insert(KeyIndex(2), ed25519::Keypair::generate(&mut csprng));

            InitialAccountData {
                keys,
                threshold: SignatureThreshold(2),
            }
        };
        let ah_info = CredentialHolderInfo::<ExampleCurve> {
            id_cred: IdCredentials::generate(&mut csprng),
        };
        let aci = AccCredentialInfo {
            cred_holder_info: ah_info,
            prf_key:          prf,
        };
        let (pio, _) = generate_pio(
            &context,
            Threshold(ars_infos.anonymity_revokers.len() as u8),
            &aci,
            &initial_acc_data,
        )
        .expect("Generating the pre-identity object should succeed.");

        let icdi = create_initial_cdi(
            &context.ip_info,
            pio.pub_info_for_ip,
            &attributes,
            ip_secret,
        );
        let versioned_icdi = Versioned::new(VERSION_0, icdi);

        if let Err(err) =
            write_json_to_file(&format!("initial-credential-{}.json", idx), &versioned_icdi)
        {
            eprintln!(
                "Could not output initial credential = {}, because {}.",
                idx, err
            );
        } else {
            println!("Output initial credential {}.", idx);
        }
    };

    let mut csprng = thread_rng();
    let prf_key = prf::SecretKey::generate(&mut csprng);
    generate_initial(prf_key, 1, &ip_cdi_secret_key);
    let prf_key: prf::SecretKey<ExampleCurve> = prf::SecretKey::generate(&mut csprng);
    let prf_key_same = prf_key.clone();
    generate_initial(prf_key, 2, &ip_cdi_secret_key);
    generate_initial(prf_key_same, 3, &ip_cdi_secret_key); // Reuse of prf key
    let prf_key: prf::SecretKey<ExampleCurve> = prf::SecretKey::generate(&mut csprng);
    let wrong_keys = ed25519_dalek::Keypair::generate(&mut csprng);
    generate_initial(prf_key, 4, &wrong_keys.secret); // Wrong secret key
}
