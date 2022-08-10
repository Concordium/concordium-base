use clap::AppSettings;
use client_server_helpers::*;
use crypto_common::{
    types::{KeyIndex, KeyPair, TransactionTime},
    *,
};
use curve_arithmetic::{Curve, Pairing};
use dodis_yampolskiy_prf as prf;
use either::{Left, Right};
use id::{
    account_holder::*,
    constants::{ArCurve, IpPairing, *},
    identity_provider::*,
    secret_sharing::Threshold,
    types::*,
};
use pairing::bls12_381::{Bls12, G1};
use rand::*;
use std::{collections::btree_map::BTreeMap, fs::File, io::Write, path::PathBuf};
use structopt::StructOpt;

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
    ip_data:            PathBuf,
    #[structopt(
        long = "global",
        help = "File with global parameters.",
        default_value = GLOBAL_CONTEXT
    )]
    global:             PathBuf,
    #[structopt(
        long = "ars",
        help = "File with a list of anonymity revokers..",
        default_value = "database/anonymity_revokers.json"
    )]
    anonymity_revokers: PathBuf,
}

const EXPIRY: TransactionTime = TransactionTime { seconds: u64::MAX };

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

    let ah_info = CredentialHolderInfo::<ArCurve> {
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

    let context = IpContext::new(&ip_info, &ars_infos.anonymity_revokers, &global_ctx);
    let initial_acc_data = InitialAccountData {
        keys:      {
            let mut keys = BTreeMap::new();
            keys.insert(KeyIndex(0), KeyPair::generate(&mut csprng));
            keys.insert(KeyIndex(1), KeyPair::generate(&mut csprng));
            keys.insert(KeyIndex(2), KeyPair::generate(&mut csprng));
            keys
        },
        threshold: SignatureThreshold(2),
    };
    // Threshold is all anonymity revokers.

    let randomness = ps_sig::SigRetrievalRandomness::generate_non_zero(&mut csprng);
    let id_use_data = IdObjectUseData { aci, randomness };
    let (pio, _) = generate_pio(
        &context,
        Threshold(ars_infos.anonymity_revokers.len() as u8),
        &id_use_data,
        &initial_acc_data,
    )
    .expect("Generating the pre-identity object should succeed.");

    let pub_info_for_ip = pio.pub_info_for_ip.clone();

    let ver_ok = verify_credentials(
        &pio,
        context,
        &attributes,
        EXPIRY,
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
        keys.insert(KeyIndex(0), KeyPair::generate(&mut csprng));
        keys.insert(KeyIndex(1), KeyPair::generate(&mut csprng));
        keys.insert(KeyIndex(2), KeyPair::generate(&mut csprng));

        let acc_data = CredentialData {
            keys,
            threshold: SignatureThreshold(2),
        };

        let (cdi_1, _) = create_credential(
            context,
            &id_object,
            &id_use_data,
            53,
            policy.clone(),
            &acc_data,
            &SystemAttributeRandomness,
            &Left(EXPIRY),
        )
        .expect("We should have generated valid data.");

        // Generate the second credential for an existing account (the one
        // created by the first credential)
        let mut keys_2 = BTreeMap::new();
        keys_2.insert(KeyIndex(0), KeyPair::generate(&mut csprng));
        keys_2.insert(KeyIndex(1), KeyPair::generate(&mut csprng));
        keys_2.insert(KeyIndex(2), KeyPair::generate(&mut csprng));
        let acc_data_2 = CredentialData {
            keys:      acc_data.keys,
            threshold: SignatureThreshold(1),
        };

        let addr = account_address_from_registration_id(&cdi_1.values.cred_id);

        let (cdi_2, _) = create_credential(
            context,
            &id_object,
            &id_use_data,
            53,
            policy.clone(),
            &acc_data_2,
            &SystemAttributeRandomness,
            &Right(addr),
        )
        .expect("We should have generated valid data.");

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
        // and account address and then the second credential
        out.put(&addr);
        let cdi2_bytes = to_bytes(&cdi_2);
        out.put(&(cdi2_bytes.len() as u32));
        out.write_all(&cdi2_bytes).unwrap();

        // output another random address
        {
            let other_addr = account_address_from_registration_id(&G1::generate(&mut csprng));
            out.put(&other_addr)
        }

        // Create an initial cdi and output it
        let icdi = create_initial_cdi(
            &ip_info,
            pub_info_for_ip,
            &attributes,
            EXPIRY,
            &ip_cdi_secret_key,
        );
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

        let cdi_coms_file = File::create("cdi-coms.bin");
        if let Err(err) = cdi_coms_file
            .unwrap()
            .write_all(&to_bytes(&cdi_1.proofs.id_proofs.commitments))
        {
            eprintln!(
                "Could not output binary file cdi-coms.bin, because {}.",
                err
            );
        } else {
            println!("Output binary file cdi-coms.bin.");
        }

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
    let mut generate = |maybe_addr, acc_num, idx| {
        let acc_data = {
            let mut keys = BTreeMap::new();
            keys.insert(KeyIndex(0), KeyPair::generate(&mut csprng));
            keys.insert(KeyIndex(1), KeyPair::generate(&mut csprng));
            keys.insert(KeyIndex(2), KeyPair::generate(&mut csprng));

            CredentialData {
                keys,
                threshold: SignatureThreshold(2),
            }
        };

        let (cdi, _) = create_credential(
            context,
            &id_object,
            &id_use_data,
            acc_num,
            policy.clone(),
            &acc_data,
            &SystemAttributeRandomness,
            maybe_addr,
        )
        .expect("We should have generated valid data.");
        let acc_addr = account_address_from_registration_id(&cdi.values.cred_id);
        let js = match maybe_addr {
            Left(message_expiry) => {
                // if it is a new account we output a full message
                let cred = AccountCredentialMessage {
                    message_expiry: *message_expiry,
                    credential:     AccountCredential::Normal { cdi },
                };
                let out = Versioned::new(VERSION_0, cred);
                serde_json::to_value(out).expect("JSON serialization does not fail")
            }
            Right(_) => {
                // if this goes onto an existing account we output just the credential.
                let out = Versioned::new(VERSION_0, cdi);
                serde_json::to_value(out).expect("JSON serialization does not fail")
            }
        };

        if let Err(err) = write_json_to_file(&format!("credential-{}.json", idx), &js) {
            eprintln!("Could not output credential = {}, because {}.", idx, err);
        } else {
            println!("Output credential {}.", idx);
        }

        if let Err(err) =
            write_json_to_file(&format!("credential-private-keys-{}.json", idx), &acc_data)
        {
            eprintln!("Could not output private keys = {}, because {}.", idx, err);
        } else {
            println!("Output private keys {}.", idx);
        }
        // return the account address that can be used to deploy more credentials
        // to the same account.
        maybe_addr.right_or(acc_addr)
    };

    let _ = generate(&Left(EXPIRY), 0, 1);
    let _ = generate(&Left(EXPIRY), 1, 2);
    let _ = generate(&Left(EXPIRY), 2, 3);
    // duplicate reg_id
    let _ = generate(&Left(EXPIRY), 2, 4);
    // deploy to the same account
    let addr = generate(&Left(EXPIRY), 4, 5);
    let ra = Right(addr);
    let _ = generate(&ra, 5, 6);
    let _ = generate(&Left(EXPIRY), 6, 7);

    // Generating account and deploying several credentials to same account
    let addr2 = generate(&Left(EXPIRY), 7, 8);
    let ra2 = Right(addr2);
    let _ = generate(&ra2, 8, 9);
    let _ = generate(&ra2, 9, 10);
    let _ = generate(&ra2, 10, 11);
    let _ = generate(&ra2, 11, 12);
    let _ = generate(&ra2, 12, 13);

    let mut generate_initial = |prf, idx, ip_secret| {
        let initial_acc_data = {
            let mut keys = BTreeMap::new();
            keys.insert(KeyIndex(0), KeyPair::generate(&mut csprng));
            keys.insert(KeyIndex(1), KeyPair::generate(&mut csprng));
            keys.insert(KeyIndex(2), KeyPair::generate(&mut csprng));

            InitialAccountData {
                keys,
                threshold: SignatureThreshold(2),
            }
        };
        let ah_info = CredentialHolderInfo::<ArCurve> {
            id_cred: IdCredentials::generate(&mut csprng),
        };
        let aci = AccCredentialInfo {
            cred_holder_info: ah_info,
            prf_key:          prf,
        };

        let id_use_data = IdObjectUseData {
            aci,
            randomness: ps_sig::SigRetrievalRandomness::generate_non_zero(&mut csprng),
        };
        let (pio, _) = generate_pio(
            &context,
            Threshold(ars_infos.anonymity_revokers.len() as u8),
            &id_use_data,
            &initial_acc_data,
        )
        .expect("Generating the pre-identity object should succeed.");

        let icdi = create_initial_cdi(
            context.ip_info,
            pio.pub_info_for_ip,
            &attributes,
            EXPIRY,
            ip_secret,
        );
        let cred = AccountCredentialMessage::<IpPairing, ArCurve, _> {
            message_expiry: EXPIRY,
            credential:     AccountCredential::Initial { icdi },
        };
        let versioned_msg = Versioned::new(VERSION_0, cred);

        if let Err(err) =
            write_json_to_file(&format!("initial-credential-{}.json", idx), &versioned_msg)
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
    let prf_key: prf::SecretKey<ArCurve> = prf::SecretKey::generate(&mut csprng);
    let prf_key_same = prf_key.clone();
    generate_initial(prf_key, 2, &ip_cdi_secret_key);
    generate_initial(prf_key_same, 3, &ip_cdi_secret_key); // Reuse of prf key
    let prf_key: prf::SecretKey<ArCurve> = prf::SecretKey::generate(&mut csprng);
    let wrong_keys = ed25519_dalek::Keypair::generate(&mut csprng);
    generate_initial(prf_key, 4, &wrong_keys.secret); // Wrong secret key
}
