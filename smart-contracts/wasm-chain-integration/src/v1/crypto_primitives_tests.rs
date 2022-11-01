//! Basic integration tests for cryptographic primitives exposed to smart
//! contracts.
use crate::{
    constants::MAX_ACTIVATION_FRAMES,
    v0,
    v1::{
        trie::{
            self, low_level::MutableTrie, EmptyCollector, Loader, MutableState, PersistentState,
        },
        ConcordiumAllowedImports, InstanceState, ProcessedImports, ReceiveContext, ReceiveHost,
        StateLessReceiveHost,
    },
    InterpreterEnergy,
};
use concordium_contracts_common::{
    Address, Amount, ChainMetadata, ContractAddress, OwnedEntrypointName, Timestamp,
};
use sha2::Digest;
use wasm_transform::{
    artifact::{Artifact, CompiledFunctionBytes},
    machine,
    output::Output,
    parse, utils, validate,
};

static CONTRACT_BYTES: &[u8] =
    include_bytes!("../../test-data/code/v1/crypto-primitives-tests.wasm");

/// Construct the initial state for the benchmark from given key-value pairs.
fn mk_state<A: AsRef<[u8]>, B: Copy>(inputs: &[(A, B)]) -> (MutableState, Loader<Vec<u8>>)
where
    Vec<u8>: From<B>, {
    let mut node = MutableTrie::empty();
    let mut loader = Loader {
        inner: Vec::new(),
    };
    for (k, v) in inputs {
        node.insert(&mut loader, k.as_ref(), trie::Value::from(*v))
            .expect("No locks, so cannot fail.");
    }
    if let Some(trie) = node.freeze(&mut loader, &mut EmptyCollector) {
        (PersistentState::from(trie).thaw(), loader)
    } else {
        (PersistentState::Empty.thaw(), loader)
    }
}

#[test]
fn test_crypto_prims() -> anyhow::Result<()> {
    let nrg = 1_000_000_000;

    let start_energy = InterpreterEnergy {
        energy: nrg * 1000,
    };

    let skeleton = parse::parse_skeleton(CONTRACT_BYTES).unwrap();
    let module = {
        let mut module = validate::validate_module(
            &ConcordiumAllowedImports {
                support_upgrade: true,
            },
            &skeleton,
        )
        .unwrap();
        module.inject_metering().expect("Metering injection should succeed.");
        module
    };

    let artifact = module.compile::<ProcessedImports>().unwrap();
    let mut out = Vec::new();
    // make sure serialization works for artifacts so do a needless serialization +
    // deserialization
    artifact.output(&mut out)?;
    let artifact: Artifact<ProcessedImports, CompiledFunctionBytes> = utils::parse_artifact(&out)?;

    let owner = concordium_contracts_common::AccountAddress([0u8; 32]);

    let receive_ctx: ReceiveContext<&[u8]> = ReceiveContext {
        common:     v0::ReceiveContext {
            metadata: ChainMetadata {
                slot_time: Timestamp::from_timestamp_millis(0),
            },
            invoker: owner,
            self_address: ContractAddress {
                index:    0,
                subindex: 0,
            },
            self_balance: Amount::from_ccd(1000),
            sender: Address::Account(owner),
            owner,
            sender_policies: &[],
        },
        entrypoint: OwnedEntrypointName::new_unchecked("entrypoint".into()),
    };

    // Construct inputs, execute the named entrypoint, ensure it succeeds, and then
    // return the return value from the contract.
    let test_crypto_primitive = |name: &'static str, params: Vec<u8>| {
        let args = [machine::Value::I64(0)];
        let inputs: Vec<(Vec<u8>, [u8; 1])> = Vec::new();
        let artifact = &artifact;
        let params = &params;
        let (mut mutable_state, parameters) = {
            let (a, _) = mk_state(&inputs);
            (a, vec![params.clone()])
        };
        let receive_ctx = &receive_ctx;
        let args = &args[..];
        let mut backing_store = Loader {
            inner: Vec::new(),
        };
        let inner = mutable_state.get_inner(&mut backing_store);
        let state = InstanceState::new(backing_store, inner);
        let mut host = ReceiveHost::<_, Vec<u8>, _> {
            energy: start_energy,
            stateless: StateLessReceiveHost {
                activation_frames: MAX_ACTIVATION_FRAMES,
                logs: v0::Logs::new(),
                receive_ctx,
                return_value: Vec::new(),
                parameters,
                params: super::ReceiveParams::new_p5(),
            },
            state,
        };
        let r = artifact.run(&mut host, name, args);
        match r {
            Ok(res) => match res {
                machine::ExecutionOutcome::Success {
                    ..
                } => host.stateless.return_value,
                machine::ExecutionOutcome::Interrupted {
                    ..
                } => {
                    panic!(
                        "Execution terminated with an interruption, but was expected to succeed \
                         for {}..",
                        name
                    );
                }
            },
            Err(e) => panic!("Execution failed, but was expected to succeed for {}: {}.", name, e),
        }
    };

    {
        let name = "hostfn.verify_ed25519_signature";
        // expect verification to succeed.
        let params1 = {
            let sk = ed25519_zebra::SigningKey::from([1u8; 32]);
            let sig = sk.sign(&[0u8; 17]); // sign a message of zeros
            let pk = ed25519_zebra::VerificationKey::from(&sk);
            let mut params = Vec::with_capacity(100);
            params.extend_from_slice(pk.as_ref());
            params.extend_from_slice(&<[u8; 64]>::from(sig)[..]);
            params.extend_from_slice(&17u32.to_le_bytes());
            params
        };
        let rv1 = test_crypto_primitive(name, params1);
        anyhow::ensure!(
            rv1[..] == [1, 0, 0, 0],
            "Incorrect verification result for {}, case 1, got {:?}.",
            name,
            rv1
        );

        // incorrect message
        let params2 = {
            let sk = ed25519_zebra::SigningKey::from([1u8; 32]);
            let sig = sk.sign(&[]); // sign an empty message
            let pk = ed25519_zebra::VerificationKey::from(&sk);
            let mut params = Vec::with_capacity(100);
            params.extend_from_slice(pk.as_ref());
            params.extend_from_slice(&<[u8; 64]>::from(sig)[..]);
            params.extend_from_slice(&17u32.to_le_bytes());
            params
        };
        let rv2 = test_crypto_primitive(name, params2);
        anyhow::ensure!(
            rv2[..] == [0, 0, 0, 0],
            "Incorrect verification result for {}, case 2, got {:?}.",
            name,
            rv2
        );

        // incorrect public key
        let params3 = {
            let sk = ed25519_zebra::SigningKey::from([1u8; 32]);
            let sig = sk.sign(&[0u8; 17]); // sign a message of zeros
            let pk =
                ed25519_zebra::VerificationKey::from(&ed25519_zebra::SigningKey::from([2u8; 32]));
            let mut params = Vec::with_capacity(100);
            params.extend_from_slice(pk.as_ref());
            params.extend_from_slice(&<[u8; 64]>::from(sig)[..]);
            params.extend_from_slice(&17u32.to_le_bytes());
            params
        };
        let rv3 = test_crypto_primitive(name, params3);
        anyhow::ensure!(
            rv3[..] == [0, 0, 0, 0],
            "Incorrect verification result for {}, case 3, got {:?}.",
            name,
            rv3
        );
    }

    {
        // ecdsa verification has a fixed message length
        let name = "hostfn.verify_ecdsa_secp256k1_signature";
        let params1 = {
            let signer = secp256k1::Secp256k1::new();
            let sk = secp256k1::SecretKey::from_slice(&[
                0xc9, 0xef, 0x15, 0x44, 0x4b, 0x1e, 0x88, 0x5f, 0x0e, 0xd0, 0x36, 0xaa, 0xc8, 0x64,
                0x6f, 0xb0, 0xc6, 0x11, 0x88, 0x6e, 0x8c, 0x40, 0x91, 0xa1, 0xb7, 0xb2, 0xb5, 0xa0,
                0x95, 0xd2, 0xd6, 0xba,
            ])
            .expect("Key generated with openssl, so should be valid.");
            let message = secp256k1::Message::from_slice(&sha2::Sha256::digest(&[])[..])
                .expect("Hashes are valid messages.");
            let sig = signer.sign_ecdsa(&message, &sk);
            let pk = secp256k1::PublicKey::from_slice(&[
                0x04, 0xbb, 0xc0, 0xa1, 0xad, 0x6f, 0x0d, 0x2c, 0x1f, 0x32, 0x50, 0xd9, 0x08, 0x78,
                0x15, 0x37, 0xd6, 0x8c, 0xf4, 0xa6, 0x96, 0x41, 0x74, 0xb9, 0x70, 0x36, 0x2c, 0x66,
                0x47, 0x52, 0x11, 0xc6, 0xf8, 0x70, 0xd4, 0xc1, 0x99, 0xc7, 0x93, 0xbf, 0x3d, 0x6c,
                0x21, 0x55, 0x2d, 0xad, 0xee, 0xc5, 0x1b, 0x6a, 0x3f, 0xa6, 0x0a, 0x7c, 0x1a, 0x1f,
                0x63, 0xd5, 0x8f, 0xf5, 0x51, 0x7b, 0x74, 0xf8, 0x12,
            ])
            .expect(
                "Should be a valid public key matching the secret key above. Generated with \
                 openssl.",
            );
            let mut params = Vec::with_capacity(100);
            params.extend_from_slice(&pk.serialize());
            params.extend_from_slice(&sig.serialize_compact());
            params.extend_from_slice(message.as_ref());
            params
        };
        let rv1 = test_crypto_primitive(name, params1);
        anyhow::ensure!(
            rv1[..] == [1, 0, 0, 0],
            "Incorrect verification result for {}, case 1, got {:?}.",
            name,
            rv1
        );

        // different message
        let params2 = {
            let signer = secp256k1::Secp256k1::new();
            let sk = secp256k1::SecretKey::from_slice(&[
                0xc9, 0xef, 0x15, 0x44, 0x4b, 0x1e, 0x88, 0x5f, 0x0e, 0xd0, 0x36, 0xaa, 0xc8, 0x64,
                0x6f, 0xb0, 0xc6, 0x11, 0x88, 0x6e, 0x8c, 0x40, 0x91, 0xa1, 0xb7, 0xb2, 0xb5, 0xa0,
                0x95, 0xd2, 0xd6, 0xba,
            ])
            .expect("Key generated with openssl, so should be valid.");
            let message = secp256k1::Message::from_slice(&sha2::Sha256::digest(&[])[..])
                .expect("Hashes are valid messages.");
            let sig = signer.sign_ecdsa(&message, &sk);
            let pk = secp256k1::PublicKey::from_slice(&[
                0x04, 0xbb, 0xc0, 0xa1, 0xad, 0x6f, 0x0d, 0x2c, 0x1f, 0x32, 0x50, 0xd9, 0x08, 0x78,
                0x15, 0x37, 0xd6, 0x8c, 0xf4, 0xa6, 0x96, 0x41, 0x74, 0xb9, 0x70, 0x36, 0x2c, 0x66,
                0x47, 0x52, 0x11, 0xc6, 0xf8, 0x70, 0xd4, 0xc1, 0x99, 0xc7, 0x93, 0xbf, 0x3d, 0x6c,
                0x21, 0x55, 0x2d, 0xad, 0xee, 0xc5, 0x1b, 0x6a, 0x3f, 0xa6, 0x0a, 0x7c, 0x1a, 0x1f,
                0x63, 0xd5, 0x8f, 0xf5, 0x51, 0x7b, 0x74, 0xf8, 0x12,
            ])
            .expect(
                "Should be a valid public key matching the secret key above. Generated with \
                 openssl.",
            );
            let mut params = Vec::with_capacity(100);
            params.extend_from_slice(&pk.serialize());
            params.extend_from_slice(&sig.serialize_compact());
            let incorrect_message = secp256k1::Message::from_slice(&sha2::Sha256::digest(&[0])[..])
                .expect("Hashes are valid messages.");
            params.extend_from_slice(incorrect_message.as_ref());
            params
        };
        let rv2 = test_crypto_primitive(name, params2);
        anyhow::ensure!(
            rv2[..] == [0, 0, 0, 0],
            "Incorrect verification result for {}, case 2, got {:?}.",
            name,
            rv2
        );

        // non-matching public key
        let params3 = {
            let signer = secp256k1::Secp256k1::new();
            let sk = secp256k1::SecretKey::from_slice(&[
                0xc9, 0xef, 0x15, 0x44, 0x4b, 0x1e, 0x88, 0x5f, 0x0e, 0xd0, 0x36, 0xaa, 0xc8, 0x64,
                0x6f, 0xb0, 0xc6, 0x11, 0x88, 0x6e, 0x8c, 0x40, 0x91, 0xa1, 0xb7, 0xb2, 0xb5, 0xa0,
                0x95, 0xd2, 0xd6, 0xba,
            ])
            .expect("Key generated with openssl, so should be valid.");
            let message = secp256k1::Message::from_slice(&sha2::Sha256::digest(&[])[..])
                .expect("Hashes are valid messages.");
            let sig = signer.sign_ecdsa(&message, &sk);
            let pk = secp256k1::PublicKey::from_slice(&[
                0x04, 0xf2, 0x56, 0xc6, 0xe6, 0xc8, 0x0b, 0x21, 0x3f, 0x2a, 0xa0, 0xb0, 0x17, 0x44,
                0x23, 0x5d, 0x51, 0x5c, 0x59, 0x44, 0x35, 0xbe, 0x65, 0x1b, 0x15, 0x88, 0x3a, 0x10,
                0xdd, 0x47, 0x2f, 0xa6, 0x46, 0xce, 0x62, 0xea, 0xf3, 0x67, 0x0d, 0xc5, 0xcb, 0x91,
                0x00, 0xa0, 0xca, 0x2a, 0x55, 0xb2, 0xc1, 0x47, 0xc1, 0xe9, 0xa3, 0x8c, 0xe4, 0x28,
                0x87, 0x8e, 0x7d, 0x46, 0xe1, 0xfb, 0x71, 0x4a, 0x99,
            ])
            .expect(
                "Should be a valid public key matching the secret key above. Generated with \
                 openssl.",
            );
            let mut params = Vec::with_capacity(100);
            params.extend_from_slice(&pk.serialize());
            params.extend_from_slice(&sig.serialize_compact());
            params.extend_from_slice(message.as_ref());
            params
        };
        let rv3 = test_crypto_primitive(name, params3);
        anyhow::ensure!(
            rv3[..] == [0, 0, 0, 0],
            "Incorrect verification result for {}, case 3, got {:?}.",
            name,
            rv3
        );
    }

    {
        // n is the length of the data to be hashed
        for n in [0u32, 10, 20, 50, 100, 1000, 10_000, 100_000] {
            let name = "hostfn.hash_sha2_256";
            let params = n.to_le_bytes().to_vec(); // length to hash
            let rv = test_crypto_primitive(name, params);
            let hash = sha2::Sha256::digest(vec![0u8; n as usize]);
            anyhow::ensure!(rv == hash[..], "Incorrect SHA2-256 digest for n = {}.", n);
        }
    }

    {
        // n is the length of the data to be hashed
        for n in [0u32, 10, 20, 50, 100, 1000, 10_000, 100_000] {
            let name = "hostfn.hash_sha3_256";
            let params = n.to_le_bytes().to_vec(); // length to hash
            let rv = test_crypto_primitive(name, params);
            let hash = sha3::Sha3_256::digest(vec![0u8; n as usize]);
            anyhow::ensure!(rv == hash[..], "Incorrect SHA3-256 digest for n = {}.", n);
        }
    }

    {
        // n is the length of the data to be hashed
        for n in [0u32, 10, 20, 50, 100, 1000, 10_000, 100_000] {
            let name = "hostfn.hash_keccak_256";
            let params = n.to_le_bytes().to_vec(); // length to hash
            let rv = test_crypto_primitive(name, params);
            let hash = sha3::Keccak256::digest(vec![0u8; n as usize]);
            anyhow::ensure!(rv == hash[..], "Incorrect Keccak-256 digest for n = {}.", n);
        }
    }

    Ok(())
}
