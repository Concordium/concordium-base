//! Functionality related to constructing and identity credential proofs.
//!
#[cfg(test)]
mod tests {
    use crate::web3id::*;
    use crate::{
        base::CredentialRegistrationID,
        curve_arithmetic::Curve,
        id::{
            constants::{ArCurve, AttributeKind},
            id_proof_types::AtomicStatement,
            types::{AttributeList, AttributeTag, GlobalContext, IpIdentity},
        },
        pedersen_commitment,
    };
    use crate::{
        common::types::{KeyIndex, KeyPair},
        curve_arithmetic::arkworks_instances::ArkGroup,
        id::{
            account_holder::create_credential,
            chain::verify_cdi,
            constants::BaseField,
            id_proof_types::AttributeInRangeStatement,
            identity_provider::*,
            test::*,
            types::{
                CredentialData, IdentityObjectV1, IpData, Policy, SystemAttributeRandomness,
                YearMonth,
            },
        },
        web3id::{did::Network, Web3IdAttribute},
    };
    use anyhow::Context;
    use concordium_contracts_common::SignatureThreshold;
    use either::Either::Left;
    use rand::Rng;
    use std::collections::BTreeMap;
    use std::marker::PhantomData;

    type ExampleAttribute = AttributeKind;

    type ExampleAttributeList = AttributeList<BaseField, ExampleAttribute>;

    /// Create example attributes to be used by tests.
    pub fn test_create_attribute_list() -> ExampleAttributeList {
        let mut alist = BTreeMap::new();

        // alist.insert(AttributeTag::from(0u8), AttributeKind::from(55));
        // alist.insert(AttributeTag::from(8u8), AttributeKind::from(31));
        alist.insert(AttributeTag::from(3u8), AttributeKind::from(137));

        let valid_to = YearMonth::try_from(2022 << 8 | 5).unwrap(); // May 2022
        let created_at = YearMonth::try_from(2020 << 8 | 5).unwrap(); // May 2020
        ExampleAttributeList {
            valid_to,
            created_at,
            max_accounts: 237,
            alist,
            _phantom: Default::default(),
        }
    }

    #[test]
    /// A test flow of an `accountCreation` proof then using these credentials/randomness to generate some proofs about given statements `accountCredentialProof`.
    ///
    /// JSON serialization of requests and presentations is also tested.
    fn test_identity_proof() -> anyhow::Result<()> {
        let mut rng = rand::thread_rng();

        // Generate PIO
        let max_attrs = 10;
        let num_ars = 5;
        let IpData {
            public_ip_info: ip_info,
            ip_secret_key,
            ..
        } = test_create_ip_info(&mut rng, num_ars, max_attrs);

        let global_ctx = GlobalContext::generate(String::from("genesis_string"));

        let (ars_infos, _) =
            test_create_ars(&global_ctx.on_chain_commitment_key.g, num_ars, &mut rng);

        let id_use_data = test_create_id_use_data(&mut rng);
        let (context, pio, randomness) =
            test_create_pio_v1(&id_use_data, &ip_info, &ars_infos, &global_ctx, num_ars);
        assert!(
            *randomness == *id_use_data.randomness,
            "Returned randomness is not equal to used randomness."
        );
        let alist = test_create_attribute_list();
        let ver_ok = verify_credentials_v1(&pio, context, &alist, &ip_secret_key);
        assert!(ver_ok.is_ok(), "Signature on the credential is invalid.");

        // Generate CDI
        let ip_sig = ver_ok.unwrap();

        let id_object = IdentityObjectV1 {
            pre_identity_object: pio,
            alist,
            signature: ip_sig,
        };
        let valid_to = YearMonth::try_from(2022 << 8 | 5).unwrap(); // May 2022
        let created_at = YearMonth::try_from(2020 << 8 | 5).unwrap(); // May 2020
        let policy = Policy {
            valid_to,
            created_at,
            policy_vec: {
                BTreeMap::new()
                // tree.insert(AttributeTag::from(8u8), AttributeKind::from(31));
            },
            _phantom: Default::default(),
        };
        let acc_data = CredentialData {
            keys: {
                let mut keys = BTreeMap::new();
                keys.insert(KeyIndex(0), KeyPair::generate(&mut rng));
                keys.insert(KeyIndex(1), KeyPair::generate(&mut rng));
                keys.insert(KeyIndex(2), KeyPair::generate(&mut rng));
                keys
            },
            threshold: SignatureThreshold::TWO,
        };
        let (cdi, commitmnet_randomness) = create_credential(
            context,
            &id_object,
            &id_use_data,
            0,
            policy.clone(),
            &acc_data,
            &SystemAttributeRandomness {},
            &Left(EXPIRY),
        )
        .expect("Should generate the credential successfully.");

        let cdi_check = verify_cdi(&global_ctx, &ip_info, &ars_infos, &cdi, &Left(EXPIRY));
        assert_eq!(cdi_check, Ok(()));

        let credential_attribute_commitments = cdi.proofs.id_proofs.commitments.cmm_attributes;

        // Now re-generate the identity credential commitments to the attributes
        // we need a slighly different type, the `CommitmentInputs`, to make proofs about them.
        let mut values = BTreeMap::new();
        values.insert(3.into(), Web3IdAttribute::Numeric(137));

        let mut randomness = BTreeMap::new();
        let randomness_tag_3 = commitmnet_randomness.attributes_rand.get(&3).unwrap();
        randomness.insert(
            3.into(),
            pedersen_commitment::Randomness::<ArCurve>::new(**randomness_tag_3),
        );
        let secrets: CommitmentInputs<
            '_,
            ArkGroup<ark_ec::short_weierstrass::Projective<ark_bls12_381::g1::Config>>,
            Web3IdAttribute,
            ed25519_dalek::SigningKey,
        > = CommitmentInputs::Account {
            values: &values,
            randomness: &randomness,
            issuer: IpIdentity::from(17u32),
        };
        let commitment_inputs = [secrets];

        // Now generate the proofs with regards to the identity credential attribute statements.
        let challenge = Challenge::new(rng.gen());
        let params = GlobalContext::generate("Test".into());

        // TODO: Maybe these two values need to match any randomness from the `credentialDeployment` instead of randomly generated.
        let cred_id_exp = ArCurve::generate_scalar(&mut rng);
        let cred_id = CredentialRegistrationID::from_exponent(&params, cred_id_exp);

        let credential_statements = vec![CredentialStatement::Account {
            network: Network::Testnet,
            cred_id,
            statement: vec![
                AtomicStatement::AttributeInRange {
                    statement: AttributeInRangeStatement {
                        attribute_tag: 3.into(),
                        lower: Web3IdAttribute::Numeric(0),
                        upper: Web3IdAttribute::Numeric(1237),
                        _phantom: PhantomData,
                    },
                },
                // AtomicStatement::AttributeNotInSet {
                //     statement: AttributeNotInSetStatement {
                //         attribute_tag: 1u8.into(),
                //         set: [
                //             Web3IdAttribute::String(AttributeKind("ff".into())),
                //             Web3IdAttribute::String(AttributeKind("aa".into())),
                //             Web3IdAttribute::String(AttributeKind("zz".into())),
                //         ]
                //         .into_iter()
                //         .collect(),
                //         _phantom: PhantomData,
                //     },
                // },
            ],
        }];

        let request = Request::<ArCurve, Web3IdAttribute> {
            challenge,
            credential_statements,
        };

        let proof = request
            .clone()
            .prove(
                &params,
                <[CommitmentInputs<
                    '_,
                    ArkGroup<ark_ec::short_weierstrass::Projective<ark_bls12_381::g1::Config>>,
                    Web3IdAttribute,
                    _,
                >; 1] as IntoIterator>::into_iter(commitment_inputs),
            )
            .context("Cannot prove")?;

        // let commitments = {
        //     let key = params.on_chain_commitment_key;
        //     let mut comms = BTreeMap::new();
        //     for (tag, value) in randomness.iter() {
        //         let _ = comms.insert(
        //             AttributeTag::from(*tag),
        //             key.hide(
        //                 &pedersen_commitment::Value::<ArCurve>::new(
        //                     values.get(tag).unwrap().to_field_element(),
        //                 ),
        //                 value,
        //             ),
        //         );
        //     }
        //     comms
        // };

        let public = vec![CredentialsInputs::Account {
            commitments: credential_attribute_commitments,
        }];

        anyhow::ensure!(
            proof
                .verify(&params, public.iter())
                .context("Verification of presentation failed.")?
                == request,
            "Proof verification failed."
        );

        let data = serde_json::to_string_pretty(&proof)?;
        assert!(
            serde_json::from_str::<Presentation<ArCurve, Web3IdAttribute>>(&data).is_ok(),
            "Cannot deserialize proof correctly."
        );

        let data = serde_json::to_string_pretty(&request)?;
        assert_eq!(
            serde_json::from_str::<Request<ArCurve, Web3IdAttribute>>(&data)?,
            request,
            "Cannot deserialize request correctly."
        );

        Ok(())
    }
}
