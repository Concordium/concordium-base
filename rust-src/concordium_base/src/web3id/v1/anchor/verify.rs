use crate::hashes;
use crate::hashes::BlockHash;
use crate::id::constants::ArCurve;
use crate::id::id_proof_types::RevealAttributeStatement;
use crate::id::types;
use crate::id::types::{AttributeTag, GlobalContext, IpIdentity};
use crate::web3id::v1::anchor::{
    ContextLabel, FromContextPropertyError, IdentityCredentialType, LabeledContextProperty,
    RequestedStatement, RequestedSubjectClaims, UnfilledContextInformation,
    VerifiablePresentationRequestV1, VerifiablePresentationV1, VerificationMaterial,
    VerificationRequest, VerificationRequestAnchor, VerificationRequestData,
};
use crate::web3id::v1::{AtomicStatementV1, ContextInformation, SubjectClaims};
use crate::web3id::{did, Web3IdAttribute};
use itertools::Itertools;
use std::str::FromStr;

/// Contextual information needed for verifying credentials.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct VerificationContext {
    /// The blockchain network at which the credential must be valid. This ties
    /// the credential to the network where the credential was issued. Must match
    /// the network from which [verification material](VerificationMaterialWithValidity)
    /// and [verification request anchor](VerificationRequestAnchorAndBlockHash) is fetched.
    pub network: did::Network,
    /// The time at which the credential must be valid.
    // todo ar move out of here?
    pub validity_time: chrono::DateTime<chrono::Utc>,
}

/// Verification request anchor (VRA) including the hash of the block where it
/// is registered.
#[derive(Debug, Clone, PartialEq)]
pub struct VerificationRequestAnchorAndBlockHash {
    /// The verification request anchor (VRA)
    pub verification_request_anchor: VerificationRequestAnchor,
    /// The block hash for the block the anchor is registered in
    pub block_hash: BlockHash,
}

/// Verification material needed to verify a credential and
/// the credential validity.
#[derive(Debug, Clone, PartialEq)]
pub struct VerificationMaterialWithValidity {
    /// Verification material needed to verify credential
    pub verification_material: VerificationMaterial,
    /// Specification of the validity of the credential
    pub validity: CredentialValidityType,
}

/// Credential validity
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum CredentialValidityType {
    ValidityPeriod(types::CredentialValidity),
}

/// Reason why credential is invalid
#[derive(Debug, Eq, PartialEq, Copy, Clone, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CredentialInvalidReason {
    Verify, // todo arg remove
    CredentialNotValidYet,
    CredentialExpired,
    Network,
    PresentationUnverifiable,
    RequestAnchor,
    NoVraBlockHash,
    VraBlockHash,
    GivenContext,
    RequestedContext,
    InvalidPropertyValue,
    UnknownProperty,
    SubjectClaims,
    SubjectClaimsCredentialType,
    SubjectClaimsIssuer,
}

/// Result of verifying a presentation against the corresponding verification request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PresentationVerificationResult {
    /// The verifiable presentation was successfully verified. See
    /// [`verify_presentation_with_request_anchor`] for a list of what is
    /// verified.
    Verified,
    /// Verification of the presentation failed. The reason for the failure
    Failed(CredentialInvalidReason),
}

impl PresentationVerificationResult {
    pub fn is_success(&self) -> bool {
        matches!(self, PresentationVerificationResult::Verified)
    }
}

/// Verifies a verifiable presentation and that the presentation matches an
/// anchored verification request.
///
/// The following is verified:
///
/// * the presentation is cryptographically verifiable
/// * the credentials in the presentation are active at the time given in the verification context
/// * the subject claims and the context information in the presentation matches
///   the requested claims and context in the verification request
/// * the request anchor is formed correctly from the verification request data
///   and its registration block hash is correctly set in the verification request
/// * the network on which the presentation credentials are valid matches the network
///   in the verification context
pub fn verify_presentation_with_request_anchor<'a, B>(
    global_context: &GlobalContext<ArCurve>,
    verification_context: &VerificationContext,
    verification_request: &VerificationRequest,
    verifiable_presentation: &VerifiablePresentationV1,
    verification_request_anchor: &VerificationRequestAnchorAndBlockHash,
    verification_material: B,
) -> PresentationVerificationResult
where
    B: IntoIterator<Item = &'a VerificationMaterialWithValidity> + Copy,
    B::IntoIter: ExactSizeIterator,
{
    if let Err(reason) = (|| {
        // Verify network
        verify_network(verification_context, verifiable_presentation)?;

        // Verify validity period, is credential currently valid
        verify_credential_validity(verification_context, verification_material)?;

        // Verify the verification request matches the request anchor
        verify_request_anchor(verification_request, verification_request_anchor)?;

        // Verify anchor block hash matches presentation context
        verify_anchor_block_hash(verification_request_anchor, verifiable_presentation)?;

        // Cryptographically verify the presentation
        let request_from_presentation = verify_presentation(
            global_context,
            verifiable_presentation,
            verification_material.into_iter(),
        )?;

        // Verify the verification request matches the subject claims in the presentation
        verify_request(&request_from_presentation, verification_request)?;

        Ok(())
    })() {
        PresentationVerificationResult::Failed(reason)
    } else {
        PresentationVerificationResult::Verified
    }
}

fn verify_network(
    verification_context: &VerificationContext,
    presentation: &VerifiablePresentationV1,
) -> Result<(), CredentialInvalidReason> {
    for metadata in presentation.metadata() {
        if metadata.network != verification_context.network {
            return Err(CredentialInvalidReason::Network);
        }
    }
    Ok(())
}

fn verify_credential_validity<'a>(
    verification_context: &VerificationContext,
    verification_material: impl IntoIterator<Item = &'a VerificationMaterialWithValidity>,
) -> Result<(), CredentialInvalidReason> {
    for credential_validity in verification_material {
        match &credential_validity.validity {
            CredentialValidityType::ValidityPeriod(cred_validity) => {
                verify_credential_validity_period(
                    verification_context.validity_time,
                    cred_validity,
                )?;
            }
        }
    }
    Ok(())
}

fn verify_credential_validity_period(
    now: chrono::DateTime<chrono::Utc>,
    credential_validity: &types::CredentialValidity,
) -> Result<(), CredentialInvalidReason> {
    let valid_from = credential_validity
        .created_at
        .lower()
        .ok_or(CredentialInvalidReason::Verify)?;

    let valid_to = credential_validity
        .valid_to
        .upper()
        .ok_or(CredentialInvalidReason::Verify)?;

    if now < valid_from {
        Err(CredentialInvalidReason::CredentialNotValidYet)
    } else if now >= valid_to {
        Err(CredentialInvalidReason::CredentialExpired)
    } else {
        Ok(())
    }
}

fn verify_presentation<'a>(
    global_context: &GlobalContext<ArCurve>,
    presentation: &VerifiablePresentationV1,
    verification_material: impl ExactSizeIterator<Item = &'a VerificationMaterialWithValidity>,
) -> Result<VerifiablePresentationRequestV1, CredentialInvalidReason> {
    presentation
        .verify(
            global_context,
            verification_material.map(|vm| &vm.verification_material),
        )
        .map_err(|_| CredentialInvalidReason::PresentationUnverifiable)
}

fn verify_anchor_block_hash(
    request_anchor: &VerificationRequestAnchorAndBlockHash,
    presentation: &VerifiablePresentationV1,
) -> Result<(), CredentialInvalidReason> {
    let Some(context_block_hash_parse_res) = presentation
        .presentation_context
        .requested
        .iter()
        .find_map(|prop| {
            if prop.label == ContextLabel::BlockHash.as_str() {
                Some(hashes::BlockHash::from_str(&prop.context))
            } else {
                None
            }
        })
    else {
        return Err(CredentialInvalidReason::NoVraBlockHash);
    };

    let context_block_hash =
        context_block_hash_parse_res.map_err(|_| CredentialInvalidReason::InvalidPropertyValue)?;

    if request_anchor.block_hash != context_block_hash {
        return Err(CredentialInvalidReason::VraBlockHash);
    }

    Ok(())
}

/// Verify that request anchor matches the verification request.
fn verify_request_anchor(
    verification_request: &VerificationRequest,
    request_anchor: &VerificationRequestAnchorAndBlockHash,
) -> Result<(), CredentialInvalidReason> {
    let verification_request_data = VerificationRequestData {
        context: verification_request.context.clone(),
        subject_claims: verification_request.subject_claims.clone(),
    };

    if verification_request_data.hash() != request_anchor.verification_request_anchor.hash {
        return Err(CredentialInvalidReason::RequestAnchor);
    }

    Ok(())
}

/// Verify that verifiable presentation matches the verification request.
fn verify_request(
    request_from_presentation: &VerifiablePresentationRequestV1,
    verification_request: &VerificationRequest,
) -> Result<(), CredentialInvalidReason> {
    verify_request_context(
        &request_from_presentation.context,
        &verification_request.context,
    )?;

    verify_request_subject_claims_list(
        &request_from_presentation.subject_claims,
        &verification_request.subject_claims,
    )?;

    Ok(())
}

fn verify_request_subject_claims_list(
    presentation_claims: &[SubjectClaims<ArCurve, Web3IdAttribute>],
    request_claims: &[RequestedSubjectClaims],
) -> Result<(), CredentialInvalidReason> {
    for pair in presentation_claims.iter().zip_longest(request_claims) {
        let (pres_claims, req_claims) =
            pair.both().ok_or(CredentialInvalidReason::SubjectClaims)?;
        verify_request_subject_claims(pres_claims, req_claims)?;
    }

    Ok(())
}

fn verify_request_subject_claims(
    presentation_claims: &SubjectClaims<ArCurve, Web3IdAttribute>,
    request_claims: &RequestedSubjectClaims,
) -> Result<(), CredentialInvalidReason> {
    match request_claims {
        RequestedSubjectClaims::Identity(req_id_claims) => {
            let (pres_issuer, pres_statements) = match presentation_claims {
                SubjectClaims::Account(acc_claims) => {
                    if !req_id_claims
                        .source
                        .contains(&IdentityCredentialType::AccountCredential)
                    {
                        return Err(CredentialInvalidReason::SubjectClaimsCredentialType);
                    }

                    let stmts: Vec<_> = acc_claims
                        .statements
                        .iter()
                        .map(statement_to_requested_statement)
                        .collect();

                    (IpIdentity(200), stmts) // todo ar
                }
                SubjectClaims::Identity(id_claims) => {
                    if !req_id_claims
                        .source
                        .contains(&IdentityCredentialType::IdentityCredential)
                    {
                        return Err(CredentialInvalidReason::SubjectClaimsCredentialType);
                    }

                    let stmts: Vec<_> = id_claims
                        .statements
                        .iter()
                        .map(statement_to_requested_statement)
                        .collect();

                    (id_claims.issuer, stmts)
                }
            };

            if !req_id_claims
                .issuers
                .iter()
                .any(|issuer| issuer.identity_provider == pres_issuer)
            {
                return Err(CredentialInvalidReason::SubjectClaimsIssuer);
            }

            // todo ar network

            if pres_statements != req_id_claims.statements {
                return Err(CredentialInvalidReason::SubjectClaims);
            }

            Ok(())
        }
    }
}

fn statement_to_requested_statement(
    statement: &AtomicStatementV1<ArCurve, AttributeTag, Web3IdAttribute>,
) -> RequestedStatement<AttributeTag> {
    match statement {
        AtomicStatementV1::AttributeValue(stmt) => {
            RequestedStatement::RevealAttribute(RevealAttributeStatement {
                attribute_tag: stmt.attribute_tag,
            })
        }
        AtomicStatementV1::AttributeInRange(stmt) => {
            RequestedStatement::AttributeInRange(stmt.clone())
        }
        AtomicStatementV1::AttributeInSet(stmt) => RequestedStatement::AttributeInSet(stmt.clone()),
        AtomicStatementV1::AttributeNotInSet(stmt) => {
            RequestedStatement::AttributeNotInSet(stmt.clone())
        }
    }
}

fn verify_request_context(
    presentation_context: &ContextInformation,
    request_context: &UnfilledContextInformation,
) -> Result<(), CredentialInvalidReason> {
    fn map_parse_prop_err<T>(
        res: Result<T, FromContextPropertyError>,
    ) -> Result<T, CredentialInvalidReason> {
        res.map_err(|err| match err {
            FromContextPropertyError::ParseLabel(_) => CredentialInvalidReason::UnknownProperty,
            FromContextPropertyError::ParseValue(_) => {
                CredentialInvalidReason::InvalidPropertyValue
            }
        })
    }

    let presentation_given_properties_parse_res: Result<Vec<_>, _> = presentation_context
        .given
        .iter()
        .map(|prop| LabeledContextProperty::try_from_context_property(prop))
        .collect();

    if map_parse_prop_err(presentation_given_properties_parse_res)? != request_context.given {
        return Err(CredentialInvalidReason::GivenContext);
    }

    let presentation_requested_property_labels_parse_res: Result<Vec<_>, _> = presentation_context
        .requested
        .iter()
        .map(|prop| {
            LabeledContextProperty::try_from_context_property(prop).map(|prop| prop.label())
        })
        .collect();

    if map_parse_prop_err(presentation_requested_property_labels_parse_res)?
        != request_context.requested
    {
        return Err(CredentialInvalidReason::RequestedContext);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashes;
    use crate::id::types::YearMonth;
    use crate::web3id::did::Network;
    use crate::web3id::v1::anchor::{
        fixtures, ContextLabel, IdentityProviderDid, LabeledContextProperty,
    };
    use crate::web3id::v1::{ContextProperty, CredentialV1};
    use assert_matches::assert_matches;

    fn verification_context() -> VerificationContext {
        VerificationContext {
            network: Network::Testnet,
            validity_time: chrono::DateTime::parse_from_rfc3339("2023-08-28T23:12:15Z")
                .unwrap()
                .to_utc(),
        }
    }

    fn validity() -> CredentialValidityType {
        CredentialValidityType::ValidityPeriod(types::CredentialValidity {
            valid_to: YearMonth::new(2030, 01).unwrap(),
            created_at: YearMonth::new(2020, 01).unwrap(),
        })
    }

    /// Test [`verify_presentation_with_request_anchor`] in case where verification succeeds.
    /// Test with identity credentials.
    #[test]
    fn test_verify_completeness_identity() {
        let global_context = GlobalContext::generate("Test".into());
        let (request, vra) = fixtures::verification_request_data_to_request_and_anchor(
            fixtures::verification_request_data_fixture(),
        );
        let id_cred =
            fixtures::identity_credentials_fixture(fixtures::default_attributes(), &global_context);
        let presentation = fixtures::generate_and_prove_presentation_identity(
            &id_cred,
            fixtures::verification_request_to_verifiable_presentation_request_identity(
                &id_cred, &request,
            ),
        );

        let anchor = VerificationRequestAnchorAndBlockHash {
            verification_request_anchor: vra,
            block_hash: *fixtures::VRA_BLOCK_HASH,
        };

        let material = VerificationMaterialWithValidity {
            verification_material: id_cred.verification_material.clone(),
            validity: validity(),
        };

        assert_eq!(
            verify_presentation_with_request_anchor(
                &global_context,
                &verification_context(),
                &request,
                &presentation,
                &anchor,
                &[material],
            ),
            PresentationVerificationResult::Verified
        );
    }

    /// Test [`verify_presentation_with_request_anchor`] in case where verification succeeds.
    /// Test with account credentials.
    #[test]
    fn test_verify_completeness_account() {
        let global_context = GlobalContext::generate("Test".into());
        let (request, vra) = fixtures::verification_request_data_to_request_and_anchor(
            fixtures::verification_request_data_fixture(),
        );
        let account_cred =
            fixtures::account_credentials_fixture(fixtures::default_attributes(), &global_context);
        let presentation = fixtures::generate_and_prove_presentation_account(
            &account_cred,
            fixtures::verification_request_to_verifiable_presentation_request_account(
                &account_cred,
                &request,
            ),
        );

        let anchor = VerificationRequestAnchorAndBlockHash {
            verification_request_anchor: vra,
            block_hash: *fixtures::VRA_BLOCK_HASH,
        };

        let material = VerificationMaterialWithValidity {
            verification_material: account_cred.verification_material.clone(),
            validity: validity(),
        };

        assert_eq!(
            verify_presentation_with_request_anchor(
                &global_context,
                &verification_context(),
                &request,
                &presentation,
                &anchor,
                &[material],
            ),
            PresentationVerificationResult::Verified
        );
    }

    /// Test [`verify_presentation_with_request_anchor`] in case where verification fails.
    /// Test that network is checked.
    #[test]
    fn test_verify_soundness_network() {
        let global_context = GlobalContext::generate("Test".into());
        let (request, vra) = fixtures::verification_request_data_to_request_and_anchor(
            fixtures::verification_request_data_fixture(),
        );
        let id_cred =
            fixtures::identity_credentials_fixture(fixtures::default_attributes(), &global_context);
        let presentation = fixtures::generate_and_prove_presentation_identity(
            &id_cred,
            fixtures::verification_request_to_verifiable_presentation_request_identity(
                &id_cred, &request,
            ),
        );

        let anchor = VerificationRequestAnchorAndBlockHash {
            verification_request_anchor: vra,
            block_hash: *fixtures::VRA_BLOCK_HASH,
        };

        let material = VerificationMaterialWithValidity {
            verification_material: id_cred.verification_material.clone(),
            validity: validity(),
        };

        // verify on wrong network
        let mut verification_context = verification_context();
        verification_context.network = Network::Mainnet;

        assert_eq!(
            verify_presentation_with_request_anchor(
                &global_context,
                &verification_context,
                &request,
                &presentation,
                &anchor,
                &[material],
            ),
            PresentationVerificationResult::Failed(CredentialInvalidReason::Network)
        );
    }

    /// Test [`verify_presentation_with_request_anchor`] in case where verification fails.
    /// Test that credential validity is checked.
    #[test]
    fn test_verify_soundness_credential_validity() {
        let global_context = GlobalContext::generate("Test".into());
        let (request, vra) = fixtures::verification_request_data_to_request_and_anchor(
            fixtures::verification_request_data_fixture(),
        );
        let id_cred =
            fixtures::identity_credentials_fixture(fixtures::default_attributes(), &global_context);
        let presentation = fixtures::generate_and_prove_presentation_identity(
            &id_cred,
            fixtures::verification_request_to_verifiable_presentation_request_identity(
                &id_cred, &request,
            ),
        );

        let anchor = VerificationRequestAnchorAndBlockHash {
            verification_request_anchor: vra,
            block_hash: *fixtures::VRA_BLOCK_HASH,
        };

        let material = VerificationMaterialWithValidity {
            verification_material: id_cred.verification_material.clone(),
            validity: validity(),
        };

        // verify at a time where credential is not valid
        let mut verification_context = verification_context();
        verification_context.validity_time =
            chrono::DateTime::parse_from_rfc3339("2035-08-28T23:12:15Z")
                .unwrap()
                .to_utc();

        assert_eq!(
            verify_presentation_with_request_anchor(
                &global_context,
                &verification_context,
                &request,
                &presentation,
                &anchor,
                &[material],
            ),
            PresentationVerificationResult::Failed(CredentialInvalidReason::CredentialExpired)
        );
    }

    /// Test [`verify_presentation_with_request_anchor`] in case where verification fails.
    /// Test that presentation verifiability is checked.
    #[test]
    fn test_verify_soundness_cryptographic_verification() {
        let global_context = GlobalContext::generate("Test".into());
        let (request, vra) = fixtures::verification_request_data_to_request_and_anchor(
            fixtures::verification_request_data_fixture(),
        );
        let id_cred =
            fixtures::identity_credentials_fixture(fixtures::default_attributes(), &global_context);
        let mut presentation = fixtures::generate_and_prove_presentation_identity(
            &id_cred,
            fixtures::verification_request_to_verifiable_presentation_request_identity(
                &id_cred, &request,
            ),
        );

        let anchor = VerificationRequestAnchorAndBlockHash {
            verification_request_anchor: vra,
            block_hash: *fixtures::VRA_BLOCK_HASH,
        };

        let material = VerificationMaterialWithValidity {
            verification_material: id_cred.verification_material.clone(),
            validity: validity(),
        };

        // change proofs to be invalid
        let CredentialV1::Identity(cred) = &mut presentation.verifiable_credentials[0] else {
            panic!("expected identity credential");
        };
        cred.proof.proof_value.statement_proofs.clear();

        assert_eq!(
            verify_presentation_with_request_anchor(
                &global_context,
                &verification_context(),
                &request,
                &presentation,
                &anchor,
                &[material],
            ),
            PresentationVerificationResult::Failed(
                CredentialInvalidReason::PresentationUnverifiable
            )
        );
    }

    /// Test [`verify_presentation_with_request_anchor`] in case where verification fails.
    /// Test that request anchor hash is checked.
    #[test]
    fn test_verify_soundness_request_anchor() {
        let global_context = GlobalContext::generate("Test".into());
        let (request, vra) = fixtures::verification_request_data_to_request_and_anchor(
            fixtures::verification_request_data_fixture(),
        );
        let id_cred =
            fixtures::identity_credentials_fixture(fixtures::default_attributes(), &global_context);
        let presentation = fixtures::generate_and_prove_presentation_identity(
            &id_cred,
            fixtures::verification_request_to_verifiable_presentation_request_identity(
                &id_cred, &request,
            ),
        );

        let mut anchor = VerificationRequestAnchorAndBlockHash {
            verification_request_anchor: vra,
            block_hash: *fixtures::VRA_BLOCK_HASH,
        };

        let material = VerificationMaterialWithValidity {
            verification_material: id_cred.verification_material.clone(),
            validity: validity(),
        };

        // set wrong request data hash in the request anchor
        anchor.verification_request_anchor.hash = hashes::Hash::from([0u8; 32]);

        assert_eq!(
            verify_presentation_with_request_anchor(
                &global_context,
                &verification_context(),
                &request,
                &presentation,
                &anchor,
                &[material],
            ),
            PresentationVerificationResult::Failed(CredentialInvalidReason::RequestAnchor)
        );
    }

    /// Test [`verify_presentation_with_request_anchor`] in case where verification fails.
    /// Test that anchor block hash in presentation context is checked.
    #[test]
    fn test_verify_soundness_context_anchor_block_hash() {
        let global_context = GlobalContext::generate("Test".into());
        let (request, vra) = fixtures::verification_request_data_to_request_and_anchor(
            fixtures::verification_request_data_fixture(),
        );
        let id_cred =
            fixtures::identity_credentials_fixture(fixtures::default_attributes(), &global_context);

        let mut presentation_request =
            fixtures::verification_request_to_verifiable_presentation_request_identity(
                &id_cred, &request,
            );

        // set wrong VRA block hash in the presentation context
        for prop in &mut presentation_request.context.requested {
            if prop.label == ContextLabel::BlockHash.as_str() {
                prop.context =
                    LabeledContextProperty::BlockHash(hashes::BlockHash::from([0u8; 32]))
                        .value()
                        .to_string();
            }
        }

        let presentation =
            fixtures::generate_and_prove_presentation_identity(&id_cred, presentation_request);

        let anchor = VerificationRequestAnchorAndBlockHash {
            verification_request_anchor: vra,
            block_hash: *fixtures::VRA_BLOCK_HASH,
        };

        let material = VerificationMaterialWithValidity {
            verification_material: id_cred.verification_material.clone(),
            validity: validity(),
        };

        assert_eq!(
            verify_presentation_with_request_anchor(
                &global_context,
                &verification_context(),
                &request,
                &presentation,
                &anchor,
                &[material],
            ),
            PresentationVerificationResult::Failed(CredentialInvalidReason::VraBlockHash)
        );
    }

    /// Test [`verify_presentation_with_request_anchor`] in case where verification fails.
    /// Test that anchor block hash in presentation context is checked.
    #[test]
    fn test_verify_soundness_context_no_anchor_block_hash() {
        let global_context = GlobalContext::generate("Test".into());
        let (request, vra) = fixtures::verification_request_data_to_request_and_anchor(
            fixtures::verification_request_data_fixture(),
        );
        let id_cred =
            fixtures::identity_credentials_fixture(fixtures::default_attributes(), &global_context);

        let mut presentation_request =
            fixtures::verification_request_to_verifiable_presentation_request_identity(
                &id_cred, &request,
            );

        // remove VRA block hash from presentation context
        presentation_request
            .context
            .requested
            .retain(|prop| prop.label != ContextLabel::BlockHash.as_str());

        let presentation =
            fixtures::generate_and_prove_presentation_identity(&id_cred, presentation_request);

        let anchor = VerificationRequestAnchorAndBlockHash {
            verification_request_anchor: vra,
            block_hash: *fixtures::VRA_BLOCK_HASH,
        };

        let material = VerificationMaterialWithValidity {
            verification_material: id_cred.verification_material.clone(),
            validity: validity(),
        };

        assert_eq!(
            verify_presentation_with_request_anchor(
                &global_context,
                &verification_context(),
                &request,
                &presentation,
                &anchor,
                &[material],
            ),
            PresentationVerificationResult::Failed(CredentialInvalidReason::NoVraBlockHash)
        );
    }

    /// Test [`verify_presentation_with_request_anchor`] in case where verification fails.
    /// Tests unknown property in context
    #[test]
    fn test_verify_soundness_context_unknown_property() {
        let global_context = GlobalContext::generate("Test".into());
        let (request, vra) = fixtures::verification_request_data_to_request_and_anchor(
            fixtures::verification_request_data_fixture(),
        );
        let id_cred =
            fixtures::identity_credentials_fixture(fixtures::default_attributes(), &global_context);

        let mut presentation_request =
            fixtures::verification_request_to_verifiable_presentation_request_identity(
                &id_cred, &request,
            );
        // add unknown property to context
        presentation_request.context.given.push(ContextProperty {
            label: "UnknownPropertyLabel".to_string(),
            context: "testvalue".to_string(),
        });

        let presentation =
            fixtures::generate_and_prove_presentation_identity(&id_cred, presentation_request);

        let anchor = VerificationRequestAnchorAndBlockHash {
            verification_request_anchor: vra,
            block_hash: *fixtures::VRA_BLOCK_HASH,
        };

        let material = VerificationMaterialWithValidity {
            verification_material: id_cred.verification_material.clone(),
            validity: validity(),
        };

        assert_eq!(
            verify_presentation_with_request_anchor(
                &global_context,
                &verification_context(),
                &request,
                &presentation,
                &anchor,
                &[material],
            ),
            PresentationVerificationResult::Failed(CredentialInvalidReason::UnknownProperty)
        );
    }

    /// Test [`verify_presentation_with_request_anchor`] in case where verification fails.
    /// Tests invalid property value.
    #[test]
    fn test_verify_soundness_context_invalid_property_value() {
        let global_context = GlobalContext::generate("Test".into());
        let (request, vra) = fixtures::verification_request_data_to_request_and_anchor(
            fixtures::verification_request_data_fixture(),
        );
        let id_cred =
            fixtures::identity_credentials_fixture(fixtures::default_attributes(), &global_context);

        let mut presentation_request =
            fixtures::verification_request_to_verifiable_presentation_request_identity(
                &id_cred, &request,
            );
        // set invalid property value
        for prop in &mut presentation_request.context.given {
            if prop.label == ContextLabel::Nonce.as_str() {
                prop.context = "invalidvalue".to_string();
            }
        }

        let presentation =
            fixtures::generate_and_prove_presentation_identity(&id_cred, presentation_request);

        let anchor = VerificationRequestAnchorAndBlockHash {
            verification_request_anchor: vra,
            block_hash: *fixtures::VRA_BLOCK_HASH,
        };

        let material = VerificationMaterialWithValidity {
            verification_material: id_cred.verification_material.clone(),
            validity: validity(),
        };

        assert_eq!(
            verify_presentation_with_request_anchor(
                &global_context,
                &verification_context(),
                &request,
                &presentation,
                &anchor,
                &[material],
            ),
            PresentationVerificationResult::Failed(CredentialInvalidReason::InvalidPropertyValue)
        );
    }

    /// Test [`verify_presentation_with_request_anchor`] in case where verification fails.
    /// Test check that context in presentation matches request context.
    #[test]
    fn test_verify_soundness_context_given() {
        let global_context = GlobalContext::generate("Test".into());
        let (request, vra) = fixtures::verification_request_data_to_request_and_anchor(
            fixtures::verification_request_data_fixture(),
        );
        let id_cred =
            fixtures::identity_credentials_fixture(fixtures::default_attributes(), &global_context);

        let mut presentation_request =
            fixtures::verification_request_to_verifiable_presentation_request_identity(
                &id_cred, &request,
            );

        // change property in given context
        for prop in &mut presentation_request.context.given {
            if prop.label == ContextLabel::Nonce.as_str() {
                prop.context = hashes::Hash::from([0u8; 32]).to_string();
            }
        }

        let presentation =
            fixtures::generate_and_prove_presentation_identity(&id_cred, presentation_request);

        let anchor = VerificationRequestAnchorAndBlockHash {
            verification_request_anchor: vra,
            block_hash: *fixtures::VRA_BLOCK_HASH,
        };

        let material = VerificationMaterialWithValidity {
            verification_material: id_cred.verification_material.clone(),
            validity: validity(),
        };

        assert_eq!(
            verify_presentation_with_request_anchor(
                &global_context,
                &verification_context(),
                &request,
                &presentation,
                &anchor,
                &[material],
            ),
            PresentationVerificationResult::Failed(CredentialInvalidReason::GivenContext)
        );
    }

    /// Test [`verify_presentation_with_request_anchor`] in case where verification fails.
    /// Test check that context in presentation matches request context.
    #[test]
    fn test_verify_soundness_context_requested() {
        let global_context = GlobalContext::generate("Test".into());
        let (request, vra) = fixtures::verification_request_data_to_request_and_anchor(
            fixtures::verification_request_data_fixture(),
        );
        let id_cred =
            fixtures::identity_credentials_fixture(fixtures::default_attributes(), &global_context);

        let mut presentation_request =
            fixtures::verification_request_to_verifiable_presentation_request_identity(
                &id_cred, &request,
            );
        // remove property from requested context
        presentation_request.context.requested.pop();

        let presentation =
            fixtures::generate_and_prove_presentation_identity(&id_cred, presentation_request);

        let anchor = VerificationRequestAnchorAndBlockHash {
            verification_request_anchor: vra,
            block_hash: *fixtures::VRA_BLOCK_HASH,
        };

        let material = VerificationMaterialWithValidity {
            verification_material: id_cred.verification_material.clone(),
            validity: validity(),
        };

        assert_eq!(
            verify_presentation_with_request_anchor(
                &global_context,
                &verification_context(),
                &request,
                &presentation,
                &anchor,
                &[material],
            ),
            PresentationVerificationResult::Failed(CredentialInvalidReason::RequestedContext)
        );
    }

    /// Test [`verify_presentation_with_request_anchor`] in case where verification fails.
    /// Test that account credentials are only accepted if allowed in request.
    #[test]
    fn test_verify_soundness_claims_cred_type_account() {
        let global_context = GlobalContext::generate("Test".into());

        let mut request_data = fixtures::verification_request_data_fixture();

        // only allow identity credentials
        assert_matches!(&mut request_data.subject_claims[0], RequestedSubjectClaims::Identity(id_claims) => {
            id_claims.source.clear();
            id_claims.source.push(IdentityCredentialType::IdentityCredential);
        });

        let (request, vra) =
            fixtures::verification_request_data_to_request_and_anchor(request_data);

        let account_cred =
            fixtures::account_credentials_fixture(fixtures::default_attributes(), &global_context);
        let presentation = fixtures::generate_and_prove_presentation_account(
            &account_cred,
            fixtures::verification_request_to_verifiable_presentation_request_account(
                &account_cred,
                &request,
            ),
        );

        let anchor = VerificationRequestAnchorAndBlockHash {
            verification_request_anchor: vra,
            block_hash: *fixtures::VRA_BLOCK_HASH,
        };

        let material = VerificationMaterialWithValidity {
            verification_material: account_cred.verification_material.clone(),
            validity: validity(),
        };

        assert_eq!(
            verify_presentation_with_request_anchor(
                &global_context,
                &verification_context(),
                &request,
                &presentation,
                &anchor,
                &[material],
            ),
            PresentationVerificationResult::Failed(
                CredentialInvalidReason::SubjectClaimsCredentialType
            )
        );
    }

    /// Test [`verify_presentation_with_request_anchor`] in case where verification fails.
    /// Test that identity credentials are only accepted if allowed in request.
    #[test]
    fn test_verify_soundness_claims_cred_type_identity() {
        let global_context = GlobalContext::generate("Test".into());

        let mut request_data = fixtures::verification_request_data_fixture();

        // only allow identity credentials
        assert_matches!(&mut request_data.subject_claims[0], RequestedSubjectClaims::Identity(id_claims) => {
            id_claims.source.clear();
            id_claims.source.push(IdentityCredentialType::AccountCredential);
        });

        let (request, vra) =
            fixtures::verification_request_data_to_request_and_anchor(request_data);

        let id_cred =
            fixtures::identity_credentials_fixture(fixtures::default_attributes(), &global_context);
        let presentation = fixtures::generate_and_prove_presentation_identity(
            &id_cred,
            fixtures::verification_request_to_verifiable_presentation_request_identity(
                &id_cred, &request,
            ),
        );

        let anchor = VerificationRequestAnchorAndBlockHash {
            verification_request_anchor: vra,
            block_hash: *fixtures::VRA_BLOCK_HASH,
        };

        let material = VerificationMaterialWithValidity {
            verification_material: id_cred.verification_material.clone(),
            validity: validity(),
        };

        assert_eq!(
            verify_presentation_with_request_anchor(
                &global_context,
                &verification_context(),
                &request,
                &presentation,
                &anchor,
                &[material],
            ),
            PresentationVerificationResult::Failed(
                CredentialInvalidReason::SubjectClaimsCredentialType
            )
        );
    }

    /// Test [`verify_presentation_with_request_anchor`] in case where verification fails.
    /// Test that issuer is only accepted if allowed in request.
    #[test]
    fn test_verify_soundness_claims_issuer_account() {
        let global_context = GlobalContext::generate("Test".into());

        let mut request_data = fixtures::verification_request_data_fixture();

        // only allow issuer 1
        assert_matches!(&mut request_data.subject_claims[0], RequestedSubjectClaims::Identity(id_claims) => {
            id_claims.issuers.clear();
            id_claims.issuers.push(IdentityProviderDid::new(1u32, did::Network::Testnet));
        });

        let (request, vra) =
            fixtures::verification_request_data_to_request_and_anchor(request_data);

        let account_cred =
            fixtures::account_credentials_fixture(fixtures::default_attributes(), &global_context);
        let presentation = fixtures::generate_and_prove_presentation_account(
            &account_cred,
            fixtures::verification_request_to_verifiable_presentation_request_account(
                &account_cred,
                &request,
            ),
        );

        let anchor = VerificationRequestAnchorAndBlockHash {
            verification_request_anchor: vra,
            block_hash: *fixtures::VRA_BLOCK_HASH,
        };

        let material = VerificationMaterialWithValidity {
            verification_material: account_cred.verification_material.clone(),
            validity: validity(),
        };

        assert_eq!(
            verify_presentation_with_request_anchor(
                &global_context,
                &verification_context(),
                &request,
                &presentation,
                &anchor,
                &[material],
            ),
            PresentationVerificationResult::Failed(CredentialInvalidReason::SubjectClaimsIssuer)
        );
    }

    /// Test [`verify_presentation_with_request_anchor`] in case where verification fails.
    /// Test that issuer is only accepted if allowed in request.
    #[test]
    fn test_verify_soundness_claims_issuer_identity() {
        let global_context = GlobalContext::generate("Test".into());

        let mut request_data = fixtures::verification_request_data_fixture();

        // only allow issuer 1
        assert_matches!(&mut request_data.subject_claims[0], RequestedSubjectClaims::Identity(id_claims) => {
            id_claims.issuers.clear();
            id_claims.issuers.push(IdentityProviderDid::new(1u32, did::Network::Testnet));
        });

        let (request, vra) =
            fixtures::verification_request_data_to_request_and_anchor(request_data);

        let id_cred =
            fixtures::identity_credentials_fixture(fixtures::default_attributes(), &global_context);
        let presentation = fixtures::generate_and_prove_presentation_identity(
            &id_cred,
            fixtures::verification_request_to_verifiable_presentation_request_identity(
                &id_cred, &request,
            ),
        );

        let anchor = VerificationRequestAnchorAndBlockHash {
            verification_request_anchor: vra,
            block_hash: *fixtures::VRA_BLOCK_HASH,
        };

        let material = VerificationMaterialWithValidity {
            verification_material: id_cred.verification_material.clone(),
            validity: validity(),
        };

        assert_eq!(
            verify_presentation_with_request_anchor(
                &global_context,
                &verification_context(),
                &request,
                &presentation,
                &anchor,
                &[material],
            ),
            PresentationVerificationResult::Failed(CredentialInvalidReason::SubjectClaimsIssuer)
        );
    }

    /// Test [`verify_presentation_with_request_anchor`] in case where verification fails.
    /// Test that identity credentials are only accepted if allowed in request.
    #[test]
    fn test_verify_soundness_claims_statements() {
        let global_context = GlobalContext::generate("Test".into());
        let (request, vra) = fixtures::verification_request_data_to_request_and_anchor(
            fixtures::verification_request_data_fixture(),
        );
        let id_cred =
            fixtures::identity_credentials_fixture(fixtures::default_attributes(), &global_context);

        let mut presentation_request =
            fixtures::verification_request_to_verifiable_presentation_request_identity(
                &id_cred, &request,
            );

        // remove a statement
        assert_matches!(&mut presentation_request.subject_claims[0], SubjectClaims::Identity(id_claims) => {
            id_claims.statements.pop();
        });

        let presentation =
            fixtures::generate_and_prove_presentation_identity(&id_cred, presentation_request);

        let anchor = VerificationRequestAnchorAndBlockHash {
            verification_request_anchor: vra,
            block_hash: *fixtures::VRA_BLOCK_HASH,
        };

        let material = VerificationMaterialWithValidity {
            verification_material: id_cred.verification_material.clone(),
            validity: validity(),
        };

        assert_eq!(
            verify_presentation_with_request_anchor(
                &global_context,
                &verification_context(),
                &request,
                &presentation,
                &anchor,
                &[material],
            ),
            PresentationVerificationResult::Failed(CredentialInvalidReason::SubjectClaims)
        );
    }

    #[test]
    fn test_verify_credential_validity_period() {
        let validity = types::CredentialValidity {
            created_at: YearMonth::new(2018, 05).unwrap(),
            valid_to: YearMonth::new(2020, 08).unwrap(),
        };

        assert_eq!(
            verify_credential_validity_period(
                chrono::DateTime::parse_from_rfc3339("2019-08-29T23:12:15Z")
                    .unwrap()
                    .to_utc(),
                &validity,
            ),
            Ok(())
        );
        assert_eq!(
            verify_credential_validity_period(
                chrono::DateTime::parse_from_rfc3339("2018-05-01T00:00:00Z")
                    .unwrap()
                    .to_utc(),
                &validity,
            ),
            Ok(())
        );
        assert_eq!(
            verify_credential_validity_period(
                chrono::DateTime::parse_from_rfc3339("2018-04-30T23:59:59Z")
                    .unwrap()
                    .to_utc(),
                &validity,
            ),
            Err(CredentialInvalidReason::CredentialNotValidYet)
        );
        assert_eq!(
            verify_credential_validity_period(
                chrono::DateTime::parse_from_rfc3339("2020-08-31T23:59:59Z")
                    .unwrap()
                    .to_utc(),
                &validity,
            ),
            Ok(())
        );
        assert_eq!(
            verify_credential_validity_period(
                chrono::DateTime::parse_from_rfc3339("2020-09-01T00:00:00Z")
                    .unwrap()
                    .to_utc(),
                &validity,
            ),
            Err(CredentialInvalidReason::CredentialExpired)
        );
    }
}
