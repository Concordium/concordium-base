use crate::hashes::BlockHash;
use crate::id::constants::ArCurve;
use crate::id::types;
use crate::id::types::GlobalContext;
use crate::web3id::did;
use crate::web3id::v1::anchor::{
    CredentialVerificationMaterial, PresentationV1, RequestV1, VerificationRequest,
    VerificationRequestAnchor, VerificationRequestData,
};

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct VerificationContext {
    pub network: did::Network,
    pub now: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VerificationRequestAnchorAndBlockHash {
    /// The verification request anchor
    pub verification_request_anchor: VerificationRequestAnchor,
    /// The block hash for the block the anchor is registered in
    pub block_hash: BlockHash,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VerificationMaterialWithValidity {
    /// Verification material needed to verify credential
    pub verification_material: CredentialVerificationMaterial,
    /// Specification of the validity of the credential
    pub validity: CredentialValidityType,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum CredentialValidityType {
    ValidityPeriod(types::CredentialValidity),
}

#[derive(Debug, Eq, PartialEq, Copy, Clone, Hash)]
pub enum VerifyFailureReason {
    Verify, // todo arg remove
    CredentialNotValidYet,
    CredentialExpired,
}

/// This function performs several validation steps:
/// * 1. The verification request anchor on-chain corresponds to the given verification request.
/// todo ar doc
pub fn verify_presentation_with_request_anchor<'a, B>(
    global_context: &GlobalContext<ArCurve>,
    verification_context: &VerificationContext,
    verification_request: &VerificationRequest,
    verifiable_presentation: &PresentationV1,
    verification_request_anchor: &VerificationRequestAnchorAndBlockHash,
    verification_material: B,
) -> Result<(), VerifyFailureReason>
where
    B: IntoIterator<Item = &'a VerificationMaterialWithValidity> + Copy,
    B::IntoIter: ExactSizeIterator,
{
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
}

fn verify_network(
    verification_context: &VerificationContext,
    presentation: &PresentationV1,
) -> Result<(), VerifyFailureReason> {
    for metadata in presentation.metadata() {
        if metadata.network != verification_context.network {
            return Err(VerifyFailureReason::Verify);
        }
    }
    Ok(())
}

fn verify_credential_validity<'a>(
    verification_context: &VerificationContext,
    verification_material: impl IntoIterator<Item = &'a VerificationMaterialWithValidity>,
) -> Result<(), VerifyFailureReason> {
    for credential_validity in verification_material {
        match &credential_validity.validity {
            CredentialValidityType::ValidityPeriod(cred_validity) => {
                verify_credential_validity_period(verification_context.now, cred_validity)?;
            }
        }
    }
    Ok(())
}

/// determine the credential validity based on the valid from and valid to date information.
/// The block info supplied has the slot time we will use as the current time, to check validity against
fn verify_credential_validity_period(
    now: chrono::DateTime<chrono::Utc>,
    credential_validity: &types::CredentialValidity,
) -> Result<(), VerifyFailureReason> {
    let valid_from = credential_validity
        .created_at
        .lower()
        .ok_or(VerifyFailureReason::Verify)?;

    let valid_to = credential_validity
        .valid_to
        .upper()
        .ok_or(VerifyFailureReason::Verify)?;

    if now < valid_from {
        Err(VerifyFailureReason::CredentialNotValidYet)
    } else if now >= valid_to {
        Err(VerifyFailureReason::CredentialExpired)
    } else {
        Ok(())
    }
}

fn verify_presentation<'a>(
    global_context: &GlobalContext<ArCurve>,
    presentation: &PresentationV1,
    verification_material: impl ExactSizeIterator<Item = &'a VerificationMaterialWithValidity>,
) -> Result<RequestV1, VerifyFailureReason> {
    presentation
        .verify(
            global_context,
            verification_material.map(|vm| &vm.verification_material),
        )
        .map_err(|_| VerifyFailureReason::Verify)
}

fn verify_anchor_block_hash(
    request_anchor: &VerificationRequestAnchorAndBlockHash,
    presentation: &PresentationV1,
) -> Result<(), VerifyFailureReason> {
    // todo verify request anchor block hash matches presentation context

    Ok(())
}

/// Verify that request anchor matches the verification request.
fn verify_request_anchor(
    verification_request: &VerificationRequest,
    request_anchor: &VerificationRequestAnchorAndBlockHash,
) -> Result<(), VerifyFailureReason> {
    let verification_request_data = VerificationRequestData {
        context: verification_request.context.clone(),
        subject_claims: verification_request.subject_claims.clone(),
    };

    if verification_request_data.hash() != request_anchor.verification_request_anchor.hash {
        return Err(VerifyFailureReason::Verify);
    }

    Ok(())
}

/// Verify that verifiable presentation matches the verification request.
fn verify_request(
    request_from_presentation: &RequestV1,
    verification_request: &VerificationRequest,
) -> Result<(), VerifyFailureReason> {
    // todo verify subject claims in presentation matches request
    //      this incudes both statements and the identity provider and the credential type
    // todo verify context in presentation matches request context

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::types::YearMonth;

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
            Err(VerifyFailureReason::CredentialNotValidYet)
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
            Err(VerifyFailureReason::CredentialExpired)
        );
    }

    // todo ar verify tests
}
