# Changelog 

## [0.2.0]

### Added

- Added method `compute_credential_deployment_hash_to_sign` for computing the credential deployment sign digest that must be signed to deploy a new credential.
- Added method `serialize_credential_deployment_payload` for serializing the credential deployment payload. 
This payload is the one sent as a raw payload to the node when deploying a new credential.

## [0.1.0]

### Added

- Initial version of the package with functions migrated from the Rust implementation in the node JS SDK.
