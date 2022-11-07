use crate::{from_bytes, schema::*, types};
use thiserror;

enum VersionedContractSchema {
    V0(ContractV0),
    V1(ContractV1),
    V2(ContractV2),
    V3(ContractV3),
}

#[derive(Debug, thiserror::Error)]
pub enum VersionedSchemaError {
    #[error("Parse error")]
    ParseError,
    #[error("Missing Schema Version")]
    MissingSchemaVersion,
    #[error("Invalid Schema Version")]
    InvalidSchemaVersion,
    #[error("Unable to find contract schema in module schema")]
    NoContractInModule,
    #[error("Receive function schema not found in contract schema")]
    NoReceiveInContract,
    #[error("Init function schema not found in contract schema")]
    NoInitInContract,
    #[error("Receive function schema does not contain a parameter schema")]
    NoParamsInReceive,
    #[error("Init function schema does not contain a parameter schema")]
    NoParamsInInit,
    #[error("Receive function schema not found in contract schema")]
    NoErrorInReceive,
    #[error("Init function schema does not contain an error schema")]
    NoErrorInInit,
    #[error("Errors not supported for this module version")]
    ErrorNotSupported,
    #[error("Receive function schema has no return value schema")]
    NoReturnValueInReceive,
    #[error("Return values not supported for this module version")]
    ReturnValueNotSupported,
}

impl From<types::ParseError> for VersionedSchemaError {
    fn from(_: types::ParseError) -> Self { VersionedSchemaError::ParseError }
}

/// Unpacks a versioned contract schema from a versioned module schema
fn get_versioned_contract_schema(
    versioned_module_schema: &VersionedModuleSchema,
    contract_name: &str,
) -> Result<VersionedContractSchema, VersionedSchemaError> {
    let versioned_contract_schema: VersionedContractSchema = match versioned_module_schema {
        VersionedModuleSchema::V0(module_schema) => {
            let contract_schema = module_schema
                .contracts
                .get(contract_name)
                .ok_or(VersionedSchemaError::NoContractInModule)?
                .clone();
            VersionedContractSchema::V0(contract_schema)
        }
        VersionedModuleSchema::V1(module_schema) => {
            let contract_schema = module_schema
                .contracts
                .get(contract_name)
                .ok_or(VersionedSchemaError::NoContractInModule)?
                .clone();
            VersionedContractSchema::V1(contract_schema)
        }
        VersionedModuleSchema::V2(module_schema) => {
            let contract_schema = module_schema
                .contracts
                .get(contract_name)
                .ok_or(VersionedSchemaError::NoContractInModule)?
                .clone();
            VersionedContractSchema::V2(contract_schema)
        }
        VersionedModuleSchema::V3(module_schema) => {
            let contract_schema = module_schema
                .contracts
                .get(contract_name)
                .ok_or(VersionedSchemaError::NoContractInModule)?
                .clone();
            VersionedContractSchema::V3(contract_schema)
        }
    };

    Ok(versioned_contract_schema)
}

impl VersionedModuleSchema {
    /// Get a versioned module schema. First reads header to see if the version
    /// can be discerned, otherwise tries using provided schema_version.
    pub fn new(
        schema_bytes: &[u8],
        schema_version: &Option<u8>,
    ) -> Result<Self, VersionedSchemaError> {
        let versioned_module_schema = match from_bytes::<VersionedModuleSchema>(schema_bytes) {
            Ok(versioned) => versioned,
            Err(_) => match schema_version {
                Some(0) => VersionedModuleSchema::V0(from_bytes(schema_bytes)?),
                Some(1) => VersionedModuleSchema::V1(from_bytes(schema_bytes)?),
                Some(2) => VersionedModuleSchema::V2(from_bytes(schema_bytes)?),
                Some(3) => VersionedModuleSchema::V3(from_bytes(schema_bytes)?),
                Some(_) => return Err(VersionedSchemaError::InvalidSchemaVersion),
                None => return Err(VersionedSchemaError::MissingSchemaVersion),
            },
        };
        Ok(versioned_module_schema)
    }

    /// Returns a receive function's parameter schema from a versioned module
    /// schema
    pub fn get_receive_param_schema(
        &self,
        contract_name: &str,
        function_name: &str,
    ) -> Result<Type, VersionedSchemaError> {
        let versioned_contract_schema = get_versioned_contract_schema(self, contract_name)?;
        let param_schema = match versioned_contract_schema {
            VersionedContractSchema::V0(contract_schema) => contract_schema
                .receive
                .get(function_name)
                .ok_or(VersionedSchemaError::NoReceiveInContract)?
                .clone(),
            VersionedContractSchema::V1(contract_schema) => contract_schema
                .receive
                .get(function_name)
                .ok_or(VersionedSchemaError::NoReceiveInContract)?
                .parameter()
                .ok_or(VersionedSchemaError::NoParamsInReceive)?
                .clone(),
            VersionedContractSchema::V2(contract_schema) => contract_schema
                .receive
                .get(function_name)
                .ok_or(VersionedSchemaError::NoReceiveInContract)?
                .parameter()
                .ok_or(VersionedSchemaError::NoParamsInReceive)?
                .clone(),
            VersionedContractSchema::V3(contract_schema) => contract_schema
                .receive
                .get(function_name)
                .ok_or(VersionedSchemaError::NoReceiveInContract)?
                .parameter()
                .ok_or(VersionedSchemaError::NoParamsInReceive)?
                .clone(),
        };
        Ok(param_schema)
    }

    /// Returns an init function's parameter schema from a versioned module
    /// schema
    pub fn get_init_param_schema(&self, contract_name: &str) -> Result<Type, VersionedSchemaError> {
        let versioned_contract_schema = get_versioned_contract_schema(self, contract_name)?;
        let param_schema = match versioned_contract_schema {
            VersionedContractSchema::V0(contract_schema) => {
                contract_schema.init.as_ref().ok_or(VersionedSchemaError::NoInitInContract)?.clone()
            }
            VersionedContractSchema::V1(contract_schema) => contract_schema
                .init
                .as_ref()
                .ok_or(VersionedSchemaError::NoInitInContract)?
                .parameter()
                .ok_or(VersionedSchemaError::NoParamsInInit)?
                .clone(),
            VersionedContractSchema::V2(contract_schema) => contract_schema
                .init
                .as_ref()
                .ok_or(VersionedSchemaError::NoInitInContract)?
                .parameter()
                .ok_or(VersionedSchemaError::NoParamsInInit)?
                .clone(),
            VersionedContractSchema::V3(contract_schema) => contract_schema
                .init
                .as_ref()
                .ok_or(VersionedSchemaError::NoInitInContract)?
                .parameter()
                .ok_or(VersionedSchemaError::NoParamsInInit)?
                .clone(),
        };
        Ok(param_schema)
    }

    /// Returns a receive function's error schema from a versioned module schema
    pub fn get_receive_error_schema(
        &self,
        contract_name: &str,
        function_name: &str,
    ) -> Result<Type, VersionedSchemaError> {
        let versioned_contract_schema = get_versioned_contract_schema(self, contract_name)?;
        let param_schema = match versioned_contract_schema {
            VersionedContractSchema::V0(_) => return Err(VersionedSchemaError::ErrorNotSupported),
            VersionedContractSchema::V1(_) => return Err(VersionedSchemaError::ErrorNotSupported),
            VersionedContractSchema::V2(contract_schema) => contract_schema
                .receive
                .get(function_name)
                .ok_or(VersionedSchemaError::NoReceiveInContract)?
                .error()
                .ok_or(VersionedSchemaError::NoErrorInReceive)?
                .clone(),
            VersionedContractSchema::V3(contract_schema) => contract_schema
                .receive
                .get(function_name)
                .ok_or(VersionedSchemaError::NoReceiveInContract)?
                .error()
                .ok_or(VersionedSchemaError::NoErrorInReceive)?
                .clone(),
        };
        Ok(param_schema)
    }

    /// Returns an init function's error schema from a versioned module schema
    pub fn get_init_error_schema(&self, contract_name: &str) -> Result<Type, VersionedSchemaError> {
        let versioned_contract_schema = get_versioned_contract_schema(self, contract_name)?;
        let param_schema = match versioned_contract_schema {
            VersionedContractSchema::V0(_) => return Err(VersionedSchemaError::ErrorNotSupported),
            VersionedContractSchema::V1(_) => return Err(VersionedSchemaError::ErrorNotSupported),
            VersionedContractSchema::V2(contract_schema) => contract_schema
                .init
                .as_ref()
                .ok_or(VersionedSchemaError::NoInitInContract)?
                .error()
                .ok_or(VersionedSchemaError::NoErrorInInit)?
                .clone(),
            VersionedContractSchema::V3(contract_schema) => contract_schema
                .init
                .as_ref()
                .ok_or(VersionedSchemaError::NoInitInContract)?
                .error()
                .ok_or(VersionedSchemaError::NoErrorInInit)?
                .clone(),
        };
        Ok(param_schema)
    }

    /// Returns the return value schema from a versioned module schema.
    pub fn get_receive_return_value_schema(
        &self,
        contract_name: &str,
        function_name: &str,
    ) -> Result<Type, VersionedSchemaError> {
        let versioned_contract_schema = get_versioned_contract_schema(self, contract_name)?;
        let return_value_schema = match versioned_contract_schema {
            VersionedContractSchema::V0(_) => {
                return Err(VersionedSchemaError::ReturnValueNotSupported)
            }
            VersionedContractSchema::V1(contract_schema) => contract_schema
                .receive
                .get(function_name)
                .ok_or(VersionedSchemaError::NoReceiveInContract)?
                .return_value()
                .ok_or(VersionedSchemaError::NoReturnValueInReceive)?
                .clone(),
            VersionedContractSchema::V2(contract_schema) => contract_schema
                .receive
                .get(function_name)
                .ok_or(VersionedSchemaError::NoReceiveInContract)?
                .return_value()
                .ok_or(VersionedSchemaError::NoReturnValueInReceive)?
                .clone(),
            VersionedContractSchema::V3(contract_schema) => contract_schema
                .receive
                .get(function_name)
                .ok_or(VersionedSchemaError::NoReceiveInContract)?
                .return_value()
                .ok_or(VersionedSchemaError::NoReturnValueInReceive)?
                .clone(),
        };

        Ok(return_value_schema)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module_schema() -> VersionedModuleSchema {
        let module_bytes = hex::decode(
            "ffff02010000000c00000054657374436f6e7472616374010402030100000010000000726563656976655f66756e6374696f6e06060807",
        )
        .unwrap();
        VersionedModuleSchema::new(&module_bytes, &None).unwrap()
    }

    #[test]
    fn getting_init_param_schema() {
        let extracted_type = module_schema().get_init_param_schema("TestContract").unwrap();
        assert_eq!(extracted_type, Type::U8)
    }

    #[test]
    fn getting_receive_param_schema() {
        let extracted_type =
            module_schema().get_receive_param_schema("TestContract", "receive_function").unwrap();
        assert_eq!(extracted_type, Type::I8)
    }

    #[test]
    fn getting_init_error_schema() {
        let extracted_type = module_schema().get_init_error_schema("TestContract").unwrap();
        assert_eq!(extracted_type, Type::U16)
    }

    #[test]
    fn getting_receive_error_schema() {
        let extracted_type =
            module_schema().get_receive_error_schema("TestContract", "receive_function").unwrap();
        assert_eq!(extracted_type, Type::I16)
    }

    #[test]
    fn getting_receive_return_value_schema() {
        let extracted_type = module_schema()
            .get_receive_return_value_schema("TestContract", "receive_function")
            .unwrap();
        assert_eq!(extracted_type, Type::I32)
    }
}
