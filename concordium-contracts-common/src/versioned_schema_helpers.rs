use crate::{from_bytes, schema::*};
use anyhow::{anyhow, Result};

enum VersionedContractSchema {
    V0(ContractV0),
    V1(ContractV1),
    V2(ContractV2),
    V3(ContractV3),
}

/// Unpacks a versioned contract schema from a versioned module schema
fn get_versioned_contract_schema(
    versioned_module_schema: &VersionedModuleSchema,
    contract_name: &str,
) -> Result<VersionedContractSchema> {
    let versioned_contract_schema: VersionedContractSchema = match versioned_module_schema {
        VersionedModuleSchema::V0(module_schema) => {
            let contract_schema = module_schema
                .contracts
                .get(contract_name)
                .ok_or_else(|| anyhow!("Unable to find contract schema in module schema"))?
                .clone();
            VersionedContractSchema::V0(contract_schema)
        }
        VersionedModuleSchema::V1(module_schema) => {
            let contract_schema = module_schema
                .contracts
                .get(contract_name)
                .ok_or_else(|| anyhow!("Unable to find contract schema in module schema"))?
                .clone();
            VersionedContractSchema::V1(contract_schema)
        }
        VersionedModuleSchema::V2(module_schema) => {
            let contract_schema = module_schema
                .contracts
                .get(contract_name)
                .ok_or_else(|| anyhow!("Unable to find contract schema in module schema"))?
                .clone();
            VersionedContractSchema::V2(contract_schema)
        }
        VersionedModuleSchema::V3(module_schema) => {
            let contract_schema = module_schema
                .contracts
                .get(contract_name)
                .ok_or_else(|| anyhow!("Unable to find contract schema in module schema"))?
                .clone();
            VersionedContractSchema::V3(contract_schema)
        }
    };

    Ok(versioned_contract_schema)
}

/// Get a versioned module schema. First reads header to see if the version can
/// be discerned, otherwise tries using provided schema_version.
pub fn get_versioned_module_schema(
    schema_bytes: &[u8],
    schema_version: &Option<u8>,
) -> Result<VersionedModuleSchema> {
    let versioned_module_schema = match from_bytes::<VersionedModuleSchema>(schema_bytes) {
        Ok(versioned) => versioned,
        Err(_) => match schema_version {
            Some(0) => VersionedModuleSchema::V0(from_bytes(schema_bytes)?),
            Some(1) => VersionedModuleSchema::V1(from_bytes(schema_bytes)?),
            Some(2) => VersionedModuleSchema::V2(from_bytes(schema_bytes)?),
            Some(3) => VersionedModuleSchema::V3(from_bytes(schema_bytes)?),
            Some(_) => return Err(anyhow!("Invalid schema version")),
            None => return Err(anyhow!("Missing schema version")),
        },
    };
    Ok(versioned_module_schema)
}

/// Returns the return value schema from a versioned module schema.
pub fn get_return_value_schema(
    versioned_module_schema: &VersionedModuleSchema,
    contract_name: &str,
    function_name: &str,
) -> Result<Type> {
    let versioned_contract_schema =
        get_versioned_contract_schema(versioned_module_schema, contract_name)?;
    let return_value_schema = match versioned_contract_schema {
        VersionedContractSchema::V0(_) => {
            return Err(anyhow!("Return values are not supported V0 smart contracts."))
        }
        VersionedContractSchema::V1(contract_schema) => contract_schema
            .receive
            .get(function_name)
            .ok_or_else(|| anyhow!("Receive function could not be found in the contract schema"))?
            .return_value()
            .ok_or_else(|| anyhow!("Receive function schema has no return value schema"))?
            .clone(),
        VersionedContractSchema::V2(contract_schema) => contract_schema
            .receive
            .get(function_name)
            .ok_or_else(|| anyhow!("Receive function could not be found in the contract schema"))?
            .return_value()
            .ok_or_else(|| anyhow!("Receive function schema has no return value schema"))?
            .clone(),
        VersionedContractSchema::V3(contract_schema) => contract_schema
            .receive
            .get(function_name)
            .ok_or_else(|| anyhow!("Receive function could not be found in the contract schema"))?
            .return_value()
            .ok_or_else(|| anyhow!("Receive function schema has no return value schema"))?
            .clone(),
    };

    Ok(return_value_schema)
}

/// Returns a receive function's parameter schema from a versioned module schema
pub fn get_receive_param_schema(
    versioned_module_schema: &VersionedModuleSchema,
    contract_name: &str,
    function_name: &str,
) -> anyhow::Result<Type> {
    let versioned_contract_schema =
        get_versioned_contract_schema(versioned_module_schema, contract_name)?;
    let param_schema = match versioned_contract_schema {
        VersionedContractSchema::V0(contract_schema) => contract_schema
            .receive
            .get(function_name)
            .ok_or_else(|| anyhow!("Receive function could not be found in the contract schema"))?
            .clone(),
        VersionedContractSchema::V1(contract_schema) => contract_schema
            .receive
            .get(function_name)
            .ok_or_else(|| anyhow!("Receive function could not be found in the contract schema"))?
            .parameter()
            .ok_or_else(|| anyhow!("Receive function schema does not contain a parameter schema"))?
            .clone(),
        VersionedContractSchema::V2(contract_schema) => contract_schema
            .receive
            .get(function_name)
            .ok_or_else(|| anyhow!("Receive function could not be found in the contract schema"))?
            .parameter()
            .ok_or_else(|| anyhow!("Receive function schema does not contain a parameter schema"))?
            .clone(),
        VersionedContractSchema::V3(contract_schema) => contract_schema
            .receive
            .get(function_name)
            .ok_or_else(|| anyhow!("Receive function could not be found in the contract schema"))?
            .parameter()
            .ok_or_else(|| anyhow!("Receive function schema does not contain a parameter schema"))?
            .clone(),
    };
    Ok(param_schema)
}

/// Returns a init function's parameter schema from a versioned module schema
pub fn get_init_param_schema(
    versioned_module_schema: &VersionedModuleSchema,
    contract_name: &str,
) -> anyhow::Result<Type> {
    let versioned_contract_schema =
        get_versioned_contract_schema(versioned_module_schema, contract_name)?;
    let param_schema = match versioned_contract_schema {
        VersionedContractSchema::V0(contract_schema) => contract_schema
            .init
            .as_ref()
            .ok_or_else(|| anyhow!("Init function schema not found in contract schema"))?
            .clone(),
        VersionedContractSchema::V1(contract_schema) => contract_schema
            .init
            .as_ref()
            .ok_or_else(|| anyhow!("Init function schema not found in contract schema"))?
            .parameter()
            .ok_or_else(|| anyhow!("Init function schema does not contain a parameter schema"))?
            .clone(),
        VersionedContractSchema::V2(contract_schema) => contract_schema
            .init
            .as_ref()
            .ok_or_else(|| anyhow!("Init function schema not found in contract schema"))?
            .parameter()
            .ok_or_else(|| anyhow!("Init function schema does not contain a parameter schema"))?
            .clone(),
        VersionedContractSchema::V3(contract_schema) => contract_schema
            .init
            .as_ref()
            .ok_or_else(|| anyhow!("Init function schema not found in contract schema"))?
            .parameter()
            .ok_or_else(|| anyhow!("Init function schema does not contain a parameter schema"))?
            .clone(),
    };
    Ok(param_schema)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module_schema() -> VersionedModuleSchema {
        let module_bytes = hex::decode(
            "ffff02010000000c00000054657374436f6e74726163740100020100000010000000726563656976655f66756e6374696f6e020304",
        )
        .unwrap();
        get_versioned_module_schema(&module_bytes, &None).unwrap()
    }

    #[test]
    fn getting_init_param_schema() {
        let extracted_type = get_init_param_schema(&module_schema(), "TestContract").unwrap();
        assert_eq!(extracted_type, Type::U8)
    }

    #[test]
    fn getting_receive_param_schema() {
        let extracted_type =
            get_receive_param_schema(&module_schema(), "TestContract", "receive_function").unwrap();
        assert_eq!(extracted_type, Type::U16)
    }

    #[test]
    fn getting_return_value_schema() {
        let extracted_type =
            get_return_value_schema(&module_schema(), "TestContract", "receive_function").unwrap();
        assert_eq!(extracted_type, Type::U32)
    }
}
