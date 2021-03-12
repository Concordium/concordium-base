use anyhow::*;
use concordium_contracts_common::{schema::*, *};
use serde_json::Value;
use std::convert::TryInto;

macro_rules! serial {
    ($value:ident, $out:ident) => {
        $value.serial($out).map_err(|_| anyhow!("Failed writing"))
    };
}

/// Uses the schema to parse JSON into bytes
/// It is assumed the array of values for Map and Set are already ordered.
pub fn write_bytes_from_json_schema_type<W: Write>(
    schema: &Type,
    json: &serde_json::Value,
    out: &mut W,
) -> anyhow::Result<()> {
    match schema {
        Type::Unit => Ok(()),
        Type::Bool => {
            if let Value::Bool(b) = json {
                serial!(b, out)
            } else {
                bail!("JSON boolean required")
            }
        }
        Type::U8 => {
            if let Value::Number(n) = json {
                let n = n.as_u64().ok_or_else(|| anyhow!("Unsigned integer required"))?;
                let n: u8 = n.try_into()?;
                serial!(n, out)
            } else {
                bail!("JSON number required")
            }
        }
        Type::U16 => {
            if let Value::Number(n) = json {
                let n = n.as_u64().ok_or_else(|| anyhow!("Unsigned integer required"))?;
                let n: u16 = n.try_into()?;
                serial!(n, out)
            } else {
                bail!("JSON number required")
            }
        }
        Type::U32 => {
            if let Value::Number(n) = json {
                let n = n.as_u64().ok_or_else(|| anyhow!("Unsigned integer required"))?;
                let n: u32 = n.try_into()?;
                serial!(n, out)
            } else {
                bail!("JSON number required")
            }
        }
        Type::U64 => {
            if let Value::Number(n) = json {
                let n = n.as_u64().ok_or_else(|| anyhow!("Unsigned integer required"))?;
                serial!(n, out)
            } else {
                bail!("JSON number required")
            }
        }
        Type::I8 => {
            if let Value::Number(n) = json {
                let n = n.as_i64().ok_or_else(|| anyhow!("Signed integer required"))?;
                let n: i8 = n.try_into()?;
                serial!(n, out)
            } else {
                bail!("JSON number required")
            }
        }
        Type::I16 => {
            if let Value::Number(n) = json {
                let n = n.as_i64().ok_or_else(|| anyhow!("Signed integer required"))?;
                let n: i16 = n.try_into()?;
                serial!(n, out)
            } else {
                bail!("JSON number required")
            }
        }
        Type::I32 => {
            if let Value::Number(n) = json {
                let n = n.as_i64().ok_or_else(|| anyhow!("Signed integer required"))?;
                let n: i32 = n.try_into()?;
                serial!(n, out)
            } else {
                bail!("JSON number required")
            }
        }
        Type::I64 => {
            if let Value::Number(n) = json {
                let n = n.as_i64().ok_or_else(|| anyhow!("Signed integer required"))?;
                serial!(n, out)
            } else {
                bail!("JSON number required")
            }
        }
        Type::Amount => {
            if let Value::String(string) = json {
                let amount: u64 = string.parse()?;
                serial!(amount, out)
            } else {
                bail!("JSON String required")
            }
        }
        Type::AccountAddress => {
            if let Value::String(string) = json {
                let account: AccountAddress =
                    string.parse().map_err(|_| anyhow!("Failed parsing account address"))?;
                serial!(account, out)
            } else {
                bail!("JSON String required")
            }
        }
        Type::ContractAddress => {
            if let Value::Object(fields) = json {
                ensure!(fields.len() <= 2, "Only index and optionally subindex are allowed");

                let index = fields
                    .get("index")
                    .and_then(|v| match v {
                        Value::Number(n) => n.as_u64(),
                        _ => None,
                    })
                    .ok_or_else(|| anyhow!("'index' is required in a Contract address"))?;
                let subindex = fields
                    .get("subindex")
                    .and_then(|v| match v {
                        Value::Number(n) => n.as_u64(),
                        _ => None,
                    })
                    .unwrap_or(0);
                let contract = ContractAddress {
                    index,
                    subindex,
                };
                serial!(contract, out)
            } else {
                bail!("JSON Object with 'index' field required")
            }
        }
        Type::Timestamp => {
            if let Value::String(string) = json {
                let timestamp: Timestamp = string.parse().map_err(anyhow::Error::msg)?;
                serial!(timestamp, out)
            } else {
                bail!("JSON String required for timestamp")
            }
        }
        Type::Duration => {
            if let Value::String(string) = json {
                let duration: Duration = string.parse().map_err(anyhow::Error::msg)?;
                serial!(duration, out)
            } else {
                bail!("JSON String required for duration")
            }
        }
        Type::Pair(left_type, right_type) => {
            if let Value::Array(values) = json {
                ensure!(values.len() == 2, "Only pairs of two are supported");

                write_bytes_from_json_schema_type(left_type, &values[0], out)?;
                write_bytes_from_json_schema_type(right_type, &values[1], out)
            } else {
                bail!("JSON Array required for a pair")
            }
        }
        Type::List(size_len, ty) => {
            if let Value::Array(values) = json {
                let len = values.len();
                write_bytes_for_length_of_size(len, size_len, out)?;
                for value in values {
                    write_bytes_from_json_schema_type(ty, value, out)?;
                }
                Ok(())
            } else {
                bail!("JSON Array required")
            }
        }
        Type::Set(size_len, ty) => {
            if let Value::Array(values) = json {
                let len = values.len();
                write_bytes_for_length_of_size(len, size_len, out)?;
                for value in values {
                    write_bytes_from_json_schema_type(ty, value, out)?;
                }
                Ok(())
            } else {
                bail!("JSON Array required")
            }
        }
        Type::Map(size_len, key_ty, val_ty) => {
            if let Value::Array(entries) = json {
                let len = entries.len();
                write_bytes_for_length_of_size(len, size_len, out)?;
                for entry in entries {
                    if let Value::Array(pair) = entry {
                        ensure!(pair.len() == 2, "Expected key-value pair");
                        write_bytes_from_json_schema_type(key_ty, &pair[0], out)?;
                        write_bytes_from_json_schema_type(val_ty, &pair[1], out)?;
                    } else {
                        bail!("Expected key value pairs as JSON arrays")
                    }
                }
                Ok(())
            } else {
                bail!("JSON Array required")
            }
        }
        Type::Array(len, ty) => {
            if let Value::Array(values) = json {
                ensure!(
                    (values.len() as u32) == *len,
                    "Expected array with {} elements",
                    values.len()
                );
                for value in values {
                    write_bytes_from_json_schema_type(ty, value, out)?;
                }
                Ok(())
            } else {
                bail!("JSON Array required")
            }
        }
        Type::Struct(fields_ty) => write_bytes_from_json_schema_fields(fields_ty, json, out),
        Type::Enum(variants_ty) => {
            if let Value::Object(map) = json {
                ensure!(map.len() == 1, "Only one variant allowed");
                let (variant_name, fields_value) = map.iter().next().unwrap(); // Safe since we already checked the length
                let schema_fields_opt = variants_ty
                    .iter()
                    .enumerate()
                    .find(|(_, (variant_name_schema, _))| variant_name_schema == variant_name);
                if let Some((i, (_, variant_fields))) = schema_fields_opt {
                    if variants_ty.len() <= 256 {
                        out.write_u8(i as u8).map_err(|_| anyhow!("Failed writing"))?;
                    } else if variants_ty.len() <= 256 * 256 {
                        out.write_u16(i as u16).map_err(|_| anyhow!("Failed writing"))?;
                    } else {
                        bail!("Enums with more than 65536 variants are not supported.");
                    };
                    write_bytes_from_json_schema_fields(variant_fields, fields_value, out)
                } else {
                    // Non-existing variant
                    bail!("Unknown variant: {}", variant_name);
                }
            } else {
                bail!("JSON Object with one field required for an Enum")
            }
        }
        Type::String(size_len) => {
            if let Value::String(string) = json {
                let len = string.len();
                write_bytes_for_length_of_size(len, size_len, out)?;
                serial_vector_no_length(string.as_bytes(), out)
                    .map_err(|_| anyhow!("Failed writing"))
            } else {
                bail!("JSON String required")
            }
        }
        Type::ContractName(size_len) => {
            if let Value::Object(fields) = json {
                let contract = fields
                    .get("contract")
                    .context("Missing field 'contract' of type JSON String")?;
                ensure!(fields.len() == 1, "Expected only one field");
                if let Value::String(name) = contract {
                    let contract_name = format!("init_{}", name);
                    let len = contract_name.len();
                    write_bytes_for_length_of_size(len, size_len, out)?;
                    serial_vector_no_length(contract_name.as_bytes(), out)
                        .map_err(|_| anyhow!("Failed writing"))
                } else {
                    bail!("JSON String required for field 'contract'");
                }
            } else {
                bail!("JSON Object required for contract name")
            }
        }
        Type::ReceiveName(size_len) => {
            if let Value::Object(fields) = json {
                let contract = fields
                    .get("contract")
                    .context("Missing field 'contract' of type JSON String")?;
                let func =
                    fields.get("func").context("Missing field 'func' of type JSON String")?;
                ensure!(fields.len() == 2, "Expected only two fields");
                if let Value::String(contract) = contract {
                    if let Value::String(func) = func {
                        let receive_name = format!("{}.{}", contract, func);
                        let len = receive_name.len();
                        write_bytes_for_length_of_size(len, size_len, out)?;
                        serial_vector_no_length(receive_name.as_bytes(), out)
                            .map_err(|_| anyhow!("Failed writing"))
                    } else {
                        bail!("JSON String required for field 'func'");
                    }
                } else {
                    bail!("JSON String required for field 'contract'");
                }
            } else {
                bail!("JSON Object required for contract name")
            }
        }
        Type::U128 => {
            if let Value::String(string) = json {
                let n: u128 = string.parse().context("Could not parse as u128.")?;
                serial!(n, out)
            } else {
                bail!("JSON String required")
            }
        }
        Type::I128 => {
            if let Value::String(string) = json {
                let n: i128 = string.parse().context("Could not parse as i128.")?;
                serial!(n, out)
            } else {
                bail!("JSON String required")
            }
        }
    }
}

fn write_bytes_from_json_schema_fields<W: Write>(
    fields: &Fields,
    json: &serde_json::Value,
    out: &mut W,
) -> anyhow::Result<()> {
    match fields {
        Fields::Named(fields) => {
            if let Value::Object(map) = json {
                ensure!(fields.len() >= map.len(), "Too many fields provided");
                for (field_name, field_ty) in fields {
                    let field_value_opt = map.get(field_name);
                    if let Some(field_value) = field_value_opt {
                        write_bytes_from_json_schema_type(field_ty, field_value, out)?;
                    } else {
                        bail!("Missing field: {}", field_name);
                    }
                }
                Ok(())
            } else {
                bail!("JSON Object required for named fields");
            }
        }
        Fields::Unnamed(fields) => {
            if let Value::Array(values) = json {
                ensure!(fields.len() == values.len(), "Expected {} unnamed fields", fields.len());
                for (field_ty, value) in fields.iter().zip(values.iter()) {
                    write_bytes_from_json_schema_type(field_ty, value, out)?;
                }
                Ok(())
            } else {
                bail!("JSON Array required for unnamed fields");
            }
        }
        Fields::None => Ok(()),
    }
}

/// Serializes the length using the number of bytes specified by the size_len.
/// Returns an error if the length cannot be represented by the number of bytes.
fn write_bytes_for_length_of_size<W: Write>(
    len: usize,
    size_len: &SizeLength,
    out: &mut W,
) -> anyhow::Result<()> {
    match size_len {
        SizeLength::U8 => {
            let len: u8 = len.try_into()?;
            serial!(len, out)
        }
        SizeLength::U16 => {
            let len: u16 = len.try_into()?;
            serial!(len, out)
        }
        SizeLength::U32 => {
            let len: u32 = len.try_into()?;
            serial!(len, out)
        }
        SizeLength::U64 => {
            let len: u64 = len.try_into()?;
            serial!(len, out)
        }
    }
}
