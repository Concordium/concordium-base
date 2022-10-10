use std::fmt::Debug;

use arbitrary::{Arbitrary, Result, Unstructured};
use concordium_contracts_common::{
    AccountAddress, Address::Account, Amount, AttributeTag, ChainMetadata, ContractAddress, Policy,
    Timestamp, ACCOUNT_ADDRESS_SIZE,
};
use wasm_smith::Config;
pub use wasm_smith::{ConfiguredModule, InterpreterConfig};

use crate::{ExecResult, InitContext, ReceiveContext};

#[derive(Arbitrary, Debug)]
pub struct RandomizedInterpreterInput<C: Config> {
    pub amount:      u64,
    pub module:      ConfiguredModule<C>,
    pub init_ctx:    InitContext,
    pub receive_ctx: ReceiveContext,
    pub state:       Vec<u8>,
    pub parameter:   Vec<u8>,
}

#[derive(Debug)]
pub struct DeterministicInterpreterInput {
    pub amount:      u64,
    pub module:      ConfiguredModule<InterpreterConfig>,
    pub init_ctx:    InitContext,
    pub receive_ctx: ReceiveContext,
    pub state:       Vec<u8>,
    pub parameter:   Vec<u8>,
}

/// Creates a deterministic state and parameters for the smart contract. Only
/// the SC module itself is randomized.
impl Arbitrary for DeterministicInterpreterInput {
    fn arbitrary(u: &mut Unstructured<'_>) -> Result<Self> {
        Ok(DeterministicInterpreterInput {
            amount:      1000,
            module:      ConfiguredModule::arbitrary(u)?,
            init_ctx:    InitContext {
                metadata:        ChainMetadata {
                    slot_time: Timestamp::from_timestamp_millis(1000),
                },
                init_origin:     AccountAddress([5; ACCOUNT_ADDRESS_SIZE]),
                sender_policies: vec![Policy {
                    identity_provider: 500,
                    created_at:        Timestamp::from_timestamp_millis(400),
                    valid_to:          Timestamp::from_timestamp_millis(2000),
                    items:             vec![(AttributeTag(5), String::from("policy").into_bytes())],
                }],
            },
            receive_ctx: ReceiveContext {
                metadata:        ChainMetadata {
                    slot_time: Timestamp::from_timestamp_millis(1000),
                },
                invoker:         AccountAddress([0; ACCOUNT_ADDRESS_SIZE]),
                self_address:    ContractAddress {
                    index:    10,
                    subindex: 5,
                },
                self_balance:    Amount::from_ccd(1),
                sender:          Account(AccountAddress([7; ACCOUNT_ADDRESS_SIZE])),
                owner:           AccountAddress([6; ACCOUNT_ADDRESS_SIZE]),
                sender_policies: Vec::new(),
            },
            state:       String::from("Very interesting state that has a bunch of words")
                .into_bytes(),
            parameter:   String::from("The best parameter").into_bytes(),
        })
    }
}

pub struct PrintConfig {
    pub print_success:                    bool,
    pub print_failure:                    bool,
    pub print_module_before_interpreting: bool,
    pub print_failing_module:             bool,
}

pub fn process<R: Debug>(result: ExecResult<R>, bytes: &[u8], conf: PrintConfig) {
    match result {
        Ok(res) => {
            if conf.print_success {
                println!("Success:\n{:?}", res);
            }
        }
        Err(err) => {
            if !conf.print_module_before_interpreting && conf.print_failing_module {
                print_module(&bytes);
            }
            if conf.print_failure {
                println!("Failure:\n{:?}\n\n", err);
            }
        }
    }
}

pub fn print_module(bytes: &[u8]) {
    let prog = wasmprinter::print_bytes(&bytes).unwrap();
    println!("Processed program:\n{}", prog);
}
