#![cfg_attr(not(feature = "std"), no_std)]
use concordium_sc_base::{collections::*, *};

/*
 * This is an implementation of ERC-20 Token Standard used on the Ethereum
 * network.
 * It provides standard functionality for transfering tokens and allowing
 * other accounts to transfer an limited amount from ones account.
 *
 * https://github.com/ethereum/EIPs/blob/master/EIPS/eip-20.md
 *
 */

// Types
type U999 = u32; // spec says u256 but we only have u64 at most

struct InitParams {
    name:         String,
    symbol:       String,
    decimals:     u32,
    total_supply: U999,
}

pub struct State {
    init_params: InitParams,
    balances:    BTreeMap<AccountAddress, U999>,
    // (owner, spender) => amount --- Owner allows spender to send the amount
    allowed: BTreeMap<(AccountAddress, AccountAddress), U999>,
}

enum Request {
    // (receive_account, amount)
    TransferTo(AccountAddress, U999),
    // (send_account, receive_account, amount)
    TransferFromTo(AccountAddress, AccountAddress, U999),
    // called Approve in the erc20 spec. TODO: this request is insecure af wrt tx ordering.
    AllowTransfer(AccountAddress, U999),
}

// Contract

#[init(name = "init")]
#[inline(always)]
fn contract_init<I: HasInitContext<()>, L: HasLogger>(
    ctx: I,
    _amount: Amount,
    _logger: &mut L,
) -> InitResult<State> {
    let init_params: InitParams = ctx.parameter_cursor().get()?;

    // Let the creator have all the tokens
    let mut balances = BTreeMap::new();
    balances.insert(*ctx.init_origin(), init_params.total_supply);

    let state = State {
        init_params,
        balances,
        allowed: BTreeMap::new(),
    };
    Ok(state)
}

#[receive(name = "receive")]
#[inline(always)]
fn contract_receive<R: HasReceiveContext<()>, L: HasLogger, A: HasActions>(
    ctx: R,
    _: Amount,
    _: &mut L,
    state: &mut State,
) -> ReceiveResult<A> {
    let msg: Request = ctx.parameter_cursor().get()?;

    let sender_address = match ctx.sender() {
        Address::Contract(_) => bail!("Only accounts can interact with this contract"),
        Address::Account(address) => *address,
    };

    match msg {
        Request::TransferTo(account_address, amount) => {
            let sender_balance = match state.balances.get(&sender_address) {
                None => 0,
                Some(balance) => *balance,
            };
            ensure!(sender_balance >= amount, "Insufficient funds");

            let receiver_balance = match state.balances.get(&account_address) {
                None => 0,
                Some(balance) => *balance,
            };
            state.balances.insert(sender_address, sender_balance - amount);
            state.balances.insert(account_address, receiver_balance + amount);
        }
        Request::TransferFromTo(owner_address, receiver_address, amount) => {
            let allowed_amount = match state.allowed.get(&(owner_address, sender_address)) {
                None => 0,
                Some(allowed_amount) => *allowed_amount,
            };
            ensure!(
                allowed_amount >= amount,
                "The account owner is not allowing you to send this much"
            );

            let owner_balance = match state.balances.get(&owner_address) {
                None => 0,
                Some(balance) => *balance,
            };
            ensure!(owner_balance >= amount, "Insufficient funds");

            let receiver_balance = match state.balances.get(&receiver_address) {
                None => 0,
                Some(balance) => *balance,
            };
            state.allowed.insert((owner_address, sender_address), allowed_amount - amount);
            state.balances.insert(owner_address, owner_balance - amount);
            state.balances.insert(receiver_address, receiver_balance + amount);
        }
        Request::AllowTransfer(spender_address, amount) => {
            state.allowed.insert((sender_address, spender_address), amount);
        }
    }
    Ok(A::accept())
}

// (de)serialization

fn serial_string<W: Write>(s: &String, out: &mut W) -> Result<(), W::Err> {
    let bytes = s.bytes();
    (bytes.len() as u64).serial(out)?;
    for byte in bytes {
        out.write_u8(byte)?;
    }
    Ok(())
}
fn deserial_string<R: Read>(source: &mut R) -> Result<String, R::Err> {
    let len = u64::deserial(source)?;
    let mut buffer = Vec::new();
    for _n in 0..len {
        buffer.push(u8::deserial(source)?);
    }
    let res = String::from_utf8(buffer).unwrap();
    Ok(res)
}

impl Serialize for InitParams {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        serial_string(&self.name, out)?;
        serial_string(&self.symbol, out)?;
        self.decimals.serial(out)?;
        self.total_supply.serial(out)?;
        Ok(())
    }

    fn deserial<R: Read>(source: &mut R) -> Result<Self, R::Err> {
        let name = deserial_string(source)?;
        let symbol = deserial_string(source)?;
        let decimals = u32::deserial(source)?;
        let total_supply = U999::deserial(source)?;
        Ok(InitParams {
            name,
            symbol,
            decimals,
            total_supply,
        })
    }
}

impl Serialize for Request {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        match self {
            Request::TransferTo(account_address, amount) => {
                out.write_u8(0)?;
                account_address.serial(out)?;
                amount.serial(out)?;
            }
            Request::TransferFromTo(owner_address, receiver_address, amount) => {
                out.write_u8(1)?;
                owner_address.serial(out)?;
                receiver_address.serial(out)?;
                amount.serial(out)?;
            }
            Request::AllowTransfer(spender_address, amount) => {
                out.write_u8(2)?;
                spender_address.serial(out)?;
                amount.serial(out)?;
            }
        }
        Ok(())
    }

    fn deserial<R: Read>(source: &mut R) -> Result<Self, R::Err> {
        let idx = source.read_u8()?;
        match idx {
            0 => {
                let account_address = AccountAddress::deserial(source)?;
                let amount = U999::deserial(source)?;
                Ok(Request::TransferTo(account_address, amount))
            }
            1 => {
                let owner_address = AccountAddress::deserial(source)?;
                let receiver_address = AccountAddress::deserial(source)?;
                let amount = U999::deserial(source)?;
                Ok(Request::TransferFromTo(owner_address, receiver_address, amount))
            }
            2 => {
                let spender_address = AccountAddress::deserial(source)?;
                let amount = U999::deserial(source)?;
                Ok(Request::AllowTransfer(spender_address, amount))
            }
            _ => Err(Default::default()),
        }
    }
}

impl Serialize for State {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        self.balances.serial(out)?;
        self.allowed.serial(out)?;
        self.init_params.serial(out)?;
        Ok(())
    }

    fn deserial<R: Read>(source: &mut R) -> Result<Self, R::Err> {
        let balances = BTreeMap::deserial(source)?;
        let allowed = BTreeMap::deserial(source)?;
        let init_params = InitParams::deserial(source)?;
        Ok(State {
            balances,
            allowed,
            init_params,
        })
    }
}

// Tests
#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    /// Initialise token/contract giving the owner
    #[no_mangle]
    fn test_init() {
        // Setup
        let metadata = ChainMetadata {
            slot_number:      0,
            block_height:     0,
            finalized_height: 0,
            slot_time:        0,
        };
        let init_origin = AccountAddress([0u8; 32]);
        let init_ctx = InitContext {
            metadata,
            init_origin,
        };
        let parameter = InitParams {
            name:         "USD".to_string(),
            symbol:       "$".to_string(),
            decimals:     0,
            total_supply: 100,
        };
        let ctx = test_infrastructure::InitContextWrapper {
            init_ctx,
            parameter: &to_bytes(&parameter),
        };
        // set up the logger so we can intercept and analyze them at the end.
        let mut logger = test_infrastructure::LogRecorder::init();

        // Execution
        let out = contract_init(ctx, 13, &mut logger);

        // Tests
        match out {
            Err(_) => assert!(false, "Contract initialization failed."),
            Ok(state) => {
                assert_eq!(
                    state.allowed.len(),
                    0,
                    "No one is allowed to transfer from others account at this point"
                );
                assert_eq!(
                    *state.balances.get(&init_origin).unwrap(),
                    100,
                    "The creator of the contract/token should own all of the tokens"
                )
            }
        }
    }

    #[test]
    #[no_mangle]
    /// Transfers tokens from the sender account
    fn test_receive_transfer_to() {
        // Setup
        let metadata = ChainMetadata {
            slot_number:      0,
            block_height:     0,
            finalized_height: 0,
            slot_time:        0,
        };
        let from_account = AccountAddress([1u8; 32]);
        let to_account = AccountAddress([2u8; 32]);
        let receive_ctx = ReceiveContext {
            metadata,
            invoker: from_account,
            self_address: ContractAddress {
                index:    0,
                subindex: 0,
            },
            self_balance: 0,
            sender: Address::Account(from_account),
            owner: from_account,
        };
        let parameter = Request::TransferTo(to_account, 70);
        let ctx = test_infrastructure::ReceiveContextWrapper {
            receive_ctx,
            parameter: &to_bytes(&parameter),
        };
        let init_params = InitParams {
            name:         "USD".to_string(),
            symbol:       "$".to_string(),
            decimals:     0,
            total_supply: 100,
        };
        let mut balances = BTreeMap::new();
        balances.insert(from_account, 100);
        let allowed = BTreeMap::new();

        let mut logger = test_infrastructure::LogRecorder::init();
        let mut state = State {
            init_params,
            balances,
            allowed,
        };

        // Execution
        let res: ReceiveResult<test_infrastructure::ActionsTree> =
            contract_receive(ctx, 17, &mut logger, &mut state);

        // Test
        match res {
            Err(_) => assert!(false, "Contract receive support failed, but it should not have."),
            Ok(actions) => {
                assert_eq!(
                    actions,
                    test_infrastructure::ActionsTree::accept(),
                    "Transfering should result in an Accept action"
                );
                let from_balance = *state.balances.get(&from_account).unwrap();
                let to_balance = *state.balances.get(&to_account).unwrap();
                assert_eq!(
                    from_balance, 30,
                    "The transfered amount should be subtracted from sender balance"
                );
                assert_eq!(
                    to_balance, 70,
                    "The transfered amount should be added to receiver balance"
                );
            }
        }
    }

    #[test]
    #[no_mangle]
    /// Sender transfer tokens between two other accounts
    ///
    /// - The amount is subtracted from the owners allowed funds
    /// - The transfer is successful
    fn test_receive_transfer_from_to() {
        // Setup
        let metadata = ChainMetadata {
            slot_number:      0,
            block_height:     0,
            finalized_height: 0,
            slot_time:        0,
        };
        let spender_account = AccountAddress([1u8; 32]);
        let from_account = AccountAddress([2u8; 32]);
        let to_account = AccountAddress([3u8; 32]);
        let receive_ctx = ReceiveContext {
            metadata,
            invoker: spender_account,
            self_address: ContractAddress {
                index:    0,
                subindex: 0,
            },
            self_balance: 0,
            sender: Address::Account(spender_account),
            owner: spender_account,
        };
        let parameter = Request::TransferFromTo(from_account, to_account, 60);
        let ctx = test_infrastructure::ReceiveContextWrapper {
            receive_ctx,
            parameter: &to_bytes(&parameter),
        };
        let init_params = InitParams {
            name:         "Dollars".to_string(),
            symbol:       "$".to_string(),
            decimals:     0,
            total_supply: 200,
        };
        let mut balances = BTreeMap::new();
        balances.insert(from_account, 200);
        let mut allowed = BTreeMap::new();
        allowed.insert((from_account, spender_account), 100);

        let mut logger = test_infrastructure::LogRecorder::init();
        let mut state = State {
            init_params,
            balances,
            allowed,
        };

        // Execution
        let res: ReceiveResult<test_infrastructure::ActionsTree> =
            contract_receive(ctx, 17, &mut logger, &mut state);

        // Test
        match res {
            Err(_) => assert!(false, "Contract receive support failed, but it should not have."),
            Ok(actions) => {
                assert_eq!(
                    actions,
                    test_infrastructure::ActionsTree::accept(),
                    "Transfering should result in an Accept action"
                );
                let from_balance = *state.balances.get(&from_account).unwrap();
                let to_balance = *state.balances.get(&to_account).unwrap();
                let from_spender_allowed =
                    *state.allowed.get(&(from_account, spender_account)).unwrap();
                assert_eq!(
                    from_balance, 140,
                    "The transfered amount should be subtracted from sender balance"
                );
                assert_eq!(
                    to_balance, 60,
                    "The transfered amount should be added to receiver balance"
                );
                assert_eq!(
                    from_spender_allowed, 40,
                    "The transfered amount should be added to receiver balance"
                );
            }
        }
    }
}

// TODO Test failing cases