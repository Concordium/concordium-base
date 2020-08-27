#![cfg_attr(not(feature = "std"), no_std)]
use concordium_sc_base::*;
use concordium_sc_base::collections::*;

// Implementation plan:
// 1. copy escrow contract +done
// 2. outline erc20 in types +done
// 3. implement erc20 requests/responses
// 4. remove escrow implementation
// 5. clean up and test

/* This Escrow contract is more a code sample that a real-world contract that
 * someone might want to use in production.
 *
 * The semantics of this contract have been chosen somewhat arbitrarily.
 * The contract utilised an arbitrator account to resolve disputes between
 * a buyer and seller, and that arbitrator gets paid when the contract is
 * completed (either in favour of the buyer or the seller).
 *
 * More advanced, real-world contracts may want to consider the parties
 * requesting to withdraw funds rather than having them pushed to their
 * accounts and so on, in light of best practises from other chains.
 */

// Types

type U999 = u32; // spec says u256 but we only have u64 at most

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    AwaitingDeposit,
    AwaitingDelivery,
    AwaitingArbitration,
    Done,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Arbitration {
    ReturnDepositToBuyer,
    ReleaseFundsToSeller,
    ReawaitDelivery,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Message {
    SubmitDeposit,
    AcceptDelivery,
    Contest,
    Arbitrate(Arbitration),
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct InitParams {
    required_deposit: Amount,
    arbiter_fee:      Amount,
    buyer:            AccountAddress,
    seller:           AccountAddress,
    arbiter:          AccountAddress,
    total_supply:      U999,
}

#[derive(Clone)]
pub struct State {
    mode:             Mode,
    required_deposit: Amount,
    arbiter_fee:      Amount,
    buyer:            AccountAddress,
    seller:           AccountAddress,
    arbiter:          AccountAddress,

    // erc20
    balances:         BTreeMap<AccountAddress, U999>,
    allowed:          BTreeMap<(AccountAddress, AccountAddress), U999>, // (from, to) => amount
    total_supply:     U999,
}

enum Request {
    // Reads
    GetName(), // e.g. "Global Transaction Unit"
    GetSymbol(), // e.g. "GTU"
    GetDecimals(), // number of decimal digits after the decimal point when showing the value to the user, e.g. 2 for showing USD when we're actually tracking USD cents in this contract.
    GetTotalSupply(),
    GetBalanceOf(AccountAddress),
    GetAllowance(AccountAddress, AccountAddress), // (from, to)

    // Writes
    TransferTo(AccountAddress, U999),
    TransferFromTo(AccountAddress, AccountAddress, U999),
    AllowTransfer(AccountAddress, U999), // called Approve in the erc20 spec. TODO: this request is insecure af wrt tx ordering.
}

enum Response {
    // Note: I'm mirroring the input arguments to each request in the beginning of each response so we know what we're responding to
    // Reads
    ResponseGetName(String),
    ResponseGetSymbol(), // e.g. "GTU"
    ResponseGetTotalSupply(U999),
    ResponseGetBalanceOf(AccountAddress, U999),
    ResponseGetAllowance(AccountAddress, AccountAddress, U999), // (from, to, amount)

    // Writes
    ResponseTransferTo(AccountAddress, U999, bool), // required to throw if caller doesn't have enough money, but still returns a bool indicating success, which presumably can never be false? Doesn't say what to do if either address is invalid
    ResponseTransferFromTo(AccountAddress, AccountAddress, U999, bool),
    ResponseAllowTransfer(AccountAddress, U999, bool), // called Approve in the erc20 spec. TODO: this request is insecure af wrt tx ordering.
}

// TODO: I'm not sure how to implement events, or if it's even a good idea?

// Contract implementation

#[init(name = "init")]
#[inline(always)]
fn contract_init<I: HasInitContext<()>, L: HasLogger>(
    ctx: I,
    amount: Amount,
    _logger: &mut L,
) -> InitResult<State> {
    ensure!(amount == 0, "This escrow contract must be initialised with a 0 amount.");
    let init_params: InitParams = ctx.parameter_cursor().get()?;
    ensure!(
        init_params.buyer != init_params.seller,
        "Buyer and seller must have different accounts."
    );
    let state = State {
        mode:             Mode::AwaitingDeposit,
        required_deposit: init_params.required_deposit,
        arbiter_fee:      init_params.arbiter_fee,
        buyer:            init_params.buyer,
        seller:           init_params.seller,
        arbiter:          init_params.arbiter,
        balances:         BTreeMap::new(),
        allowed:          BTreeMap::new(),
        total_supply:      init_params.total_supply,
    };
    Ok(state)
}

#[receive(name = "receive")]
#[inline(always)]
fn contract_receive<R: HasReceiveContext<()>, L: HasLogger, A: HasActions>(
    ctx: R,
    amount: Amount,
    _logger: &mut L,
    state: &mut State,
) -> ReceiveResult<A> {
    let msg: Message = ctx.parameter_cursor().get()?;



    match (state.mode, msg) {
        (Mode::AwaitingDeposit, Message::SubmitDeposit) => {
            ensure!(
                ctx.sender().matches_account(&state.buyer),
                "Only the designated buyer can submit the deposit."
            );
            ensure!(
                amount == state.required_deposit + state.arbiter_fee,
                "Amount given does not match the required deposit and arbiter fee."
            );
            state.mode = Mode::AwaitingDelivery;
            Ok(A::accept())
        }

        (Mode::AwaitingDelivery, Message::AcceptDelivery) => {
            ensure!(
                ctx.sender().matches_account(&state.buyer),
                "Only the designated buyer can accept delivery."
            );
            state.mode = Mode::Done;
            let release_payment_to_seller =
                A::simple_transfer(&state.seller, state.required_deposit);
            let pay_arbiter = A::simple_transfer(&state.arbiter, state.arbiter_fee);
            Ok(try_send_both(release_payment_to_seller, pay_arbiter))
        }

        (Mode::AwaitingDelivery, Message::Contest) => {
            ensure!(
                ctx.sender().matches_account(&state.buyer)
                    || ctx.sender().matches_account(&state.seller),
                "Only the designated buyer or seller can contest delivery."
            );
            state.mode = Mode::AwaitingArbitration;
            Ok(A::accept())
        }

        (Mode::AwaitingArbitration, Message::Arbitrate(Arbitration::ReturnDepositToBuyer)) => {
            state.mode = Mode::Done;
            let return_deposit = A::simple_transfer(&state.buyer, state.required_deposit);
            let pay_arbiter = A::simple_transfer(&state.arbiter, state.arbiter_fee);
            Ok(try_send_both(return_deposit, pay_arbiter))
        }

        (Mode::AwaitingArbitration, Message::Arbitrate(Arbitration::ReleaseFundsToSeller)) => {
            state.mode = Mode::Done;
            let release_payment_to_seller =
                A::simple_transfer(&state.seller, state.required_deposit);
            let pay_arbiter = A::simple_transfer(&state.arbiter, state.arbiter_fee);
            Ok(try_send_both(release_payment_to_seller, pay_arbiter))
        }

        (Mode::AwaitingArbitration, Message::Arbitrate(Arbitration::ReawaitDelivery)) => {
            state.mode = Mode::AwaitingDelivery;
            Ok(A::accept())
        }

        (Mode::Done, _) => {
            bail!("This escrow contract has been completed - there is nothing more for it to do.")
        }

        _ => bail!("Invalid operation for current mode."),
    }
}

// Try to send a, and whether it succeeds or fails, try to send b
fn try_send_both<A: HasActions>(a: A, b: A) -> A {
    let best_effort_a = a.or_else(A::accept());
    let best_effort_b = b.or_else(A::accept());
    best_effort_a.and_then(best_effort_b)
}

// (De)serialization

impl Serialize for Message {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        match self {
            Message::SubmitDeposit => {
                out.write_u8(1)?;
            }
            Message::AcceptDelivery => {
                out.write_u8(2)?;
            }
            Message::Arbitrate(Arbitration::ReturnDepositToBuyer) => {
                out.write_u8(3)?;
            }
            Message::Arbitrate(Arbitration::ReleaseFundsToSeller) => {
                out.write_u8(4)?;
            }
            Message::Arbitrate(Arbitration::ReawaitDelivery) => {
                out.write_u8(5)?;
            }
            Message::Contest => {
                out.write_u8(6)?;
            }
        }
        Ok(())
    }

    fn deserial<R: Read>(source: &mut R) -> Result<Self, R::Err> {
        let idx = source.read_u8()?;
        match idx {
            1 => Ok(Message::SubmitDeposit),
            2 => Ok(Message::AcceptDelivery),
            3 => Ok(Message::Arbitrate(Arbitration::ReturnDepositToBuyer)),
            4 => Ok(Message::Arbitrate(Arbitration::ReleaseFundsToSeller)),
            5 => Ok(Message::Arbitrate(Arbitration::ReawaitDelivery)),
            6 => Ok(Message::Contest),
            _ => Err(Default::default()),
        }
    }
}

impl Serialize for Mode {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        match self {
            Mode::AwaitingDeposit => {
                out.write_u8(1)?;
            }
            Mode::AwaitingDelivery => {
                out.write_u8(2)?;
            }
            Mode::AwaitingArbitration => {
                out.write_u8(3)?;
            }
            Mode::Done => {
                out.write_u8(4)?;
            }
        }
        Ok(())
    }

    fn deserial<R: Read>(source: &mut R) -> Result<Self, R::Err> {
        let idx = source.read_u8()?;
        match idx {
            1 => Ok(Mode::AwaitingDeposit),
            2 => Ok(Mode::AwaitingDelivery),
            3 => Ok(Mode::AwaitingArbitration),
            4 => Ok(Mode::Done),
            _ => Err(Default::default()),
        }
    }
}

impl Serialize for InitParams {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        self.required_deposit.serial(out)?;
        self.arbiter_fee.serial(out)?;
        self.buyer.serial(out)?;
        self.seller.serial(out)?;
        self.arbiter.serial(out)?;
        Ok(())
    }

    fn deserial<R: Read>(source: &mut R) -> Result<Self, R::Err> {
        let required_deposit = source.get()?;
        let arbiter_fee = source.get()?;
        let buyer = source.get()?;
        let seller = source.get()?;
        let arbiter = source.get()?;
        let total_supply = source.get()?;
        Ok(InitParams {
            required_deposit,
            arbiter_fee,
            buyer,
            seller,
            arbiter,
            total_supply,
        })
    }
}

impl Serialize for State {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        self.mode.serial(out)?;
        self.required_deposit.serial(out)?;
        self.arbiter_fee.serial(out)?;
        self.buyer.serial(out)?;
        self.seller.serial(out)?;
        self.arbiter.serial(out)?;
        self.balances.serial(out)?;
        Ok(())
    }

    fn deserial<R: Read>(source: &mut R) -> Result<Self, R::Err> {
        let mode = source.get()?;
        let required_deposit = source.get()?;
        let arbiter_fee = source.get()?;
        let buyer = source.get()?;
        let seller = source.get()?;
        let arbiter = source.get()?;
        let balances = source.get()?;
        let allowed = source.get()?;
        let total_supply = source.get()?;
        Ok(State {
            mode,
            required_deposit,
            arbiter_fee,
            buyer,
            seller,
            arbiter,
            balances,
            allowed,
            total_supply,
        })
    }
}

// Tests

// We don't use assert_eq! etc. here since they end up requiring formatters
// which we don't necessarily want to import, etc., etc.
#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    #[no_mangle]
    fn test_init_rejects_non_zero_amounts() {
        let metadata = ChainMetadata {
            slot_number:      1172,
            block_height:     1150,
            finalized_height: 1148,
            slot_time:        43578934,
        };
        let init_origin = AccountAddress([4; ACCOUNT_ADDRESS_SIZE]);
        let init_context = InitContext {
            metadata,
            init_origin,
        };
        let amount = 200;
        let result = contract_init(init_context, amount);
        let expected = Err(Reject {});
        if !(result == expected) {
            panic!("init failed to reject a non-zero amount")
        }
    }

    #[test]
    #[no_mangle]
    fn test_init_rejects_same_buyer_and_seller() {
        todo!("implement me");
    }

    #[test]
    #[no_mangle]
    fn test_init_builds_corresponding_state_from_init_params() {
        todo!("implement me");
    }

    #[test]
    #[no_mangle]
    fn test_receive_happy_path() {
        todo!("implement me");
    }

    // TODO Lots more to test!
}
