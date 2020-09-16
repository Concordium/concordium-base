#![cfg_attr(not(feature = "std"), no_std)]
use concordium_sc_base::*;

/* A contract that acts like an account (can send, store and accept GTU),
 * but requires that no more than x GTU be withdrawn every y time-units
 * (or something approximating that).
 *
 * The idea being that perhaps it can act as something like an annuity,
 * or it can be a form of security in that it gives observers time to react
 * to odd movements of GTU before too much damage is inflicted (e.g. by
 * enacting Concordium’s ability to unmask actors on the chain).
*/


// Type Aliases

type TransferRequestId = u64;
type TimeMilliseconds = u64;


// Transfer Requests

#[derive(Clone)]
struct TransferRequest {
    request_id: TransferRequestId,
    amount: Amount,
    target_account: AccountAddress,
}

#[derive(Clone)]
struct Transfer {
    time_of_transfer: TimeMilliseconds,
    transfer_request: TransferRequest,
}


// State

struct InitParams {
    timed_withdraw_limit: Amount,
    time_limit: TimeMilliseconds,
}

pub struct State {
    init_params: InitParams,
    transfers: Vec<Transfer>, // TODO: Should BTreeSet be used instead to avoid duplicates?
}



#[init(name = "init")]
fn contract_init<I: HasInitContext<()>, L: HasLogger>(
    ctx: I,
    _amount: Amount,
    _logger: &mut L,
) -> InitResult<State> {
   
    let init_params: InitParams = ctx.parameter_cursor().get()?;
    let state = State {
        init_params,
        transfers: Vec::new(),
    };
   
    // TODO: Ensure reasonable init_params

    Ok(state)
}

#[receive(name = "deposit")]
fn contract_receive_deposit<R: HasReceiveContext<()>, L: HasLogger, A: HasActions>(
    _ctx: R,
    _amount: Amount,
    _logger: &mut L,
    _state: &mut State,
) -> ReceiveResult<A> {
    Ok(A::accept())
}


#[receive(name = "receive")]
fn contract_receive_transfer<R: HasReceiveContext<()>, L: HasLogger, A: HasActions>(
    ctx: R,
    _amount: Amount,
    _logger: &mut L,
    state: &mut State,
) -> ReceiveResult<A> {

    let sender_address = match ctx.sender() {
        Address::Contract(_) => bail!("Sender cannot be a contract"),
        Address::Account(account_address) => account_address,
    };
    ensure!(sender_address == ctx.owner());

    let current_time: TimeMilliseconds = ctx.metadata().slot_time();

    // Beginning of the time window in which to check transfer history
    let time_window_start: TimeMilliseconds = match current_time
        .checked_sub(state.init_params.time_limit) {
        None => 0,
        Some(res) => res,
    };

    let transfer_request: TransferRequest = ctx.parameter_cursor().get()?;
    let transfer = Transfer{time_of_transfer: current_time, transfer_request};

    // Remove requests before the time_window_start
    state.transfers.retain(|r|r.time_of_transfer >= time_window_start);

    // Calculate sum of transfers within time limit, TODO: Use single traversal of vec
    let amount_transferred_in_window: Amount = state.transfers
                                                    .iter()
                                                    .map(|r| r.transfer_request.amount)
                                                    .sum();

    ensure!(transfer.transfer_request.amount <= ctx.self_balance()
            && amount_transferred_in_window + transfer.transfer_request.amount
            <= state.init_params.timed_withdraw_limit);

    // Add request to vec because it is valid
    state.transfers.push(transfer.clone());

    Ok(A::simple_transfer(&transfer.transfer_request.target_account,
                          transfer.transfer_request.amount))
}



// (De)serialization

impl Serialize for TransferRequest {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        out.write_u64(self.request_id)?;
        self.amount.serial(out)?;
        self.target_account.serial(out)?;
        Ok(())
    }

    fn deserial<R: Read>(source: &mut R) -> Result<Self, R::Err> {
        let request_id = source.read_u64()?;
        let amount = Amount::deserial(source)?;
        let target_account = AccountAddress::deserial(source)?;
        Ok(TransferRequest {
            request_id,
            amount,
            target_account,
        })
    }
}

impl Serialize for Transfer {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        out.write_u64(self.time_of_transfer)?;
        self.transfer_request.serial(out)?;
        Ok(())
    }

    fn deserial<R: Read>(source: &mut R) -> Result<Self, R::Err> {
        let time_of_transfer = source.read_u64()?;
        let transfer_request = TransferRequest::deserial(source)?;
        Ok(Transfer{
            time_of_transfer,
            transfer_request,
        })
    }
}

impl Serialize for InitParams {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        out.write_u64(self.timed_withdraw_limit)?;
        out.write_u64(self.time_limit)?;
        Ok(())
    }

    fn deserial<R: Read>(source: &mut R) -> Result<Self, R::Err> {
        let timed_withdraw_limit = source.read_u64()?;
        let time_limit = source.read_u64()?;
        Ok(InitParams {
            timed_withdraw_limit,
            time_limit,
        })
    }
}



impl Serialize for State {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        self.init_params.serial(out)?;
        self.transfers.serial(out)?;
        Ok(())
    }

    fn deserial<R: Read>(source: &mut R) -> Result<Self, R::Err> {
        let init_params = InitParams::deserial(source)?;
        let transfers = Vec::deserial(source)?;

        Ok(State {
            init_params,
            transfers,
        })
    }
}


/* == Test Overview ==
 * Regular init DONE
 * Deposit from
 *  - owner DONE
 *  - others
 * Transfer
 *  - Insufficient funds, empty time_window
 *  - Sufficient funds, empty time_window
 *  - Sufficient funds, accepted for time_window after cleanup DONE
 *  - Sufficient funds, denied for time_window DONE
 *  - Insufficient funds for last two
 *  - Transfer initiated by Wrong account, i.e not owner
 *  - No underflow occurs when time_limit > current_time DONE
*/


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// Test that init succeeds and state is initialized with an empty vec.
    fn test_init() {
        // Setup our example state the contract is to be run in.
        // First the context.
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
        // The init function does not expect a parameter, so empty will do.
        let parameters = InitParams { timed_withdraw_limit: 100, time_limit: 1000 };
       
        let ctx = test_infrastructure::InitContextWrapper {
            init_ctx,
            parameter: &to_bytes(&parameters),
        };
        // set up the logger so we can intercept and analyze them at the end.
        let mut logger = test_infrastructure::LogRecorder::init();

        // call the init function
        let out = contract_init(ctx, 0, &mut logger);

        // and inspect the result.
        if let Ok(state) = out {
            assert!(state.transfers.is_empty(), "The transfer should be empty initially.");
        } else {
            assert!(false, "Contract initialization failed.");
        }
    }

    #[test]
    /// Test that the owner can deposit GTU into the contract
    fn test_receive_deposit() {
        // setup our example state the contract is to be run in.
        // first the context.
        let metadata = ChainMetadata {
            slot_number:      0,
            block_height:     0,
            finalized_height: 0,
            slot_time:        10,
        };

        let account_owner = AccountAddress([1u8; 32]);

        let receive_ctx = ReceiveContext {
            metadata,
            invoker: account_owner,
            self_address: ContractAddress {
                index:    0,
                subindex: 0,
            },
            self_balance: 0,
            sender: Address::Account(account_owner),
            owner: account_owner,
        };

        let ctx = test_infrastructure::ReceiveContextWrapper {
            receive_ctx,
            parameter: &[],
        };

        let transfers = Vec::new();

        let init_params = InitParams{ timed_withdraw_limit: 10, time_limit: 9 };

        let mut logger = test_infrastructure::LogRecorder::init();
        let mut state = State {
            init_params,
            transfers,
        };


        // Execution
        let res: ReceiveResult<test_infrastructure::ActionsTree> =
            contract_receive_deposit(ctx, 10, &mut logger, &mut state);

        // Test
        assert!(res.is_ok(), "Contract receive deposite failed, but it should not have.");
    }


    #[test]
    /// Test that a valid transfer request is accepted
    ///
    ///  - Removes outdated transfers from history
    ///  - Accepts the requested transfer
    ///  - Adds the new request to history
    fn test_receive_transfer_accepted() {
        // setup our example state the contract is to be run in.
        // first the context.
        let metadata = ChainMetadata {
            slot_number:      0,
            block_height:     0,
            finalized_height: 0,
            slot_time:        10,
        };

        let account1 = AccountAddress([1u8; 32]);
        let account2 = AccountAddress([2u8; 32]);
        let target_account = AccountAddress([2u8; 32]);

        let receive_ctx = ReceiveContext {
            metadata,
            invoker: account1,
            self_address: ContractAddress {
                index:    0,
                subindex: 0,
            },
            self_balance: 10,
            sender: Address::Account(account1),
            owner: account1,
        };

        let parameter = TransferRequest{
            request_id: 0,
            amount: 5,
            target_account: target_account
        };

        let ctx = test_infrastructure::ReceiveContextWrapper {
            receive_ctx,
            parameter: &to_bytes(&parameter),
        };


        let mut transfers = Vec::new();
        transfers.push(Transfer { time_of_transfer: 0,
                                  transfer_request: TransferRequest { request_id: 0,
                                                                      amount: 6,
                                                                      target_account: account1, },
        });
        transfers.push(Transfer { time_of_transfer: 1,
                                  transfer_request: TransferRequest { request_id: 1,
                                                                      amount: 2,
                                                                      target_account: account2, },
        });

        transfers.push(Transfer { time_of_transfer: 2,
                                  transfer_request: TransferRequest { request_id: 2,
                                                                      amount: 3,
                                                                      target_account: account2, },
        });

        let init_params = InitParams{ timed_withdraw_limit: 10, time_limit: 9 };

        let mut logger = test_infrastructure::LogRecorder::init();
        let mut state = State {
            init_params,
            transfers,
        };


        // Execution
        let res: ReceiveResult<test_infrastructure::ActionsTree> =
            contract_receive_transfer(ctx, 0, &mut logger, &mut state);

        // Test
        match res {
            Err(_) => assert!(false, "Contract receive transfer failed, but it should not have."),
            Ok(actions) => {
                assert_eq!(
                    actions,
                    test_infrastructure::ActionsTree::simple_transfer(&target_account, 5),
                    "The request did not transfer the correct amount."
                );
                assert_eq!(state.transfers.len(), 3, "The oldest transfer should have been removed \
                                                 and the new one added.");
            }
        }

    }


    #[test]
    /// Test that a request fails when the rate limit is exceeded\
    ///
    /// - Request is denied
    /// - Request is _not_ added to history
    fn test_receive_transfer_denied_due_to_limit() {
        // setup our example state the contract is to be run in.
        // first the context.
        let metadata = ChainMetadata {
            slot_number:      0,
            block_height:     0,
            finalized_height: 0,
            slot_time:        10,
        };

        let account1 = AccountAddress([1u8; 32]);
        let account2 = AccountAddress([2u8; 32]);
        let target_account = AccountAddress([2u8; 32]);

        let receive_ctx = ReceiveContext {
            metadata,
            invoker: account1,
            self_address: ContractAddress {
                index:    0,
                subindex: 0,
            },
            self_balance: 10,
            sender: Address::Account(account1),
            owner: account1,
        };

        let parameter = TransferRequest{
            request_id: 0,
            amount: 5,
            target_account: target_account
        };

        let ctx = test_infrastructure::ReceiveContextWrapper {
            receive_ctx,
            parameter: &to_bytes(&parameter),
        };


        let mut transfers = Vec::new();
        transfers.push(Transfer { time_of_transfer: 0,
                                  transfer_request: TransferRequest { request_id: 0,
                                                                      amount: 6,
                                                                      target_account: account1, },
        });
        transfers.push(Transfer { time_of_transfer: 1,
                                  transfer_request: TransferRequest { request_id: 1,
                                                                      amount: 2,
                                                                      target_account: account2, },
        });

        transfers.push(Transfer { time_of_transfer: 2,
                                  transfer_request: TransferRequest { request_id: 2,
                                                                      amount: 3,
                                                                      target_account: account2, },
        });

        let init_params = InitParams{ timed_withdraw_limit: 10, time_limit: 10 };

        let mut logger = test_infrastructure::LogRecorder::init();
        let mut state = State {
            init_params,
            transfers,
        };


        // Execution
        let res: ReceiveResult<test_infrastructure::ActionsTree> =
            contract_receive_transfer(ctx, 0, &mut logger, &mut state);

        // Test
        assert!(res.is_err(), "Contract receive transfer succeeded, but it should not have.");
        assert_eq!(state.transfers.len(), 3, "No transfers should have been removed, \
                                              and the new one should not be added.");
    }

    #[test]
    /// Test that underflows do not occur when the time_limit is larger than the current time
    ///
    /// - Transfer request is accepted
    /// - No underflow occurs
    fn test_receive_transfer_no_underflow() {
        // setup our example state the contract is to be run in.
        // first the context.
        let metadata = ChainMetadata {
            slot_number:      0,
            block_height:     0,
            finalized_height: 0,
            slot_time:        10,
        };

        let account1 = AccountAddress([1u8; 32]);
        let account2 = AccountAddress([2u8; 32]);
        let target_account = AccountAddress([2u8; 32]);

        let receive_ctx = ReceiveContext {
            metadata,
            invoker: account1,
            self_address: ContractAddress {
                index:    0,
                subindex: 0,
            },
            self_balance: 10,
            sender: Address::Account(account1),
            owner: account1,
        };

        let parameter = TransferRequest{
            request_id: 0,
            amount: 5,
            target_account: target_account
        };

        let ctx = test_infrastructure::ReceiveContextWrapper {
            receive_ctx,
            parameter: &to_bytes(&parameter),
        };


        let mut transfers = Vec::new();
        transfers.push(Transfer { time_of_transfer: 0,
                                  transfer_request: TransferRequest { request_id: 0,
                                                                      amount: 1,
                                                                      target_account: account1, },
        });
        transfers.push(Transfer { time_of_transfer: 1,
                                  transfer_request: TransferRequest { request_id: 1,
                                                                      amount: 1,
                                                                      target_account: account2, },
        });

        transfers.push(Transfer { time_of_transfer: 2,
                                  transfer_request: TransferRequest { request_id: 2,
                                                                      amount: 1,
                                                                      target_account: account2, },
        });

        let init_params = InitParams{ timed_withdraw_limit: 10, time_limit: 1000 };

        let mut logger = test_infrastructure::LogRecorder::init();
        let mut state = State {
            init_params,
            transfers,
        };


        // Execution
        let res: ReceiveResult<test_infrastructure::ActionsTree> =
            contract_receive_transfer(ctx, 0, &mut logger, &mut state);

        // Test
        assert!(res.is_ok(), "Contract receive transfer failed, but it should not have.");
    }
}
