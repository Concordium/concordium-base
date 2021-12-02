#![cfg_attr(not(feature = "std"), no_std)]
use concordium_std::*;

/* A contract that acts like an account (can send, store and accept CCD),
 * but requires that no more than x CCD be withdrawn every y time-units.
 *
 * The idea being that perhaps it can act as something like an annuity,
 * or it can be a form of security in that it gives observers time to react
 * to odd movements of CCD before too much damage is inflicted (e.g. by
 * enacting Concordium’s ability to unmask actors on the chain).
 *
 * Implementation:
 *  - The contract is initiated with a timed_withdraw_limit (corresponding to
 *    x in the above) and a time_limit (corresponding to y).
 *  - When a transfer request is received, it is checked whether the contract
 *    has sufficient funds to process it and whether the accepted recent
 *    transfers within the y last time-units, including the new request, is
 *    below the x withdraw limit. If both terms are met, the transfer is
 *    accepted and put into state.recent_transfers for future reference.
 *  - With every request the outdated requests, i.e. those older than
 *    current_time minus y, are pruned from state.recent_transfers.
 */

// Transfer Requests

#[derive(Clone, Serialize, SchemaType)]
struct TransferRequest {
    /// The amount of CCD to transfer from the contract to the target_account
    amount:         Amount,
    /// The account to transfer to
    target_account: AccountAddress,
}

#[derive(Clone, Serialize, SchemaType)]
struct Transfer {
    /// The time, fx slot_time, of when the request was initiated
    time_of_transfer: Timestamp,
    /// The associated request
    transfer_request: TransferRequest,
}

/// # State of the contract.
#[derive(Serialize, SchemaType)]
struct InitParams {
    /// The amount of CCD allowed to be withdrawn within the time_limit
    timed_withdraw_limit: Amount,
    /// The duration in which recently accepted recent_transfers are checked
    time_limit:           Duration,
}

#[contract_state(contract = "rate-limited")]
#[derive(Serialize, SchemaType)]
pub struct State {
    /// The initiating parameters
    init_params:      InitParams,
    /// The recently accepted transfers.
    /// Used to check whether a new transfer request should be accepted
    /// according to the time_limit and timed_withdraw_limit.
    recent_transfers: Vec<Transfer>,
}

#[init(contract = "rate-limited", parameter = "InitParams")]
fn contract_init(ctx: &impl HasInitContext<()>) -> InitResult<State> {
    let init_params: InitParams = ctx.parameter_cursor().get()?;

    // If timed_withdraw_limit is zero then no CCD can be transferred from the
    // account, thus violating the purpose of the contract.
    ensure!(init_params.timed_withdraw_limit.micro_ccd > 0); // The timed_withdraw_limit should be greater than 0.

    let state = State {
        init_params,
        recent_transfers: Vec::new(),
    };

    Ok(state)
}

#[receive(contract = "rate-limited", name = "receive_deposit", payable)]
/// Allows anyone to deposit CCD into the contract.
fn contract_receive_deposit<A: HasActions>(
    _ctx: &impl HasReceiveContext<()>,
    _amount: Amount,
    _state: &mut State,
) -> ReceiveResult<A> {
    Ok(A::accept())
}

#[receive(contract = "rate-limited", name = "receive", payable, parameter = "TransferRequest")]
/// Allows the owner of the contract to transfer CCD from the contract to an
/// arbitrary account
fn contract_receive_transfer<A: HasActions>(
    ctx: &impl HasReceiveContext<()>,
    _amount: Amount,
    state: &mut State,
) -> ReceiveResult<A> {
    ensure!(ctx.sender().matches_account(&ctx.owner())); // Only the owner can transfer.

    let current_time = ctx.metadata().slot_time();

    // Beginning of the time window in which to check transfer history
    let time_window_start = current_time
        .checked_sub(state.init_params.time_limit)
        .unwrap_or_else(|| Timestamp::from_timestamp_millis(0));

    let transfer_request: TransferRequest = ctx.parameter_cursor().get()?;
    let transfer = Transfer {
        time_of_transfer: current_time,
        transfer_request,
    };

    // Remove requests before the time_window_start
    state.recent_transfers.retain(|r| r.time_of_transfer >= time_window_start);

    // Calculate sum of recent_transfers within time limit
    let amount_transferred_in_window: Amount =
        state.recent_transfers.iter().map(|r| r.transfer_request.amount).sum();

    ensure!(
        transfer.transfer_request.amount <= ctx.self_balance()
            && amount_transferred_in_window + transfer.transfer_request.amount
                <= state.init_params.timed_withdraw_limit
    );

    // Add request to vec because it is valid
    state.recent_transfers.push(transfer.clone());

    Ok(A::simple_transfer(
        &transfer.transfer_request.target_account,
        transfer.transfer_request.amount,
    ))
}

#[concordium_cfg_test]
mod tests {
    use super::*;
    use concordium_std::test_infrastructure::*;

    #[concordium_test]
    /// Test that a valid transfer request is accepted
    ///
    ///  - Removes outdated recent_transfers
    ///  - Accepts the requested transfer
    ///  - Adds the new request to recent_transfers
    fn test_receive_transfer_accepted() {
        // Setup the context

        let account1 = AccountAddress([1u8; 32]);
        let account2 = AccountAddress([2u8; 32]);
        let target_account = AccountAddress([2u8; 32]);

        let parameter = TransferRequest {
            amount: Amount::from_micro_ccd(5),
            target_account,
        };
        let parameter_bytes = to_bytes(&parameter);

        let mut ctx = ReceiveContextTest::empty();
        ctx.set_parameter(&parameter_bytes);
        ctx.set_metadata_slot_time(Timestamp::from_timestamp_millis(10));
        ctx.set_sender(Address::Account(account1));
        ctx.set_owner(account1);
        ctx.set_self_balance(Amount::from_micro_ccd(10));

        // Setup state
        let recent_transfers = vec![
            Transfer {
                time_of_transfer: Timestamp::from_timestamp_millis(0),
                transfer_request: TransferRequest {
                    amount:         Amount::from_micro_ccd(6),
                    target_account: account1,
                },
            },
            Transfer {
                time_of_transfer: Timestamp::from_timestamp_millis(1),
                transfer_request: TransferRequest {
                    amount:         Amount::from_micro_ccd(2),
                    target_account: account2,
                },
            },
            Transfer {
                time_of_transfer: Timestamp::from_timestamp_millis(2),
                transfer_request: TransferRequest {
                    amount:         Amount::from_micro_ccd(3),
                    target_account: account1,
                },
            },
        ];

        let init_params = InitParams {
            timed_withdraw_limit: Amount::from_micro_ccd(10),
            time_limit:           Duration::from_millis(9),
        };

        let mut state = State {
            init_params,
            recent_transfers,
        };

        // Execution
        let res: ReceiveResult<ActionsTree> =
            contract_receive_transfer(&ctx, Amount::zero(), &mut state);

        // Test
        let actions = match res {
            Err(_) => fail!("Contract receive transfer failed, but it should not have."),
            Ok(actions) => actions,
        };
        claim_eq!(
            actions,
            ActionsTree::simple_transfer(&target_account, Amount::from_micro_ccd(5)),
            "The request did not transfer the correct amount."
        );
        claim_eq!(
            state.recent_transfers.len(),
            3,
            "The oldest transfer should have been removed and the new one added."
        );
        claim_eq!(
            state.recent_transfers[2].transfer_request.amount.micro_ccd,
            5,
            "The new transfer should have been added to recent_transfers."
        );
    }

    #[concordium_test]
    /// Test that a request fails when the rate limit is exceeded\
    ///
    /// - Request is denied
    /// - Recent_transfers is unaltered
    fn test_receive_transfer_denied_due_to_limit() {
        // Setup context
        let account1 = AccountAddress([1u8; 32]);
        let account2 = AccountAddress([2u8; 32]);
        let target_account = AccountAddress([2u8; 32]);

        let parameter = TransferRequest {
            amount: Amount::from_micro_ccd(5),
            target_account,
        };
        let parameter_bytes = to_bytes(&parameter);

        let mut ctx = ReceiveContextTest::empty();
        ctx.set_metadata_slot_time(Timestamp::from_timestamp_millis(10));
        ctx.set_sender(Address::Account(account1));
        ctx.set_owner(account1);
        ctx.set_self_balance(Amount::from_micro_ccd(10));
        ctx.set_parameter(&parameter_bytes);

        // Setup state
        let recent_transfers = vec![
            Transfer {
                time_of_transfer: Timestamp::from_timestamp_millis(0),
                transfer_request: TransferRequest {
                    amount:         Amount::from_micro_ccd(6),
                    target_account: account1,
                },
            },
            Transfer {
                time_of_transfer: Timestamp::from_timestamp_millis(1),
                transfer_request: TransferRequest {
                    amount:         Amount::from_micro_ccd(2),
                    target_account: account2,
                },
            },
            Transfer {
                time_of_transfer: Timestamp::from_timestamp_millis(2),
                transfer_request: TransferRequest {
                    amount:         Amount::from_micro_ccd(3),
                    target_account: account2,
                },
            },
        ];

        let init_params = InitParams {
            timed_withdraw_limit: Amount::from_micro_ccd(10),
            time_limit:           Duration::from_millis(10),
        };

        let mut state = State {
            init_params,
            recent_transfers,
        };

        // Execution
        let res: ReceiveResult<ActionsTree> =
            contract_receive_transfer(&ctx, Amount::zero(), &mut state);

        // Test
        claim!(res.is_err(), "Contract receive transfer succeeded, but it should not have.");
        claim_eq!(
            state.recent_transfers.len(),
            3,
            "No recent transfers should have been removed, and the new one should not be added."
        );

        let recent_transfers_amounts: Vec<u64> =
            state.recent_transfers.iter().map(|t| t.transfer_request.amount.micro_ccd).collect();
        claim_eq!(
            recent_transfers_amounts,
            vec![6, 2, 3],
            "The recent_transfers should not have been altered."
        )
    }

    #[concordium_test]
    /// Test that an underflow does not occur when the time_limit is larger than
    /// the current time
    ///
    /// - Transfer request is accepted
    /// - No underflow occurs
    fn test_receive_transfer_no_underflow() {
        // Setup context
        let account1 = AccountAddress([1u8; 32]);
        let account2 = AccountAddress([2u8; 32]);
        let target_account = AccountAddress([2u8; 32]);

        let parameter = TransferRequest {
            amount: Amount::from_micro_ccd(5),
            target_account,
        };
        let parameter_bytes = to_bytes(&parameter);

        let mut ctx = ReceiveContextTest::empty();
        ctx.set_parameter(&parameter_bytes);
        ctx.set_metadata_slot_time(Timestamp::from_timestamp_millis(10));
        ctx.set_self_balance(Amount::from_micro_ccd(10));
        ctx.set_sender(Address::Account(account1));
        ctx.set_owner(account1);

        // Setup state
        let recent_transfers = vec![
            Transfer {
                time_of_transfer: Timestamp::from_timestamp_millis(0),
                transfer_request: TransferRequest {
                    amount:         Amount::from_micro_ccd(1),
                    target_account: account1,
                },
            },
            Transfer {
                time_of_transfer: Timestamp::from_timestamp_millis(1),
                transfer_request: TransferRequest {
                    amount:         Amount::from_micro_ccd(1),
                    target_account: account2,
                },
            },
            Transfer {
                time_of_transfer: Timestamp::from_timestamp_millis(2),
                transfer_request: TransferRequest {
                    amount:         Amount::from_micro_ccd(1),
                    target_account: account2,
                },
            },
        ];

        let init_params = InitParams {
            timed_withdraw_limit: Amount::from_micro_ccd(10),
            time_limit:           Duration::from_millis(1000),
        };

        let mut state = State {
            init_params,
            recent_transfers,
        };

        // Execution
        let res: ReceiveResult<ActionsTree> =
            contract_receive_transfer(&ctx, Amount::zero(), &mut state);

        // Test
        claim!(res.is_ok(), "Contract receive transfer failed, but it should not have.");
    }
}
