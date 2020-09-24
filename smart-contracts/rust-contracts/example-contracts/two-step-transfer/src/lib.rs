#![cfg_attr(not(feature = "std"), no_std)]
use concordium_sc_base::{collections::*, *};

/*
 * A contract that acts like an account (can send, store and accept GTU), but
 * requires n > 1 ordained accounts to agree to the sending of GTU before it
 * is accepted. This is useful for storing GTU where the security of just one
 * account isn’t considered high enough.
 *
 * Transfer requests time out if not agreed to within the contract's
 * specified time-to-live for transfer requests
 *
 * Transfer requests are given IDs to disambiguate otherwise identical
 * requests, since they might have different motivations behind the scenes,
 * making them not-quite fungible (e.g. for accounting purposes it might be
 * necessary for account holders to track a particular named transfer).
 *
 * Depositing funds:
 *   Allowed at any time from anyone.
 *
 * Transfering funds:
 *   Only requestable by accounts named at initialization, and only with the
 *   agreement of at least n of those accounts, but can send to any account.
 *
 * At the point when a transfer/withdrawal is requested, the account balance
 * is checked. Either there are not enough funds and the request is rejected,
 * or there are enough funds and the requested sum is set aside (and can be
 * re-added to the balance if the request times out).
 *
 * TODO Consider allowing the person who initially made the request to cancel
 * it, iff it is still outstanding
 */

// Types
#[derive(Serialize)]
enum Message {
    // Indicates that the user sending the message would like to make a request
    // to send funds to the given address with the given ID and amount.
    // This is a no-op if the given ID already exists and has not timed out.
    RequestTransfer(TransferRequestId, Amount, AccountAddress),

    // Indicates that the user sending the message votes in favour of the
    // transfer with the given ID and amount to the given account address.
    // This is a no-op if the given ID does not exist (potentially due to timing
    // out), or exists with a different amount or address.
    SupportTransfer(TransferRequestId, Amount, AccountAddress),
}

type TransferRequestId = u64;

// TODO Is seconds the correct unit?
type TransferRequestTimeToLiveMilliseconds = u64;
type TimeoutSlotTimeMilliseconds = u64;

#[derive(Clone, Serialize)]
struct TransferRequest {
    transfer_amount: Amount,
    target_account:  AccountAddress,
    times_out_at:    TimeoutSlotTimeMilliseconds,
    supporters:      BTreeSet<AccountAddress>,
}

#[derive(Serialize)]
struct InitParams {
    // Who is authorised to withdraw funds from this lockup (must be non-empty)
    #[set_size_length = 1]
    #[skip_order_check]
    account_holders: BTreeSet<AccountAddress>,

    // How many of the account holders need to agree before funds are released
    transfer_agreement_threshold: u32,

    // How long to wait before dropping a request due to lack of support
    // N.B. If this is set too long, in practice the chain might !ome busy
    //      enough that requests time out before they can be agreed to by all
    //      parties, so be wary of setting this too low. On the otherhand,
    //      if this is set too high, a bunch of pending requests can get into
    //      a murky state where some account holders may consider the request obsolete,
    //      only for another account holder to "resurrect" it, so having _some_
    //      time out gives some security against old requests being surprisingly
    //      accepted.
    transfer_request_ttl: TransferRequestTimeToLiveMilliseconds,
}

#[derive(Serialize)]
pub struct State {
    // The initial configuration of the contract
    init_params: InitParams,

    // Requests which have not been dropped due to timing out or due to being agreed to yet
    // The request ID, the associated amount, when it times out, who is making the transfer and
    // which account holders support this transfer
    #[map_size_length = 2]
    #[skip_order_check]
    requests: BTreeMap<TransferRequestId, TransferRequest>,
}

// Contract implementation

#[init(name = "init")]
#[inline(always)]
fn contract_init<I: HasInitContext<()>, L: HasLogger>(
    ctx: I,
    _amount: Amount,
    _logger: &mut L,
) -> InitResult<State> {
    let init_params: InitParams = ctx.parameter_cursor().get()?;
    ensure!(
        init_params.account_holders.len() >= 2,
        "Not enough account holders: At least two are needed for this contract to be valid."
    );
    ensure!(
        init_params.transfer_agreement_threshold <= init_params.account_holders.len() as u32,
        ("The threshold for agreeing account holders to allow a transfer must be "
            + "less than or equal to the number of unique account holders, else a transfer can \
               never be made!")
    );
    ensure!(
        init_params.transfer_agreement_threshold >= 2,
        "The number of account holders required to accept a transfer must be two or more else you \
         would be better off with a normal account!"
    );

    let state = State {
        init_params,
        requests: BTreeMap::new(),
    };

    Ok(state)
}

#[receive(name = "deposit")]
#[inline(always)]
fn contract_receive_deposit<R: HasReceiveContext<()>, L: HasLogger, A: HasActions>(
    _ctx: R,
    _amount: Amount,
    _logger: &mut L,
    _state: &mut State,
) -> ReceiveResult<A> {
    Ok(A::accept())
}

#[receive(name = "receive")]
#[inline(always)]
fn contract_receive_message<R: HasReceiveContext<()>, L: HasLogger, A: HasActions>(
    ctx: R,
    amount: Amount,
    _logger: &mut L,
    state: &mut State,
) -> ReceiveResult<A> {
    let sender = ctx.sender();
    ensure!(
        state
            .init_params
            .account_holders
            .iter()
            .any(|account_holder| sender.matches_account(account_holder)),
        "Only account holders can interact with this contract."
    );
    let sender_address = match sender {
        Address::Contract(_) => bail!("Sender cannot be a contract"),
        Address::Account(account_address) => account_address,
    };
    let now = ctx.metadata().slot_time();

    let msg: Message = ctx.parameter_cursor().get()?;
    match msg {
        Message::RequestTransfer(req_id, transfer_amount, target_account) => {
            // Remove outdated requests and calculate the reserved balance
            let mut reserved_balance = 0;
            let mut active_requests: BTreeMap<TransferRequestId, TransferRequest> = BTreeMap::new();
            for (key, req) in state.requests.iter() {
                if req.times_out_at > now {
                    active_requests.insert(*key, req.clone());
                    reserved_balance += req.transfer_amount;
                }
            }
            state.requests = active_requests;

            // Check if a request already exists
            ensure!(
                !state.requests.contains_key(&req_id),
                "A request with this ID already exists."
            );

            // Ensure enough funds for the requested transfer
            let balance = amount + ctx.self_balance();
            ensure!(
                balance - reserved_balance >= transfer_amount,
                "Not enough available funds for the requested transfer."
            );

            // Create the request with the sender as the only supporter
            let mut supporters = BTreeSet::new();
            supporters.insert(sender_address);
            let new_request = TransferRequest {
                transfer_amount,
                target_account,
                times_out_at: now + state.init_params.transfer_request_ttl,
                supporters,
            };
            state.requests.insert(req_id, new_request);
            Ok(A::accept())
        }

        Message::SupportTransfer(transfer_request_id, transfer_amount, target_account) => {
            // Find the request
            let matching_request_result = state.requests.get_mut(&transfer_request_id);

            let matching_request = match matching_request_result {
                None => bail!("No such transfer to support."),
                Some(matching) => matching,
            };

            // Validate the details of the transfer
            ensure!(matching_request.times_out_at > now, "The request have timed out.");
            ensure!(
                matching_request.transfer_amount == transfer_amount,
                "Transfer amount is different from the amount of the request."
            );
            ensure!(
                matching_request.target_account == target_account,
                "Target account is different from the target account of the request."
            );

            // Can't have already supported this transfer
            ensure!(
                !matching_request.supporters.contains(&sender_address),
                "You have already supported this transfer."
            );

            // Support the request
            matching_request.supporters.insert(sender_address);

            // Check if the have enough supporters to trigger
            if matching_request.supporters.len() as u32
                >= state.init_params.transfer_agreement_threshold
            {
                // Remove the transfer from the list of outstanding transfers and send it
                state.requests.remove(&transfer_request_id);
                Ok(A::simple_transfer(&target_account, transfer_amount))
            } else {
                // Keep the updated support and accept
                Ok(A::accept())
            }
        }
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    fn sum_reserved_balance(state: &State) -> Amount {
        state.requests.iter().map(|(_, req)| req.transfer_amount).sum()
    }

    #[test]
    /// Initialise contract with account holders
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
        let account1 = AccountAddress([1u8; 32]);
        let account2 = AccountAddress([2u8; 32]);
        let init_ctx = InitContext {
            metadata,
            init_origin,
        };
        let mut account_holders = BTreeSet::new();
        account_holders.insert(account1);
        account_holders.insert(account2);
        let parameter = InitParams {
            account_holders,
            transfer_agreement_threshold: 2,
            transfer_request_ttl: 10,
        };

        let ctx = test_infrastructure::InitContextWrapper {
            init_ctx,
            parameter: &to_bytes(&parameter),
        };
        // set up the logger so we can intercept and analyze them at the end.
        let mut logger = test_infrastructure::LogRecorder::init();

        // call the init function
        let out = contract_init(ctx, 0, &mut logger);

        // and inspect the result.
        if let Ok(state) = out {
            claim!(
                state.init_params.account_holders.contains(&account1),
                "Should contain the first account holder"
            );
            claim!(
                state.init_params.account_holders.contains(&account2),
                "Should contain the second account holder"
            );
            claim_eq!(
                state.init_params.account_holders.len(),
                2,
                "Should not contain more account holders"
            );
            claim_eq!(state.requests.len(), 0, "No transfer request at initialisation");
        } else {
            claim!(false, "Contract initialization failed.");
        }
        // and make sure the correct logs were produced.
    }

    #[test]
    /// Creates the request
    ///
    /// - Mutates the state with the request
    /// - Sets the right amount aside for the request
    /// - Only have the sender support the request at this point
    fn test_receive_request() {
        // Setup
        let metadata = ChainMetadata {
            slot_number:      0,
            block_height:     0,
            finalized_height: 0,
            slot_time:        0,
        };
        let account1 = AccountAddress([1u8; 32]);
        let account2 = AccountAddress([2u8; 32]);
        let target_account = AccountAddress([3u8; 32]);
        let receive_ctx = ReceiveContext {
            metadata,
            invoker: account1,
            self_address: ContractAddress {
                index:    0,
                subindex: 0,
            },
            self_balance: 0,
            sender: Address::Account(account1),
            owner: account1,
        };
        let request_id = 0;
        // Create Request with id 0, to transfer 50 to target_account
        let parameter = Message::RequestTransfer(request_id, 50, target_account);
        let ctx = test_infrastructure::ReceiveContextWrapper {
            receive_ctx,
            parameter: &to_bytes(&parameter),
        };

        let mut account_holders = BTreeSet::new();
        account_holders.insert(account1);
        account_holders.insert(account2);
        let init_params = InitParams {
            account_holders,
            transfer_agreement_threshold: 2,
            transfer_request_ttl: 10,
        };
        // set up the logger so we can intercept and analyze them at the end.
        let mut logger = test_infrastructure::LogRecorder::init();
        let mut state = State {
            init_params,
            requests: BTreeMap::new(),
        };

        // Execution
        let res: ReceiveResult<test_infrastructure::ActionsTree> =
            contract_receive_message(ctx, 100, &mut logger, &mut state);

        // Test
        match res {
            Err(_) => claim!(false, "Contract receive failed, but it should not have."),
            Ok(actions) => {
                claim_eq!(
                    actions,
                    test_infrastructure::ActionsTree::Accept,
                    "Contract receive produced incorrect actions."
                );
                claim_eq!(
                    state.requests.len(),
                    1,
                    "Contract receive did not create transfer request"
                );
                claim_eq!(
                    sum_reserved_balance(&state),
                    50,
                    "Contract receive did not reserve requested amount"
                );
                let request = state.requests.get(&request_id).unwrap();
                claim_eq!(
                    request.supporters.len(),
                    1,
                    "Only one is supporting the request from start"
                );
                claim!(
                    request.supporters.contains(&account1),
                    "The request sender supports the request"
                );
            }
        }
    }

    #[test]
    /// Support a request without entering the threshold
    ///
    /// - Mutates the request in the state by adding the supporter
    fn test_receive_support_no_transfer() {
        // Setup
        let metadata = ChainMetadata {
            slot_number:      0,
            block_height:     0,
            finalized_height: 0,
            slot_time:        100,
        };
        let account1 = AccountAddress([1u8; 32]);
        let account2 = AccountAddress([2u8; 32]);
        let account3 = AccountAddress([3u8; 32]);
        let target_account = AccountAddress([3u8; 32]);
        let receive_ctx = ReceiveContext {
            metadata,
            invoker: account1,
            self_address: ContractAddress {
                index:    0,
                subindex: 0,
            },
            self_balance: 25,
            sender: Address::Account(account2),
            owner: account1,
        };
        let request_id = 0;
        let parameter = Message::SupportTransfer(request_id, 50, target_account);
        let ctx = test_infrastructure::ReceiveContextWrapper {
            receive_ctx,
            parameter: &to_bytes(&parameter),
        };
        let mut account_holders = BTreeSet::new();
        account_holders.insert(account1);
        account_holders.insert(account2);
        account_holders.insert(account3);
        let init_params = InitParams {
            account_holders,
            transfer_agreement_threshold: 3,
            transfer_request_ttl: 10,
        };
        let mut supporters = BTreeSet::new();
        supporters.insert(account1);
        let request = TransferRequest {
            supporters,
            target_account,
            times_out_at: 200,
            transfer_amount: 50,
        };
        let mut requests = BTreeMap::new();
        requests.insert(request_id, request);
        let mut logger = test_infrastructure::LogRecorder::init();

        let mut state = State {
            init_params,
            requests,
        };

        // Execution
        let res: ReceiveResult<test_infrastructure::ActionsTree> =
            contract_receive_message(ctx, 75, &mut logger, &mut state);

        // Test
        match res {
            Err(_) => claim!(false, "Contract receive support failed, but it should not have.:"),
            Ok(actions) => {
                claim_eq!(
                    actions,
                    test_infrastructure::ActionsTree::Accept,
                    "Contract receive support produced incorrect actions."
                );
            }
        }
        claim_eq!(
            state.requests.len(),
            1,
            "Contract receive support should not mutate the outstanding requests"
        );
        claim_eq!(
            sum_reserved_balance(&state),
            50,
            "Contract receive did not reserve the requested amount"
        );
        let request = state.requests.get(&request_id).unwrap();
        claim_eq!(request.supporters.len(), 2, "Two should support the transfer request");
        claim!(request.supporters.contains(&account2), "The support sender supports the request");
    }

    #[test]
    /// Support a request triggering the transfer
    ///
    /// - Results in the transfer
    /// - Removes the request from state
    /// - Updates the reserved_balance
    fn test_receive_support_transfer() {
        // Setup
        let metadata = ChainMetadata {
            slot_number:      0,
            block_height:     0,
            finalized_height: 0,
            slot_time:        0,
        };
        let account1 = AccountAddress([1u8; 32]);
        let account2 = AccountAddress([2u8; 32]);
        let account3 = AccountAddress([3u8; 32]);
        let target_account = AccountAddress([3u8; 32]);
        let receive_ctx = ReceiveContext {
            metadata,
            invoker: account2,
            self_address: ContractAddress {
                index:    0,
                subindex: 0,
            },
            self_balance: 0,
            sender: Address::Account(account2),
            owner: account2,
        };
        let request_id = 0;
        let parameter = Message::SupportTransfer(request_id, 50, target_account);
        let ctx = test_infrastructure::ReceiveContextWrapper {
            receive_ctx,
            parameter: &to_bytes(&parameter),
        };
        let mut account_holders = BTreeSet::new();
        account_holders.insert(account1);
        account_holders.insert(account2);
        account_holders.insert(account3);
        let init_params = InitParams {
            account_holders,
            transfer_agreement_threshold: 2,
            transfer_request_ttl: 10,
        };
        let mut supporters = BTreeSet::new();
        supporters.insert(account1);
        let request = TransferRequest {
            supporters,
            target_account,
            times_out_at: 10,
            transfer_amount: 50,
        };

        let mut logger = test_infrastructure::LogRecorder::init();
        let mut requests = BTreeMap::new();
        requests.insert(request_id, request);
        let mut state = State {
            init_params,
            requests,
        };

        // Execution
        let res: ReceiveResult<test_infrastructure::ActionsTree> =
            contract_receive_message(ctx, 100, &mut logger, &mut state);

        // Test
        match res {
            Err(_) => claim!(false, "Contract receive support failed, but it should not have."),
            Ok(actions) => {
                claim_eq!(
                    actions,
                    test_infrastructure::ActionsTree::simple_transfer(&target_account, 50),
                    "Supporting the transfer did not result in the right transfer"
                );
            }
        }
        claim_eq!(state.requests.len(), 0, "The request should be removed");
        claim_eq!(
            sum_reserved_balance(&state),
            0,
            "The transfer should be subtracted from the reserved balance"
        );
    }
}
