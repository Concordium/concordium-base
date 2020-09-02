#![cfg_attr(not(feature = "std"), no_std)]
use concordium_sc_base::*;

/*
 * A contract that acts like an account (can send, store and accept GTU), but
 * requires n > 1 ordained accounts to agree to the sending of GTU before it is
 * accepted. This is useful for storing GTU where the security of just one account
 * isn’t considered high enough.
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
 * At the point when a transfer/withdrawal is requested, the account balance is
 * checked. Either there are not enough funds and the request is rejected, or
 * there are enough funds and the requested sum is set aside (and can be
 * re-added to the balance if the request times out).
 *
 * TODO Consider allowing the person who initially made the request to cancel it, iff it is still
 * outstanding
 */

// Types

#[derive(Clone, Copy, PartialEq, Eq)]
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

    // Just put the funds sent with this message into this contract
   Deposit
}

type TransferRequestId = u64;

// TODO Is seconds the correct unit?
type TransferRequestTimeToLiveSeconds = u64;
type TimeoutSlotTimeSeconds = u64;

#[derive(Clone)]
struct OutstandingTransferRequest {
    id:              TransferRequestId,
    transfer_amount: Amount,
    target_account:  AccountAddress,
    times_out_at:    TimeoutSlotTimeSeconds,
    supporters:      Vec<AccountAddress> // TODO use a Set instead
}

struct InitParams {
    // Who is authorised to withdraw funds from this lockup (must be non-empty)
    account_holders: Vec<AccountAddress>,

    // How many of the account holders need to agree before funds are released
    transfer_agreement_threshold: u32,

    // How long to wait before dropping a request due to lack of support
    // N.B. If this is set too long, in practice the chain might become busy
    //      enough that requests time out before they can be agreed to by all
    //      parties, so be wary of setting this too low. On the otherhand,
    //      if this is set too high, a bunch of pending requests can get into
    //      a murky state where some account holders may consider the request obsolete,
    //      only for another account holder to "resurrect" it, so having _some_
    //      time out gives some security against old requests being surprisingly
    //      accepted.
    transfer_request_ttl: TransferRequestTimeToLiveSeconds
}

pub struct State {
    // The initial configuration of the contract
    init_params: InitParams,

    // Current balance that has not already been reserved for an outstanding transfer request
    available_balance: Amount,

    // Requests which have not been dropped due to timing out or due to being agreed to yet
    // The request ID, the associated amount, when it times out, who is making the transfer and
    // which account holders support this transfer
    outstanding_transfer_requests: Vec<OutstandingTransferRequest>,
    // TODO Use a Map from the id instead
}

// Contract implementation

#[init(name = "init")]
#[inline(always)]
fn contract_init<I: HasInitContext<()>, L: HasLogger>(
    ctx: I,
    _amount: Amount,
    _logger: &mut L,
) -> InitResult<State> {
    let mut init_params: InitParams = ctx.parameter_cursor().get()?;
    init_params.account_holders.dedup();
    ensure!(
        init_params.account_holders.len() >= 2,
        "Not enough account holders: At least two are needed for this contract to be valid."
    );
    ensure!(
        init_params.transfer_agreement_threshold <= init_params.account_holders.len() as u32,
        ("The threshold for agreeing account holders to allow a transfer must be " +
         "less than or equal to the number of unique account holders, else a transfer can never be made!")
    );
    ensure!(
        init_params.transfer_agreement_threshold >= 2,
        "The number of account holders required to accept a transfer must be two or more else you would be better off with a normal account!"
    );

    let state = State {
        init_params:                   init_params,
        available_balance:             0,
        outstanding_transfer_requests: vec![],
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

    let sender = ctx.sender();
    ensure!(
        state.init_params.account_holders.iter().any(|account_holder| sender.matches_account(account_holder)),
        "Only account holders can interact with this contract."
    );
    let sender_address = match sender {
        Address::Contract(_) => bail!("Sender cannot be a contract"),
        Address::Account(account_address) => account_address
    };
    let now = ctx.metadata().slot_time();

    // Drop requests which have gone too long without getting the support they need
    state
      .outstanding_transfer_requests
      .retain(|outstanding| outstanding.times_out_at > now);

    let msg: Message = ctx.parameter_cursor().get()?;
    match msg {
        Message::RequestTransfer(req_id, transfer_amount, target_account) => {
            ensure!(
                state.available_balance >= transfer_amount,
                "Not enough available funds to for this transfer."
            );
            ensure!(
                !state.outstanding_transfer_requests.iter().any(|existing| existing.id == req_id),
                "A request with this ID already exists."
            );
            state.available_balance -= transfer_amount;
            let new_request = OutstandingTransferRequest {
                id:              req_id,
                transfer_amount: transfer_amount,
                target_account:  target_account,
                times_out_at:    now + state.init_params.transfer_request_ttl,
                supporters:      vec![*sender_address]
            };
            state.outstanding_transfer_requests.push(new_request);
            Ok(A::accept())
        }

        Message::SupportTransfer(transfer_request_id, transfer_amount, target_account) => {
            // Need to find an existing, matching transfer
            let matching_request_result =
                state
                    .outstanding_transfer_requests
                    .iter_mut()
                    .find(|existing|
                            existing.id == transfer_request_id &&
                            existing.transfer_amount == transfer_amount &&
                            existing.target_account == target_account);
            let matching_request = match matching_request_result {
                None => bail!("No such transfer to support."),
                Some(matching) => matching
            };
                
            // Can't have already supported this transfer
            ensure!(
                !matching_request.supporters.contains(sender_address),
                "You have already supported this transfer."
            );
            matching_request.supporters.push(*sender_address);
            
            if matching_request.supporters.len() as u32 >= state.init_params.transfer_agreement_threshold {
                let matching_request = matching_request.clone();
                // Remove the transfer from the list of outstanding transfers and send it
                state
                    .outstanding_transfer_requests
                    .retain(|outstanding| outstanding.id != transfer_request_id);
                Ok(A::simple_transfer(&matching_request.target_account, matching_request.transfer_amount))
            } else {
                // Keep the updated support and accept
                Ok(A::accept())
            }
        }

        Message::Deposit => {
            state.available_balance += amount;
            Ok(A::accept())
        }
    }
}

// (De)serialization

impl Serialize for Message {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        match self {
            Message::RequestTransfer(transfer_request_id, amount, account_address) => {
              out.write_u8(0)?;
                out.write_u64(*transfer_request_id)?;
                out.write_u64(*amount)?;
                account_address.serial(out)?;
            }
            Message::SupportTransfer(transfer_request_id, amount, account_address) => {
                out.write_u8(1)?;
                out.write_u64(*transfer_request_id)?;
                out.write_u64(*amount)?;
                account_address.serial(out)?;
            }
            Message::Deposit => {
                out.write_u8(2)?;
            }

        }

        Ok(())
    }

    fn deserial<R: Read>(source: &mut R) -> Result<Self, R::Err> {
        // TODO
        match source.read_u8()? {
            0 => {
                let transfer_request_id = source.read_u64()?;
                let amount = source.read_u64()?;
                let account_address = AccountAddress::deserial(source)?;
                Ok(Message::RequestTransfer(transfer_request_id, amount, account_address))
            }

            1 => {
                let transfer_request_id = source.read_u64()?;
                let amount = source.read_u64()?;
                let account_address = AccountAddress::deserial(source)?;
                Ok(Message::SupportTransfer(transfer_request_id, amount, account_address))
            }

            2 => {
                Ok(Message::Deposit)
            }

            _ => Err(R::Err::default()),
        }
    }
}

impl Serialize for InitParams {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        self.account_holders.serial(out)?;
        out.write_u32(self.transfer_agreement_threshold)?;
        out.write_u64(self.transfer_request_ttl)?;
        Ok(())
    }

    fn deserial<R: Read>(source: &mut R) -> Result<Self, R::Err> {
        let account_holders = Vec::deserial(source)?;
        let transfer_agreement_threshold = source.read_u32()?;
        let transfer_request_ttl = source.read_u64()?;
        Ok(InitParams {
            account_holders,
            transfer_agreement_threshold,
            transfer_request_ttl,
        })
    }
}

impl Serialize for OutstandingTransferRequest {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        self.id.serial(out)?;
        self.transfer_amount.serial(out)?;
        self.target_account.serial(out)?;
        self.times_out_at.serial(out)?;
        self.supporters.serial(out)?;
        Ok(())
    }

    fn deserial<R: Read>(source: &mut R) -> Result<Self, R::Err> {
        let id = TransferRequestId::deserial(source)?;
        let transfer_amount = Amount::deserial(source)?;
        let target_account = AccountAddress::deserial(source)?;
        let times_out_at = TimeoutSlotTimeSeconds::deserial(source)?;
        let supporters = Vec::deserial(source)?;
        Ok(OutstandingTransferRequest {
            id,
            transfer_amount,
            target_account,
            times_out_at,
            supporters
        })
    }
}

impl Serialize for State {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        self.init_params.serial(out)?;
        self.available_balance.serial(out)?;
        self.outstanding_transfer_requests.serial(out)?;
        Ok(())
    }

    fn deserial<R: Read>(source: &mut R) -> Result<Self, R::Err> {
        // TODO
        let init_params = InitParams::deserial(source)?;
        let available_balance = Amount::deserial(source)?;
        let outstanding_transfer_requests = Vec::deserial(source)?;

        Ok(State {
            init_params,
            available_balance,
            outstanding_transfer_requests
        })
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

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
        // The init function does not expect a parameter, so empty will do.
        let parameter = InitParams {
            account_holders: vec![account1, account2],
            transfer_agreement_threshold: 2,
            transfer_request_ttl: 10
        };
        
        let ctx = test_infrastructure::InitContextWrapper {
            init_ctx,
            parameter: &to_bytes(&parameter),
        };
        // set up the logger so we can intercept and analyze them at the end.
        let mut logger = test_infrastructure::LogRecorder::init();

        // call the init function
        let out = contract_init(ctx, 13, &mut logger);

        // and inspect the result.
        if let Ok(state) = out {
            assert!(state.init_params.account_holders.contains(&account1), "Should contain the first account holder");
            assert!(state.init_params.account_holders.contains(&account2), "Should contain the second account holder");
            assert_eq!(state.init_params.account_holders.len(), 2, "Should not contain more account holders");
            assert_eq!(state.outstanding_transfer_requests.len(), 0, "No transfer request at initialisation");
        } else {
            assert!(false, "Contract initialization failed.");
        }
        // and make sure the correct logs were produced.
        // assert_eq!(logger.logs.len(), 1, "Incorrect number of logs produced.");
        // assert_eq!(&logger.logs[0], &[0, 13], "Incorrect log produced.");
    }

    #[test]
    /// Creates the request
    /// 
    /// - Mutates the state with the request
    /// - Sets the right amount aside for the request
    /// - Only have the sender support the request
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
            owner: account1
        };
        let request_id = 0;
        // Create Request with id 0, to transfer 50 to target_account
        let parameter = Message::RequestTransfer(request_id, 50, target_account);
        let ctx = test_infrastructure::ReceiveContextWrapper {
            receive_ctx,
            parameter: &to_bytes(&parameter),
        };
        let init_params = InitParams {
            account_holders: vec![account1, account2],
            transfer_agreement_threshold: 2,
            transfer_request_ttl: 10
        };
        // set up the logger so we can intercept and analyze them at the end.
        let mut logger = test_infrastructure::LogRecorder::init();
        let mut state = State {
            available_balance: 100,
            init_params,
            outstanding_transfer_requests: Vec::new(),
        };

        // Execution
        let res: ReceiveResult<test_infrastructure::ActionsTree> =
            contract_receive(ctx, 17, &mut logger, &mut state);
        
        // Test
        match res {
            Err(_) => assert!(false, "Contract receive failed, but it should not have."),
            Ok(actions) => {
                assert_eq!(
                    actions,
                    test_infrastructure::ActionsTree::Accept,
                    "Contract receive produced incorrect actions."
                );
                assert_eq!(state.outstanding_transfer_requests.len(), 1, "Contract receive did not create transfer request");
                assert_eq!(state.available_balance, 50, "Contract receive did not lock requested amount");
                let request = state.outstanding_transfer_requests.get(0).unwrap();
                assert_eq!(request.id, request_id, "Contract receive created transfer request with wrong id");
                assert_eq!(request.supporters.len(), 1, "Only one is supporting the request from start");
                assert!(account1 == *request.supporters.get(0).unwrap(), "The request sender supports the request");
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
            slot_time:        0,
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
            self_balance: 0,
            sender: Address::Account(account2),
            owner: account1
        };
        let request_id = 0;
        let parameter = Message::SupportTransfer(request_id, 50, target_account);
        let ctx = test_infrastructure::ReceiveContextWrapper {
            receive_ctx,
            parameter: &to_bytes(&parameter),
        };
        let init_params = InitParams {
            account_holders: vec![account1, account2, account3],
            transfer_agreement_threshold: 3,
            transfer_request_ttl: 10
        };
        let request = OutstandingTransferRequest {
            id: request_id,
            supporters: vec![account1],
            target_account,
            times_out_at: 10,
            transfer_amount: 50
        };
        // set up the logger so we can intercept and analyze them at the end.
        let mut logger = test_infrastructure::LogRecorder::init();
        
        let mut state = State {
            available_balance: 50,
            init_params,
            outstanding_transfer_requests: vec![request],
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
                    test_infrastructure::ActionsTree::Accept,
                    "Contract receive support produced incorrect actions."
                );
                assert_eq!(state.outstanding_transfer_requests.len(), 1, "Contract receive support should not mutate the outstanding requests");
                assert_eq!(state.available_balance, 50, "Contract receive did not lock requested amount");
                let request = state.outstanding_transfer_requests.get(0).unwrap();
                assert_eq!(request.id, request_id, "Contract receive created transfer request with wrong id");
                assert_eq!(request.supporters.len(), 2, "Two should support the transfer request");
                assert!(request.supporters.contains(&account2), "The support sender supports the request");
            }
        }
    }


    #[test]
    /// Support a request triggering the transfer
    /// 
    /// - Results in the transfer
    /// - Removes the request from state
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
            owner: account2
        };
        let request_id = 0;
        let parameter = Message::SupportTransfer(request_id, 50, target_account);
        let ctx = test_infrastructure::ReceiveContextWrapper {
            receive_ctx,
            parameter: &to_bytes(&parameter),
        };
        let init_params = InitParams {
            account_holders: vec![account1, account2, account3],
            transfer_agreement_threshold: 2,
            transfer_request_ttl: 10
        };
        let request = OutstandingTransferRequest {
            id: request_id,
            supporters: vec![account1],
            target_account,
            times_out_at: 10,
            transfer_amount: 50
        };
        let mut logger = test_infrastructure::LogRecorder::init();
        
        let mut state = State {
            available_balance: 50,
            init_params,
            outstanding_transfer_requests: vec![request],
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
                    test_infrastructure::ActionsTree::simple_transfer(&target_account, 50),
                    "Supporting the transfer did not result in the right transfer"
                );
                assert_eq!(state.outstanding_transfer_requests.len(), 0, "The request should be removed");
                assert_eq!(state.available_balance, 50, "The available amount should be unchanged");
            }
        }
    }
}
