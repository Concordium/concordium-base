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
    RequestTransferFunds(TransferRequestId, Amount, AccountAddress),

    // Indicates that the user sending the message votes in favour of the
    // transfer with the given ID and amount to the given account address.
    // This is a no-op if the given ID does not exist (potentially due to timing
    // out), or exists with a different amount or address.
    SupportTransfer(TransferRequestId, Amount, AccountAddress),

    // Just put the funds sent with this message into this contract
    Deposit,
}

type TransferRequestId = u64;
type Reason = &str;

// TODO Is seconds the correct unit?
type TransferRequestTimeToLiveSeconds = u64;
type TimeoutSlotTimeSeconds = u64;

pub struct OutstandingTransferRequest {
    id:              TransferRequestId,
    transfer_amount: Amount,
    target_account:  AccountAddress
    times_out_at:    TimeoutSlotTimeSeconds,
    supporters:      Vec<AccountAddress>
}

pub struct InitParams {
    // Who is authorised to withdraw funds from this lockup (must be non-empty)
    account_holders: Vec<AccountAddress>,

    // How many of the account holders need to agree before funds are released
    transfer_agreement_threshold: u32

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
}

// Contract implementation

#[init(name = "init")]
#[inline(always)]
fn contract_init<I: HasInitContext<()>, L: HasLogger>(
    ctx: I,
    amount: Amount,
    _logger: &mut L,
) -> InitResult<State> {
    let init_params: InitParams = ctx.parameter_cursor().get()?;
    ensure!(
        init_params.account_holders.dedup().len() >= 2,
        "Not enough account holders: At least two are needed for this contract to be valid."
    );
    ensure!(
        init_params.transfer_agreement_threshold <= init_params.account_holders.dedup().len(),
        "The threshold for agreeing account holders to allow a transfer must be " +
        "less than or equal to the number of unique account holders, else a transfer can never be made!"
    );
    ensure!(
        init_params.transfer_agreement_threshold >= 2,
        "The number of account holders required to accept a transfer must be two or more else you would be better off with a normal account!"
    );

    let state = State {
        init_params:                init_params,
        available_balance:          0,
        remaining_vesting_schedule: vec![],
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
        state.account_holders.iter().any(|account_holder| sender == account_holder),
        "Only account holders can interact with this contract."
    );
    let now = ctx.metadata().slot_time();

    // Drop requests which have gone too long without getting the support they need
    state
      .outstanding_transfer_requests
      .retain(|outstanding| outstanding.times_out_at > now);

    let msg: Message = ctx.parameter_cursor().get()?;
    match msg {
        Message::RequestTransferFunds(req_id, transfer_amount, target_account) => {
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
                supporters:      vec![sender]
            };
            state.outstanding_transfer_requests.push(new_request);
            Ok(Action::Accept)
        }

        Message::SupportTransfer(req_id, transfer_amount, target_account, withdrawer_account, existing_supporters) => {
            // Need to find an existing, matching transfer
            let matching_requests =
                state
                    .outstanding_transfer_requests
                    .iter()
                    .filter(|existing|
                            existing.req_id == req_id &&
                            existing.transfer_amount == transfer_amount &&
                            existing.target_account == target_account)
            let matching_request =
                match matching_requests {
                    [] => bail!("No such transfer to support.");
                    [matching] => matching
                    _ => impossible!();
                }
            // Can't have already supported this transfer
            ensure!(
                !matching_request.supporters.contains(sender),
                "You have already supported this transfer."
            );
            matching_request.supporters.push(sender);
            if (matching_request.supporters.len() >= state.init_params.transfer_agreement_threshold) {
                // Remove the transfer fron the list of outstanding transfers and send it
                state
                    .outstanding_transfer_requests
                    .retain(|outstanding| outstanding.id != req_id)
                Ok(A::simple_transfer(matching_request.target_account, matching_request.transfer_amount))
            } else {
                // Keep the updated support and accept
                Ok(Action::Accept)
            }
        }
    }
}

// (De)serialization

impl Serialize for Message {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        // TODO
        match self {
            Message::WithdrawFunds(how_much) => {
                out.write_u8(0)?;
                out.write_u64(*how_much)?;
            }
            Message::CancelFutureVesting => {
                out.write_u8(1)?;
            }
        }
        Ok(())
    }

    fn deserial<R: Read>(source: &mut R) -> Result<Self, R::Err> {
        // TODO
        match source.read_u8()? {
            0 => {
                let how_much = source.read_u64()?;
                Ok(Message::WithdrawFunds(how_much))
            }

            1 => Ok(Message::CancelFutureVesting),

            _ => Err(R::Err::default()),
        }
    }
}

impl Serialize for InitParams {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        // TODO
        self.account_holders.serial(out)?;
        self.future_vesting_veto_accounts.serial(out)?;
        self.vesting_schedule.serial(out)?;
        Ok(())
    }

    fn deserial<R: Read>(source: &mut R) -> Result<Self, R::Err> {
        // TODO
        let account_holders = source.get()?;
        let future_vesting_veto_accounts = source.get()?;
        let vesting_schedule = source.get()?;
        Ok(InitParams {
            account_holders,
            future_vesting_veto_accounts,
            vesting_schedule,
        })
    }
}

impl Serialize for State {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        // TODO
        self.account_holders.serial(out)?;
        self.future_vesting_veto_accounts.serial(out)?;
        self.available_balance.serial(out)?;
        self.remaining_vesting_schedule.serial(out)?;
        Ok(())
    }

    fn deserial<R: Read>(source: &mut R) -> Result<Self, R::Err> {
        // TODO
        let account_holders = source.get()?;
        let future_vesting_veto_accounts = source.get()?;
        let available_balance = source.get()?;
        let remaining_vesting_schedule = source.get()?;
        Ok(State {
            account_holders,
            future_vesting_veto_accounts,
            available_balance,
            remaining_vesting_schedule,
        })
    }
}

// Tests

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    #[no_mangle]
    fn test() {
        todo!("implement tests");
    }
}
