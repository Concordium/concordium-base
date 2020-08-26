#![cfg_attr(not(feature = "std"), no_std)]
use concordium_sc_base::*;

/*
 * A contract that acts like an account (can send, store and accept GTU), but
 * requires n > 1 ordained accounts to agree to the sending of GTU before it is
 * accepted. This is useful for storing GTU where the security of just one account
 * isn’t considered high enough.
 *
 * Withdrawal requests time out if not agreed to within the contract's
 * specified time-to-live for withdrawal requests
 *
 * Withdrawal requests are given IDs to disambiguate otherwise identical
 * requests, since they might have different motivations behind the scenes,
 * making them not-quite fungible (e.g. for accounting purposes it might be
 * necessary for account holders to track a particular named withdrawal).
 *
 * Deposits: Allowed at any time from anyone
 * Withdrawals: Only by accounts named at initialization, and only with the agreement of at least n of those accounts
 *
 * TODO Generalise to sending to _any_ account with the agreement of the named accounts (e.g. to
 * pay someone as a group)?
 */

// Types

#[derive(Clone, Copy, PartialEq, Eq)]
enum Message {
    // Indicates that the user sending the message would like to make a request
    // with the given ID and amount.
    // This is a no-op if the given ID already exists and has not timed out.
    RequestWithdrawFunds(WithdrawalRequestId, Amount),

    // Indicates that the user sending the message votes in favour of the
    // withdrawal with the given ID and amount to the given account address.
    // This is a no-op if the given ID does not exist (potentially due to timing
    // out), or exists with a different amount or address.
    AgreeWithdrawFunds(WithdrawalRequestId, Amount, AccountAddress),
}

type WithdrawalRequestId = u64;
type Reason = &str;

// TODO Is seconds the correct unit?
type WithdrawalRequestTimeToLiveSeconds = u64;
type TimeoutSlotTimeSeconds = u64;

pub struct InitParams {
    // Who is authorised to withdraw funds from this lockup (must be non-empty)
    account_holders: Vec<AccountAddress>,

    // How many of the account holders need to agree before funds are released
    withdrawal_agreement_threshold: u32

    // How long to wait before dropping a request due to lack of support
    // N.B. If this is set too long, in practice the chain might become busy
    //      enough that requests time out before they can be agreed to by all
    //      parties, so be wary of setting this too low. On the otherhand,
    //      if this is set too high, a bunch of pending requests can get into
    //      a murky state where some account holders may consider the request obsolete,
    //      only for another account holder to "resurrect" it, so having _some_
    //      time out gives some security against old requests being surprisingly
    //      accepted.
    withdrawal_request_ttl: WithdrawalRequestTimeToLiveSeconds
}

pub struct State {
    // The initial configuration of the contract
    init_params: InitParams,

    // Requests which have not been dropped due to timing out or due to being agreed to yet
    // The request ID, the associated amount, when it times out and who is making the withdrawal
    outstanding_withdrawal_requests: Vec<(WithdrawalRequestId, Amount, TimeoutSlotTimeSeconds, AccountAddress)>,
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
        init_params.withdrawal_agreement_threshold <= init_params.account_holders.dedup().len(),
        "The threshold for agreeing account holders to allow a withdrawal must be " +
        "less than or equal to the number of unique account holders, else a withdrawal can never be made!"
    );
    ensure!(
        init_params.withdrawal_agreement_threshold >= 2,
        "The number of account holders required to accept a withdrawal must be two or more else you would be better off with a normal account!"
    );

    let state = State {
        init_params:                init_params,
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
    remove_timed_out_requests(ctx.metadata().slot_time(), state);
    let msg: Message = ctx.parameter_cursor().get()?;

    match msg {
        Message::RequestWithdrawFunds(req_id, withdrawal_amount, _, withdrawer_account) => {
            // TODO
            unimplemented!();
            /*
            ensure!(
                state.account_holders.iter().any(|account_holder| sender == account_holder),
                "Only account holders can make a withdrawal."
            );
            ensure!(
                state.available_balance >= withdrawal_amount,
                "Not enough available funds to make withdrawal."
            );

            // We have checked that the avaiable balance is high enough, so underflow
            // should not be possible
            state.available_balance -= withdrawal_amount;
            Ok(A::simple_transfer(sender, withdrawal_amount))
            */
        }

        Message::AcceptWithdrawFunds(req_id, withdrawal_amount, _, withdrawer_account) => {
            // TODO
            unimplemented!();
            /*
            ensure!(
                state
                    .future_vesting_veto_accounts
                    .iter()
                    .any(|veto_account| sender == veto_account),
                "Only veto accounts can cancel future vesting."
            );

            // Should not overflow since the sum is positive but less than
            // or equal to the checked sum of the initial vesting schedule
            // computed at init time
            let cancelled_vesting_amount: Amount =
                state.remaining_vesting_schedule.iter().map(|(_, how_much)| *how_much).sum();
            state.remaining_vesting_schedule = vec![];

            // Return unvested funds to the contract owner
            Ok(A::simple_transfer(ctx.owner(), cancelled_vesting_amount))
            */
        }
    }
}

// Update the state to purge requests which have sat too long without being
// agreed to by the relevant parties
fn remove_timed_out_requests(time_now: u64, state: &mut State) {
    let live_requests: Vec<(WithdrawalRequestId, Amount, TimeoutSlotTimeSeconds)> =
        state
          .outstanding_withdrawal_requests
          .iter()
          .filter(|(_, _, expiry)| expiry > &time_now)
          .collect();

    state.outstanding_withdrawal_requests = live_requests;
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
