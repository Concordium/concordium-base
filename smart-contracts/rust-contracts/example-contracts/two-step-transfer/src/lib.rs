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
 * Deposits: Allowed at any time from anyone
 * Withdrawals: Only by accounts named at initialization, and only with the agreement of at least n of those accounts
 *
 * TODO Generalise to sending to _any_ account with the agreement of the named accounts (e.g. to
 * pay someone as a group)?
 */

// Types

#[derive(Clone, Copy, PartialEq, Eq)]
enum Message {
    RequestWithdrawFunds(WithdrawalRequestId, Amount, Reason),
    AgreeWithdrawFunds(WithdrawalRequestId, Amount),
}

type WithdrawalRequestId = u64;
type Reason = &str;

// TODO Is seconds the correct unit?
type WithdrawalRequestTimeToLiveSeconds = u64;
type SlotTimeSeconds = u64;

pub struct InitParams {
    // Who is authorised to withdraw funds from this lockup (must be non-empty)
    account_holders: Vec<AccountAddress>,

    // How many of the account holders need to agree before funds are released
    withdrawal_agreement_threshold: u32

    // How long to wait before dropping a request due to lack of support
    withdrawal_request_ttl: WithdrawalRequestTimeToLiveSeconds
}

pub struct State {
    // Who is authorised to withdraw funds from this lockup (must be non-empty)
    account_holders: Vec<AccountAddress>,

    // How many of the account holders need to agree before funds are released
    withdrawal_agreement_threshold: u32

    // Requests which have not been dropped due to timing out or due to being agreed to yet
    // The request ID, the associated amount and when it times out
    outstanding_withdrawal_requests: Vec<(WithdrawalRequestId, Amount, SlotTime)>,
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
        !init_params.account_holders.is_empty(),
        "No account holders given, but we need at least one."
    );

    // TODO
    let state = State {
        account_holders:              init_params.account_holders,
        future_vesting_veto_accounts: init_params.future_vesting_veto_accounts,
        available_balance:            0,
        remaining_vesting_schedule:   init_params.vesting_schedule,
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
    ensure!(amount == 0, "Depositing into a running lockup account is not allowed.");
    let sender = match ctx.sender() {
        Address::Account(acc) => acc,
        Address::Contract(_) => {
            bail!("This contract only allows interaction with accounts, not contracts.")
        }
    };

    // TODO Change this to timing out old requests
    make_vested_funds_available(ctx.metadata().slot_time(), state);
    let msg: Message = ctx.parameter_cursor().get()?;

    match msg {
        Message::WithdrawFunds(withdrawal_amount) => {
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
        }

        Message::CancelFutureVesting => {
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
        }
    }
}

// TODO Change this to timing out old requests
// Updates the available balance with any funds which have now vested
fn make_vested_funds_available(time_now: u64, state: &mut State) {
    let (newly_vested, not_vested_yet): (Vec<VestingEvent>, Vec<VestingEvent>) =
        state.remaining_vesting_schedule.iter().partition(|(when, _how_much)| when < &time_now);
    let newly_vested_amount: Amount = newly_vested.iter().map(|(_, how_much)| how_much).sum();

    state.remaining_vesting_schedule = not_vested_yet;

    // It shouldn't be possible to overflow because when we init we sum all
    // vesting events and check for no overflow, and this sum here should
    // always be less than or equal to that (the difference being due to
    // withrawn funds), but greater than or equal to zero (since you can't
    // withdraw funds you don't have).
    state.available_balance += newly_vested_amount;
}

// (De)serialization

impl Serialize for Message {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
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
        self.account_holders.serial(out)?;
        self.future_vesting_veto_accounts.serial(out)?;
        self.vesting_schedule.serial(out)?;
        Ok(())
    }

    fn deserial<R: Read>(source: &mut R) -> Result<Self, R::Err> {
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
        self.account_holders.serial(out)?;
        self.future_vesting_veto_accounts.serial(out)?;
        self.available_balance.serial(out)?;
        self.remaining_vesting_schedule.serial(out)?;
        Ok(())
    }

    fn deserial<R: Read>(source: &mut R) -> Result<Self, R::Err> {
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
