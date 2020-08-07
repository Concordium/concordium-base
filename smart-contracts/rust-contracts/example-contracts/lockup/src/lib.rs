#![cfg_attr(not(feature = "std"), no_std)]
use concordium_sc_base::*;

/* This contract allows GTU to be allocated to a user or group of users,
 * where those GTU vest over a period of time defined at the contract's
 * point of creation.
 *
 * Zero or more accounts may be given the right to stop future GTU vesting
 * (e.g. for cases such as an employee resigning where their future vesting
 * GTU is contingent on their employment). GTU corresponding to cancelled
 * vesting events will be returned to the contract owner.
 *
 * N.B. GTU that have notionally vested but have not yet been added to
 *      the available balance _will_ still be made available - only vesting
 *      events scheduled for after the current slot time will be cancelled.
 */

// Types

#[derive(Clone, Copy, PartialEq, Eq)]
enum Message {
    WithdrawFunds(Amount),
    CancelFutureVesting,
}

type SlotTime = u64;

type VestingEvent = (SlotTime, Amount);

pub struct InitParams {
    // Who is authorised to withdraw funds from this lockup (must be non-empty)
    account_holders: Vec<AccountAddress>,

    // Who is authorised to cancel future GTU vesting (can be left empty)
    future_vesting_veto_accounts: Vec<AccountAddress>,

    // When funds become available
    vesting_schedule: Vec<VestingEvent>,
}

pub struct State {
    // Who is authorised to withdraw funds from this lockup (must be non-empty)
    account_holders: Vec<AccountAddress>,

    // Who is authorised to cancel future GTU vesting (can be left empty)
    future_vesting_veto_accounts: Vec<AccountAddress>,

    // Funds which have vested but have not yet been withdrawn
    // N.B. This is updated each time a withdrawal is requested, so it
    //      may well be out of date just prior to the request being made.
    //      As such, this number alone is not enough to determine whether a
    //      withdrawal will succeed - you'll need to check the slot time and the
    //      vesting schedule too in order to determine what amount can actually
    //      be withdrawn at a given slot time. The existence of this field,
    //      therefore, is an implementation artifact and not a simple view onto
    //      the state of the contract.
    available_balance: Amount,

    // Funds which have yet to be made available (as funds vest and are added to the available
    // funds, they will be removed from here)
    remaining_vesting_schedule: Vec<VestingEvent>,
}

// Contract implementation

#[init(name = "init")]
#[inline(always)]
fn contract_init(ctx: InitContext, amount: Amount) -> InitResult<State> {
    let init_params: InitParams = ctx.parameter()?;
    ensure!(
        !init_params.account_holders.is_empty(),
        "No account holders given, but we need at least one."
    );

    // Catch overflow when computing the amount to vest using checked summation
    let total_to_vest: Amount = init_params
        .vesting_schedule
        .iter()
        .map(|(_, how_much)| *how_much)
        .try_fold(0, u64::checked_add)
        .ok_or(Reject {})?;
    ensure!(
        total_to_vest == amount,
        "Amount given does not match what is required by the vesting schedule."
    );
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
fn contract_receive(ctx: ReceiveContext, amount: Amount, state: &mut State) -> ReceiveResult {
    ensure!(amount == 0, "Depositing into a running lockup account is not allowed.");
    let sender = match ctx.sender() {
        Address::Account(acc) => acc,
        Address::Contract(_) => {
            bail!("This contract only allows interaction with accounts, not contracts.")
        }
    };

    make_vested_funds_available(ctx.get_time(), state);
    let msg: Message = ctx.parameter()?;

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
            Ok(Action::simple_transfer(sender, withdrawal_amount))
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
            Ok(Action::simple_transfer(ctx.owner(), cancelled_vesting_amount))
        }
    }
}

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
