#![cfg_attr(not(feature = "std"), no_std)]
use concordium_std::*;

/* This contract allows CCD to be allocated to a user or group of users,
 * where those CCD vest over a period of time defined at the contract's
 * point of creation.
 *
 * Zero or more accounts may be given the right to stop future CCD vesting
 * (e.g. for cases such as an employee resigning where their future vesting
 * CCD is contingent on their employment). CCD corresponding to cancelled
 * vesting events will be returned to the contract owner.
 *
 * N.B. CCD that have notionally vested but have not yet been added to
 *      the available balance _will_ still be made available - only vesting
 *      events scheduled for after the current slot time will be cancelled.
 */

// Types

#[derive(Serialize)]
enum Message {
    WithdrawFunds(Amount),
    CancelFutureVesting,
}

type VestingEvent = (Timestamp, Amount);

#[derive(Serialize)]
struct InitParams {
    // Who is authorised to withdraw funds from this lockup (must be non-empty)
    account_holders: Vec<AccountAddress>,

    // Who is authorised to cancel future CCD vesting (can be left empty)
    future_vesting_veto_accounts: Vec<AccountAddress>,

    // When funds become available
    vesting_schedule: Vec<VestingEvent>,
}

#[contract_state(contract = "lockup")]
#[derive(Serialize, SchemaType)]
struct State {
    // Who is authorised to withdraw funds from this lockup (must be non-empty)
    account_holders: Vec<AccountAddress>,

    // Who is authorised to cancel future CCD vesting (can be left empty)
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

#[init(contract = "lockup", payable)]
#[inline(always)]
fn contract_init(ctx: &impl HasInitContext<()>, amount: Amount) -> InitResult<State> {
    let init_params: InitParams = ctx.parameter_cursor().get()?;
    ensure!(!init_params.account_holders.is_empty()); // No account holders given, but we need at least one.

    // Catch overflow when computing the amount to vest using checked summation
    let total_to_vest: Amount =
        init_params.vesting_schedule.iter().map(|(_, how_much)| *how_much).sum();
    ensure_eq!(total_to_vest, amount); // Amount given does not match what is required by the vesting schedule.

    let state = State {
        account_holders:              init_params.account_holders,
        future_vesting_veto_accounts: init_params.future_vesting_veto_accounts,
        available_balance:            Amount::zero(),
        remaining_vesting_schedule:   init_params.vesting_schedule,
    };
    Ok(state)
}

#[receive(contract = "lockup", name = "receive")]
#[inline(always)]
fn contract_receive<A: HasActions>(
    ctx: &impl HasReceiveContext<()>,
    state: &mut State,
) -> ReceiveResult<A> {
    let sender = match ctx.sender() {
        Address::Account(acc) => acc,
        Address::Contract(_) => {
            bail!(); // This contract only allows interaction with accounts, not
                     // contracts.
        }
    };

    make_vested_funds_available(ctx.metadata().slot_time(), state);
    let msg: Message = ctx.parameter_cursor().get()?;

    match msg {
        Message::WithdrawFunds(withdrawal_amount) => {
            ensure!(state.account_holders.iter().any(|&account_holder| sender == account_holder)); // Only account holders can make a withdrawal.
            ensure!(state.available_balance >= withdrawal_amount); // Not enough available funds to make withdrawal.

            // We have checked that the available balance is high enough, so underflow
            // should not be possible
            state.available_balance -= withdrawal_amount;
            Ok(A::simple_transfer(&sender, withdrawal_amount))
        }

        Message::CancelFutureVesting => {
            ensure!(state
                .future_vesting_veto_accounts
                .iter()
                .any(|&veto_account| sender == veto_account)); // Only veto accounts can cancel future vesting.

            // Should not overflow since the sum is positive but less than
            // or equal to the checked sum of the initial vesting schedule
            // computed at init time
            let cancelled_vesting_amount: Amount =
                state.remaining_vesting_schedule.iter().map(|(_, how_much)| *how_much).sum();
            state.remaining_vesting_schedule = vec![];

            // Return unvested funds to the contract owner
            Ok(A::simple_transfer(&ctx.owner(), cancelled_vesting_amount))
        }
    }
}

// Updates the available balance with any funds which have now vested
fn make_vested_funds_available(time_now: Timestamp, state: &mut State) {
    let (newly_vested, not_vested_yet): (Vec<VestingEvent>, Vec<VestingEvent>) =
        state.remaining_vesting_schedule.iter().partition(|(when, _how_much)| when < &time_now);
    let newly_vested_amount: Amount = newly_vested.iter().map(|(_, how_much)| *how_much).sum();

    state.remaining_vesting_schedule = not_vested_yet;

    // It shouldn't be possible to overflow because when we init we sum all
    // vesting events and check for no overflow, and this sum here should
    // always be less than or equal to that (the difference being due to
    // withdrawn funds), but greater than or equal to zero (since you can't
    // withdraw funds you don't have).
    state.available_balance += newly_vested_amount;
}

// Tests
#[concordium_cfg_test]
pub mod tests {
    use super::*;

    #[concordium_test]
    fn test() {
        fail!("implement tests");
    }
}
