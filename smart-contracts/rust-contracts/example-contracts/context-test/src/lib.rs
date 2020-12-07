#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
use concordium_std::*;

#[init(contract = "context_test")]
// can only be initialized
fn contract_init(
    ctx: &impl HasInitContext,
    _amount: Amount,
    _logger: &mut impl HasLogger,
) -> InitResult<u8> {
    if ctx.policies().len() != 1 {
        return Ok(1);
    }
    for mut policy in ctx.policies() {
        if policy.identity_provider() != 17 {
            return Ok(2);
        }
        if policy.created_at() != policy.valid_to() {
            return Ok(3);
        }
        let mut buf = [0u8; 31];
        if policy.next_item(&mut buf).is_some() {
            return Ok(4);
        }
    }
    Ok(0)
}
