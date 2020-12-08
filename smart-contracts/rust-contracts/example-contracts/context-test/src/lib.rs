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

#[init(contract = "context_test_2")]
// can only be initialized
fn contract_init_2(
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
        if let Some(p) = policy.next_item(&mut buf) {
            if p.1 != 31 {
                return Ok(p.1);
            } else if p.0 != attributes::COUNTRY_OF_RESIDENCE {
                return Ok(5);
            } else if &buf[..] != (1..=31).collect::<Vec<_>>().as_slice() {
                return Ok(6);
            } else if policy.next_item(&mut buf).is_some() {
                return Ok(4)
            }
        } else {
            return Ok(7);
        }
    }
    Ok(0)
}

#[concordium_cfg_test]
mod tests {
    use super::*;
    use concordium_std::test_infrastructure::*;

    #[concordium_test]
    fn test_init_2_success() {
        let mut ctx = InitContextTest::empty();
        let policy = OwnedPolicy {
            identity_provider: 17,
            created_at: 1,
            valid_to: 1,
            items: vec![(attributes::COUNTRY_OF_RESIDENCE, (1..=31).collect::<Vec<_>>())]
        };

        ctx.set_policies(vec![TestPolicy::new(policy)]);
        let mut logger = LogRecorder::init();

        let out = contract_init_2(&ctx, Amount::from_micro_gtu(0), &mut logger);

        let state = match out {
            Ok(state) => state,
            Err(_) => fail!("Contract initialization failed."),
        };
        claim_eq!(state, 0);
    }
}
