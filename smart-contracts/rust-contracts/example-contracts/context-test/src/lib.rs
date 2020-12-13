#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
use concordium_std::*;

#[init(contract = "context_test")]
// can only be initialized
fn contract_init(ctx: &impl HasInitContext) -> InitResult<u8> {
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
fn contract_init_2(ctx: &impl HasInitContext) -> InitResult<u8> {
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
                return Ok(4);
            }
        } else {
            return Ok(7);
        }
    }
    Ok(0)
}

#[init(contract = "context_test_3")]
// expect an account with 2 policies.
fn contract_init_3(ctx: &impl HasInitContext) -> InitResult<u8> {
    if ctx.policies().len() != 2 {
        return Ok(1);
    }
    let mut policies = ctx.policies();
    if let Some(mut policy) = policies.next() {
        if policy.identity_provider() != 17 {
            return Ok(2);
        }
        if policy.created_at() != policy.valid_to() {
            return Ok(3);
        }
        let mut buf = [0u8; 31];
        if let Some(p) = policy.next_item(&mut buf) {
            if p.1 != 31 {
                return Ok(4);
            } else if p.0 != attributes::COUNTRY_OF_RESIDENCE {
                return Ok(5);
            } else if &buf[..] != (1..=31).collect::<Vec<_>>().as_slice() {
                return Ok(6);
            } else if policy.next_item(&mut buf).is_some() {
                return Ok(7);
            }
        } else {
            return Ok(8);
        }
    } else {
        return Ok(9);
    }
    if let Some(mut policy) = policies.next() {
        if policy.identity_provider() != 25 {
            return Ok(10);
        }
        if policy.created_at().checked_add(Duration::from_millis(10)).unwrap_abort()
            != policy.valid_to()
        {
            return Ok(11);
        }
        let mut buf = [0u8; 31];
        if let Some(p) = policy.next_item(&mut buf) {
            if p.1 != 31 {
                return Ok(12);
            } else if p.0 != attributes::COUNTRY_OF_RESIDENCE {
                return Ok(13);
            } else if &buf[..] != (1..=31).collect::<Vec<_>>().as_slice() {
                return Ok(14);
            }
        } else {
            return Ok(16);
        }
        if let Some(p) = policy.next_item(&mut buf) {
            if p.1 != 13 {
                return Ok(17);
            } else if p.0 != attributes::DOB {
                return Ok(18);
            } else if &buf[0..13] != vec![17; 13].as_slice() {
                return Ok(19);
            }
        }
        if policy.next_item(&mut buf).is_some() {
            return Ok(20);
        }
    } else {
        return Ok(21);
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
            created_at:        Timestamp::from_timestamp_millis(1),
            valid_to:          Timestamp::from_timestamp_millis(1),
            items:             vec![(
                attributes::COUNTRY_OF_RESIDENCE,
                (1..=31).collect::<Vec<_>>(),
            )],
        };

        ctx.push_policy(policy);

        let out = contract_init_2(&ctx);

        let state = out.expect_report("Contract initialization failed.");
        claim_eq!(state, 0);
    }
}
