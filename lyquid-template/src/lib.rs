#![feature(allocator_api)]
use lyquid::runtime::*;

lyquid::state! {
    service greeting: service::String = service::new_string();
    service greet_count: u64 = 0;
    // Off-chain state
    instance per_user_count: instance::HashMap<Address, u64> = instance::new_hashmap();
}

lyquid::method! {
    constructor(ctx; greeting: String) {
        *ctx.service.greeting = greeting.into();
    }

    service fn set_greeting(ctx; greeting: String) -> LyquidResult<bool> {
        *ctx.service.greeting = greeting.into();
        Ok(true)
    }

    service fn greet(ctx;) -> LyquidResult<bool> {
        *ctx.service.greet_count += 1;
        Ok(true)
    }

    // This instance function only reads service state, so it's more like a "view" function in Solidity.
    instance fn get_greeting_message(ctx;) -> LyquidResult<String> {
        Ok(format!("{} I've greeted {} times to on-chain users",
            ctx.service.greeting, ctx.service.greet_count))
    }

    // The off-chain computation below CANNOT be done by Solidity/EVM.
    instance fn greet_me(ctx;) -> LyquidResult<String> {
        let mut per_user_count = ctx.instance.per_user_count.write();
        let user = per_user_count.entry(ctx.caller).or_default();
        *user += 1;
        Ok(format!("{} I've greeted {} times to on-chain users, and {} times to you",
            ctx.service.greeting, ctx.service.greet_count, *user))
    }
}
