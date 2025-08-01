#![feature(allocator_api)]
use lyquid::runtime::*;

lyquid::state! {
    network greeting: network::String = network::new_string();
    network greet_count: u64 = 0;
    // Off-chain state
    instance per_user_count: instance::HashMap<Address, u64> = instance::new_hashmap();
}

lyquid::method! {
    constructor(&mut ctx, greeting: String) {
        *ctx.network.greeting = greeting.into();
    }

    network fn set_greeting(&mut ctx, greeting: String) -> LyquidResult<bool> {
        *ctx.network.greeting = greeting.into();
        Ok(true)
    }

    network fn greet(&mut ctx) -> LyquidResult<bool> {
        *ctx.network.greet_count += 1;
        Ok(true)
    }

    // This network function only reads network state (`&ctx`), so it's like a "view" function in
    // Solidity. You can also write `instance fn` instead, but since we don't use any instance
    // state here it's good to be conservative, so you can't touch upon instance state accidentally.
    network fn get_greeting_message(&ctx) -> LyquidResult<String> {
        Ok(format!("{} I've greeted {} times to on-chain users",
            ctx.network.greeting, ctx.network.greet_count))
    }

    // The off-chain computation below CANNOT be done by Solidity/EVM.
    instance fn greet_me(&mut ctx) -> LyquidResult<String> {
        let mut per_user_count = ctx.instance.per_user_count.write();
        let user = per_user_count.entry(ctx.caller).or_default();
        *user += 1;
        Ok(format!("{} I've greeted {} times to on-chain users, and {} times to you",
            ctx.network.greeting, ctx.network.greet_count, *user))
    }
}
