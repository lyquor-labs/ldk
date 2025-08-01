// =============================================================================
// Lyquid ERC-20 Token Implementation
// =============================================================================
//
// This module implements a standard ERC-20 compliant token in the Lyquid framework.
// It closely follows the OpenZeppelin ERC-20 implementation pattern from Solidity.
//
// Features:
// - Full ERC-20 standard compliance
// - Token name: "Lyquor"
// - Token symbol: "LYQ"
// - Decimals: 18
// - Initial supply: 1000 LYQ minted to the contract deployer
// - Standard transfer, allowance, and approval mechanisms
// - Internal minting and burning capabilities
//
// Note: Some Ethereum-specific features like events are currently marked as TODOs.
// =============================================================================

#![feature(allocator_api)]
use lyquid::runtime::*;

// Written by following Solidity code in
// https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/ERC20.sol

/// Returns the token balance of the specified account, defaulting to zero if not found
fn get_balance<'a>(state: &'a __lyquid::NetworkState, account: &Address) -> &'a U256 {
    state.balances.get(account).unwrap_or(&U256::ZERO)
}

/// Core function to update balances when tokens are transferred, minted, or burned
/// Handles special cases where from/to is the zero address (minting/burning)
fn update(state: &mut __lyquid::NetworkState, from: Address, to: Address, value: U256) -> LyquidResult<()> {
    if from == Address::ZERO {
        *state.total_supply += value;
    } else {
        let from_balance = state.balances.entry(from).or_insert(U256::ZERO);
        if *from_balance < value {
            return Err(LyquidError::LyquidRuntime("insufficient balance".into()))
        }
        *from_balance -= value;
    }
    if to == Address::ZERO {
        *state.total_supply -= value;
    } else {
        state.balances.entry(to).and_modify(|v| *v += value).or_insert(value);
    }
    // TODO: emit Transfer event
    Ok(())
}

/// Transfers tokens between non-zero addresses
/// Validates both sender and receiver are valid (non-zero) addresses
fn transfer(state: &mut __lyquid::NetworkState, from: Address, to: Address, value: U256) -> LyquidResult<()> {
    if from == Address::ZERO {
        return Err(LyquidError::LyquidRuntime("invalid sender".into()))
    }
    if to == Address::ZERO {
        return Err(LyquidError::LyquidRuntime("invalid receiver".into()))
    }
    update(state, from, to, value)
}

/// Sets the amount of tokens that the spender is allowed to transfer on behalf of the owner
/// Both owner and spender must be valid (non-zero) addresses
fn approve(
    state: &mut __lyquid::NetworkState, owner: Address, spender: Address, value: U256, _emit_event: bool,
) -> LyquidResult<()> {
    if owner == Address::ZERO {
        return Err(LyquidError::LyquidRuntime("invalid approver".into()))
    }
    if spender == Address::ZERO {
        return Err(LyquidError::LyquidRuntime("invalid spender".into()))
    }
    state.allowances.insert((owner, spender), value);
    // TODO: emit events
    Ok(())
}

/// Returns the current allowance granted to a spender by an owner
/// Returns zero if no allowance has been set
fn allowance(state: &__lyquid::NetworkState, owner: Address, spender: Address) -> &U256 {
    state.allowances.get(&(owner, spender)).unwrap_or(&U256::ZERO)
}

/// Decreases the allowance granted to spender by owner when tokens are transferred
/// If current allowance is the maximum value (U256::MAX), it represents an unlimited allowance
fn spend_allowance(
    state: &mut __lyquid::NetworkState, owner: Address, spender: Address, value: U256,
) -> LyquidResult<()> {
    let current = allowance(state, owner, spender);
    if current < &U256::MAX {
        if current < &value {
            return Err(LyquidError::LyquidRuntime("insufficient allowance".into()))
        }
        approve(state, owner, spender, current - value, false)?;
    }
    Ok(())
}

/// Creates and assigns new tokens to an account, increasing the total supply
/// Cannot mint to the zero address
fn _mint(state: &mut __lyquid::NetworkState, account: Address, amount: U256) -> LyquidResult<()> {
    if account == Address::ZERO {
        return Err(LyquidError::LyquidRuntime("invalid receiver".into()))
    }
    update(state, Address::ZERO, account, amount)?;
    lyquid::println!("minted {} to {}", amount, account);
    Ok(())
}

/// Destroys tokens from an account, decreasing the total supply
/// Cannot burn from the zero address
fn _burn(state: &mut __lyquid::NetworkState, account: Address, amount: U256) -> LyquidResult<()> {
    if account == Address::ZERO {
        return Err(LyquidError::LyquidRuntime("invalid sender".into()))
    }
    update(state, account, Address::ZERO, amount)
}

/// Defines the contract state variables:
/// - total_supply: Tracks the total amount of tokens in circulation
/// - balances: Maps addresses to their token balances
/// - allowances: Maps (owner, spender) pairs to approved allowance amounts
lyquid::state! {
    network total_supply: U256 = U256::ZERO;
    network balances: network::HashMap<Address, U256> = network::new_hashmap();
    network allowances: network::HashMap<(Address, Address), U256> = network::new_hashmap();
}

/// Defines all the contract methods required by the ERC-20 standard:
/// - constructor: Initializes the contract with initial token supply
/// - name, symbol, decimals: Token metadata
/// - totalSupply: Returns the total amount of tokens in circulation
/// - balanceOf: Returns the balance of a specific account
/// - transfer: Transfers tokens from the caller to another account
/// - allowance: Returns the amount a spender is allowed to withdraw from an owner
/// - approve: Sets spender allowance to withdraw from the caller's account
/// - transferFrom: Transfers tokens on behalf of another account using allowances
lyquid::method! {
    constructor(&mut ctx) {
        // sender will mint 1000 LYQ
        _mint(&mut ctx.network, ctx.caller, uint!(1_000_000_000_000_000_000_000_U256)).expect("failed to init");
    }

    instance fn name(&mut ctx) -> LyquidResult<String> {
        Ok("Lyquor".into())
    }

    instance fn symbol(&mut ctx) -> LyquidResult<String> {
        Ok("LYQ".into())
    }

    instance fn decimals(&mut ctx) -> LyquidResult<u8> {
        Ok(18)
    }

    network fn totalSupply(&ctx) -> LyquidResult<U256> {
        Ok(ctx.network.total_supply.clone())
    }

    network fn balanceOf(&ctx, account: Address) -> LyquidResult<U256> {
        Ok(get_balance(&ctx.network, &account).clone())
    }

    network fn transfer(&mut ctx, to: Address, amount: U256) -> LyquidResult<bool> {
        let from = ctx.caller.clone();
        lyquid::println!("transfer {} from {} to {}", amount, from, to);
        transfer(&mut ctx.network, from, to, amount)?;
        Ok(true)
    }

    instance fn allowance(&mut ctx, owner: Address, spender: Address) -> LyquidResult<U256> {
        Ok(allowance(&mut ctx.network, owner, spender).clone())
    }

    network fn approve(&mut ctx, spender: Address, value: U256) -> LyquidResult<bool> {
        approve(&mut ctx.network, ctx.caller, spender, value, true)?;
        Ok(true)
    }

    network fn transferFrom(&mut ctx, from: Address, to: Address, value: U256) -> LyquidResult<bool> {
        let spender = ctx.caller;
        spend_allowance(&mut ctx.network, from, spender, value)?;
        transfer(&mut ctx.network, from, to, value)?;
        Ok(true)
    }
}
