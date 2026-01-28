// =============================================================================
// Lyquid Basic Swap Implementation
//
// This module implements a Uniswap V2-style Automated Market Maker (AMM) in the Lyquid framework.
// It follows the constant product formula (x * y = k) for token swaps and liquidity provision.
// =============================================================================

use lyquid::runtime::*;

mod utils;
use utils::{min, sqrt};

// Written by following Solidity code in
// https://github.com/Uniswap/v2-core/blob/master/contracts/UniswapV2Pair.sol

/// Minimum liquidity locked in the contract forever (sent to zero address)
const MINIMUM_LIQUIDITY: U256 = uint!(1000_U256);

/// Fee taken on swaps: 0.3% = 3/1000
const FEE_RATE: U256 = uint!(3_U256);
const FEE_DENOMINATOR: U256 = uint!(1000_U256);

fn _safe_transfer(token: LyquidID, to: Address, amount: U256) -> LyquidResult<()> {
    if !call!((token).transfer(to: Address = to, amount: U256 = amount) -> (success: LyquidResult<bool>))?.success? {
        return Err(LyquidError::LyquidRuntime("TRANSFER_FAILED".into()));
    }
    Ok(())
}

fn _safe_transfer_from(token: LyquidID, from: Address, to: Address, amount: U256) -> LyquidResult<()> {
    if !call!((token).transferFrom(from: Address = from, to: Address = to, value: U256 = amount) -> (success: LyquidResult<bool>))?.success? {
        return Err(LyquidError::LyquidRuntime("TRANSFER_FROM_FAILED".into()));
    }
    Ok(())
}

fn _get_token_balance(token: LyquidID, account: Address) -> LyquidResult<U256> {
    Ok(call!((token).balanceOf(account: Address = account) -> (balance: LyquidResult<U256>))?.balance?)
}

fn _update(self_address: Address, state: &mut __lyquid::NetworkState) -> LyquidResult<()> {
    *state.reserve0 = _get_token_balance(*state.token0, self_address)?;
    *state.reserve1 = _get_token_balance(*state.token1, self_address)?;
    Ok(())
}

fn _mint(state: &mut __lyquid::NetworkState, to: Address, amount: U256) -> LyquidResult<()> {
    *state.total_supply += amount;
    state
        .balances
        .insert(to, state.balances.get(&to).unwrap_or(&U256::ZERO) + amount);
    Ok(())
}

fn _burn(state: &mut __lyquid::NetworkState, from: Address, amount: U256) -> LyquidResult<()> {
    let balance = state.balances.get(&from).unwrap_or(&U256::ZERO).clone();
    if balance < amount {
        return Err(LyquidError::LyquidRuntime("INSUFFICIENT_BALANCE".into()));
    }
    state.balances.insert(from, balance - amount);
    *state.total_supply -= amount;
    Ok(())
}

lyquid::state! {
    network token0: LyquidID = LyquidID::default();
    network token1: LyquidID = LyquidID::default();
    network reserve0: U256 = U256::ZERO;
    network reserve1: U256 = U256::ZERO;
    network total_supply: U256 = U256::ZERO;
    network balances: HashMap<Address, U256> = new_hashmap();
}

#[lyquid::method::network(export = ethereum)]
fn constructor(ctx: &mut _, _token0: RequiredLyquid, _token1: RequiredLyquid) {
    *ctx.network.token0 = _token0.0;
    *ctx.network.token1 = _token1.0;
}

#[lyquid::method::network(export = ethereum)]
fn mint(ctx: &mut _, to: Address) -> LyquidResult<U256> {
    let (reserve0, reserve1) = (*ctx.network.reserve0, *ctx.network.reserve1);
    let lyquid_id = ctx.lyquid_id;
    let self_address: Address = lyquid_id.into();
    let balance0 = _get_token_balance(*ctx.network.token0, self_address)?;
    let balance1 = _get_token_balance(*ctx.network.token1, self_address)?;
    if balance0 <= reserve0 || balance1 <= reserve1 {
        return Err(LyquidError::LyquidRuntime("INSUFFICIENT_BALANCE_FOR_MIN".into()));
    }
    let (amount0, amount1) = (balance0 - reserve0, balance1 - reserve1);

    let liquidity = if *ctx.network.total_supply == U256::ZERO {
        let initial = sqrt(amount0 * amount1);
        if initial <= MINIMUM_LIQUIDITY {
            return Err(LyquidError::LyquidRuntime("INSUFFICIENT_LIQUIDITY_MINTED".into()));
        }
        _mint(&mut ctx.network, Address::ZERO, MINIMUM_LIQUIDITY)?;
        initial - MINIMUM_LIQUIDITY
    } else {
        min(
            amount0 * *ctx.network.total_supply / reserve0,
            amount1 * *ctx.network.total_supply / reserve1,
        )
    };

    if liquidity == U256::ZERO {
        return Err(LyquidError::LyquidRuntime("INSUFFICIENT_LIQUIDITY_MINTED".into()));
    }
    _mint(&mut ctx.network, to, liquidity)?;
    *ctx.network.reserve0 = balance0;
    *ctx.network.reserve1 = balance1;
    lyquid::println!(
        "Minted {} LP tokens to {} (amounts: {} token0, {} token1)",
        liquidity,
        to,
        amount0,
        amount1
    );
    Ok(liquidity)
}

#[lyquid::method::network(export = ethereum)]
fn burn(ctx: &mut _, to: Address, liquidity: U256) -> LyquidResult<bool> {
    if to == Address::ZERO || liquidity == U256::ZERO {
        return Err(LyquidError::LyquidRuntime("INVALID_BURN".into()));
    }
    let amount0 = liquidity * *ctx.network.reserve0 / *ctx.network.total_supply;
    let amount1 = liquidity * *ctx.network.reserve1 / *ctx.network.total_supply;
    if amount0 == U256::ZERO || amount1 == U256::ZERO {
        return Err(LyquidError::LyquidRuntime("INSUFFICIENT_LIQUIDITY_BURNED".into()));
    }

    _burn(&mut ctx.network, ctx.caller, liquidity)?;
    _safe_transfer(*ctx.network.token0, to, amount0)?;
    _safe_transfer(*ctx.network.token1, to, amount1)?;

    let lyquid_id = ctx.lyquid_id;
    _update(lyquid_id.into(), &mut ctx.network)?;
    lyquid::println!(
        "Burned {} LP tokens from {}, returned {} token0 and {} token1",
        liquidity,
        ctx.caller,
        amount0,
        amount1
    );
    Ok(true)
}

#[lyquid::method::network(export = ethereum)]
fn swap(
    ctx: &mut _, amount0_out: U256, amount1_out: U256, to: Address, amount0_in: U256, amount1_in: U256,
) -> LyquidResult<bool> {
    let (reserve0, reserve1) = (*ctx.network.reserve0, *ctx.network.reserve1);
    let (token0, token1) = (*ctx.network.token0, *ctx.network.token1);

    let lyquid_id = ctx.lyquid_id;
    let self_address: Address = lyquid_id.into();

    if amount0_out == U256::ZERO && amount1_out == U256::ZERO {
        return Err(LyquidError::LyquidRuntime("INSUFFICIENT_OUTPUT_AMOUNT".into()));
    }
    if amount0_out >= reserve0 || amount1_out >= reserve1 {
        return Err(LyquidError::LyquidRuntime("INSUFFICIENT_LIQUIDITY".into()));
    }
    if to == Address::from(token0) || to == Address::from(token1) {
        return Err(LyquidError::LyquidRuntime("INVALID_TO".into()));
    }

    // Transfer input tokens from user to this contract
    if amount0_in > U256::ZERO {
        _safe_transfer_from(token0, ctx.caller, self_address, amount0_in)?;
    }
    if amount1_in > U256::ZERO {
        _safe_transfer_from(token1, ctx.caller, self_address, amount1_in)?;
    }
    // Transfer output tokens to recipient
    if amount0_out > U256::ZERO {
        _safe_transfer(token0, to, amount0_out)?;
    }
    if amount1_out > U256::ZERO {
        _safe_transfer(token1, to, amount1_out)?;
    }

    let balance0_adjusted = _get_token_balance(token0, self_address)? * FEE_DENOMINATOR - amount0_in * FEE_RATE;
    let balance1_adjusted = _get_token_balance(token1, self_address)? * FEE_DENOMINATOR - amount1_in * FEE_RATE;
    if balance0_adjusted * balance1_adjusted < reserve0 * reserve1 * FEE_DENOMINATOR * FEE_DENOMINATOR {
        return Err(LyquidError::LyquidRuntime(
            "INSUFFICIENT_INVARIANT: Constant product formula violated (x*y=k)".into(),
        ));
    }
    _update(self_address, &mut ctx.network)?;
    lyquid::println!("Swapped: {} token0 and {} token1 to {}", amount0_out, amount1_out, to);
    Ok(true)
}

#[lyquid::method::network(export = ethereum)]
fn getPrice0(ctx: &_) -> LyquidResult<U256> {
    Ok(*ctx.network.reserve1 * uint!(1000000000000000000_U256) / *ctx.network.reserve0)
}

#[lyquid::method::network(export = ethereum)]
fn getPrice1(ctx: &_) -> LyquidResult<U256> {
    Ok(*ctx.network.reserve0 * uint!(1000000000000000000_U256) / *ctx.network.reserve1)
}

#[lyquid::method::network(export = ethereum)]
fn totalSupply(ctx: &_) -> LyquidResult<U256> {
    Ok(*ctx.network.total_supply)
}

#[lyquid::method::network(export = ethereum)]
fn balanceOf(ctx: &_, account: Address) -> LyquidResult<U256> {
    Ok(*ctx.network.balances.get(&account).unwrap_or(&U256::ZERO))
}
