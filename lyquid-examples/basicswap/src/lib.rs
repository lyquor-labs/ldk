// =============================================================================
// Lyquid Basic Swap Implementation
//
// This module implements a Uniswap V2-style Automated Market Maker (AMM) in the Lyquid framework.
// It follows the constant product formula (x * y = k) for token swaps and liquidity provision.
// =============================================================================

use lyquid::prelude::*;

mod utils;
use utils::{min, sqrt};

// Core AMM logic follows Uniswap V2 Pair (Solidity):
// https://github.com/Uniswap/v2-core/blob/master/contracts/UniswapV2Pair.sol
// Quote math and slippage-style flows are inspired by Uniswap V2 periphery:
// - Library math: https://github.com/Uniswap/v2-periphery/blob/master/contracts/libraries/UniswapV2Library.sol
// - Router flows: https://github.com/Uniswap/v2-periphery/blob/master/contracts/UniswapV2Router02.sol

/// Minimum liquidity locked in the contract forever (sent to zero address)
const MINIMUM_LIQUIDITY: U256 = uint!(1000_U256);

/// Fee taken on swaps: 0.3% = 3/1000
const FEE_RATE: U256 = uint!(3_U256);
const FEE_DENOMINATOR: U256 = uint!(1000_U256);
const FEE_FACTOR: U256 = uint!(997_U256);
/// Basis points denominator (100% = 10_000 bps)
const BPS_DENOMINATOR: U256 = uint!(10_000_U256);

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

fn _get_amount_out(amount_in: U256, reserve_in: U256, reserve_out: U256) -> LyquidResult<U256> {
    if amount_in == U256::ZERO {
        return Err(LyquidError::LyquidRuntime("INSUFFICIENT_INPUT_AMOUNT".into()));
    }
    if reserve_in == U256::ZERO || reserve_out == U256::ZERO {
        return Err(LyquidError::LyquidRuntime("INSUFFICIENT_LIQUIDITY".into()));
    }
    let amount_in_with_fee = amount_in * FEE_FACTOR;
    let numerator = amount_in_with_fee * reserve_out;
    let denominator = reserve_in * FEE_DENOMINATOR + amount_in_with_fee;
    let amount_out = numerator / denominator;
    if amount_out == U256::ZERO {
        return Err(LyquidError::LyquidRuntime("INSUFFICIENT_OUTPUT_AMOUNT".into()));
    }
    Ok(amount_out)
}

fn _get_amount_in(amount_out: U256, reserve_in: U256, reserve_out: U256) -> LyquidResult<U256> {
    if amount_out == U256::ZERO {
        return Err(LyquidError::LyquidRuntime("INSUFFICIENT_OUTPUT_AMOUNT".into()));
    }
    if reserve_in == U256::ZERO || reserve_out == U256::ZERO || amount_out >= reserve_out {
        return Err(LyquidError::LyquidRuntime("INSUFFICIENT_LIQUIDITY".into()));
    }
    let numerator = reserve_in * amount_out * FEE_DENOMINATOR;
    let denominator = (reserve_out - amount_out) * FEE_FACTOR;
    Ok(numerator / denominator + uint!(1_U256))
}

fn _slippage_bps(slippage_bps: u32) -> LyquidResult<U256> {
    if slippage_bps > 10_000 {
        return Err(LyquidError::LyquidRuntime("SLIPPAGE_TOO_HIGH".into()));
    }
    Ok(U256::from(slippage_bps))
}

fn _min_amount_out(quote_out: U256, slippage_bps: u32) -> LyquidResult<U256> {
    let bps = _slippage_bps(slippage_bps)?;
    Ok(quote_out * (BPS_DENOMINATOR - bps) / BPS_DENOMINATOR)
}

fn _max_amount_in(quote_in: U256, slippage_bps: u32) -> LyquidResult<U256> {
    let bps = _slippage_bps(slippage_bps)?;
    Ok(quote_in * (BPS_DENOMINATOR + bps) / BPS_DENOMINATOR)
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

fn _swap_internal(
    ctx: &mut __lyquid::NetworkContext, amount0_out: U256, amount1_out: U256, to: Address, amount0_in: U256,
    amount1_in: U256,
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

state! {
    network token0: LyquidID = LyquidID::default();
    network token1: LyquidID = LyquidID::default();
    network reserve0: U256 = U256::ZERO;
    network reserve1: U256 = U256::ZERO;
    network total_supply: U256 = U256::ZERO;
    network balances: HashMap<Address, U256> = new_hashmap();
}

#[method::network(export = eth)]
fn constructor(ctx: &mut _, _token0: RequiredLyquid, _token1: RequiredLyquid) {
    *ctx.network.token0 = _token0.0;
    *ctx.network.token1 = _token1.0;
}

#[method::network(export = eth)]
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

#[method::network(export = eth)]
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

#[method::network(export = eth)]
fn swap(
    ctx: &mut _, amount0_out: U256, amount1_out: U256, to: Address, amount0_in: U256, amount1_in: U256,
) -> LyquidResult<bool> {
    _swap_internal(&mut ctx, amount0_out, amount1_out, to, amount0_in, amount1_in)
}

/// Swap with exact input amount and slippage (bps). Returns actual output amount.
/// `token0_to_token1`: set true to swap token0 for token1 (token0 is input, token1 is output);
/// set false for otherwise.
#[method::network(export = eth)]
fn swapExactInWithSlippage(
    ctx: &mut _, token0_to_token1: bool, amount_in: U256, slippage_bps: u32, to: Address,
) -> LyquidResult<U256> {
    let (reserve_in, reserve_out) = if token0_to_token1 {
        (*ctx.network.reserve0, *ctx.network.reserve1)
    } else {
        (*ctx.network.reserve1, *ctx.network.reserve0)
    };
    let quote_out = _get_amount_out(amount_in, reserve_in, reserve_out)?;
    let min_out = _min_amount_out(quote_out, slippage_bps)?;
    if quote_out < min_out {
        return Err(LyquidError::LyquidRuntime("INSUFFICIENT_OUTPUT_AMOUNT".into()));
    }
    let (amount0_in, amount1_in, amount0_out, amount1_out) = if token0_to_token1 {
        (amount_in, U256::ZERO, U256::ZERO, quote_out)
    } else {
        (U256::ZERO, amount_in, quote_out, U256::ZERO)
    };
    _swap_internal(&mut ctx, amount0_out, amount1_out, to, amount0_in, amount1_in)?;
    Ok(quote_out)
}

/// Swap with exact output amount and slippage (bps). Returns actual input amount.
/// `token0_to_token1`: set true to swap token0 for token1 (token0 is input, token1 is output);
/// set false for otherwise.
#[method::network(export = eth)]
fn swapExactOutWithSlippage(
    ctx: &mut _, token0_to_token1: bool, amount_out: U256, slippage_bps: u32, to: Address,
) -> LyquidResult<U256> {
    let (reserve_in, reserve_out) = if token0_to_token1 {
        (*ctx.network.reserve0, *ctx.network.reserve1)
    } else {
        (*ctx.network.reserve1, *ctx.network.reserve0)
    };
    let quote_in = _get_amount_in(amount_out, reserve_in, reserve_out)?;
    let max_in = _max_amount_in(quote_in, slippage_bps)?;
    if quote_in > max_in {
        return Err(LyquidError::LyquidRuntime("EXCESSIVE_INPUT_AMOUNT".into()));
    }
    let (amount0_in, amount1_in, amount0_out, amount1_out) = if token0_to_token1 {
        (quote_in, U256::ZERO, U256::ZERO, amount_out)
    } else {
        (U256::ZERO, quote_in, amount_out, U256::ZERO)
    };
    _swap_internal(&mut ctx, amount0_out, amount1_out, to, amount0_in, amount1_in)?;
    Ok(quote_in)
}

#[method::network(export = eth)]
fn getPrice0(ctx: &_) -> LyquidResult<U256> {
    Ok(*ctx.network.reserve1 * uint!(1000000000000000000_U256) / *ctx.network.reserve0)
}

#[method::network(export = eth)]
fn getPrice1(ctx: &_) -> LyquidResult<U256> {
    Ok(*ctx.network.reserve0 * uint!(1000000000000000000_U256) / *ctx.network.reserve1)
}

#[method::network(export = eth)]
fn totalSupply(ctx: &_) -> LyquidResult<U256> {
    Ok(*ctx.network.total_supply)
}

#[method::network(export = eth)]
fn balanceOf(ctx: &_, account: Address) -> LyquidResult<U256> {
    Ok(*ctx.network.balances.get(&account).unwrap_or(&U256::ZERO))
}
