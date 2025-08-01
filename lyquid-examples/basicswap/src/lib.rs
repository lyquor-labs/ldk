// =============================================================================
// Lyquid Basic Swap Implementation
// =============================================================================
//
// This module implements a Uniswap V2-style Automated Market Maker (AMM) in the Lyquid framework.
// It follows the constant product formula (x * y = k) for token swaps and liquidity provision.
//
// Features:
// - Automated Market Maker with constant product formula
// - Liquidity provision and removal (LP tokens)
// - Token swapping with 0.3% fees
// - Safe transfer functions with error handling
// - Price calculation
// - Minimum liquidity requirement (1000 wei)
//
// =============================================================================

#![feature(allocator_api)]
use lyquid::runtime::*;

mod utils;
use utils::{sqrt, min};

// Written by following Solidity code in
// https://github.com/Uniswap/v2-core/blob/master/contracts/UniswapV2Pair.sol

/// Minimum liquidity locked in the contract forever (sent to zero address)
const MINIMUM_LIQUIDITY: U256 = uint!(1000_U256);

/// Fee taken on swaps: 0.3% = 3/1000
const FEE_RATE: U256 = uint!(3_U256);
const FEE_DENOMINATOR: U256 = uint!(1000_U256);

fn _safe_transfer(
    token: LyquidID,
    to: Address,
    amount: U256
) -> LyquidResult<()> {
    if amount == U256::ZERO {
        return Ok(());
    }

    let result = call!((token).transfer(to: Address = to, amount: U256 = amount) -> (success: LyquidResult<bool>))?;
    if !result.success? {
        return Err(LyquidError::LyquidRuntime("TRANSFER_FAILED".into()));
    }

    Ok(())
}

fn _safe_transfer_from(
    token: LyquidID,
    from: Address,
    to: Address,
    amount: U256
) -> LyquidResult<()> {
    if amount == U256::ZERO {
        return Ok(());
    }

    let result = call!((token).transferFrom(from: Address = from, to: Address = to, value: U256 = amount) -> (success: LyquidResult<bool>))?;
    if !result.success? {
        return Err(LyquidError::LyquidRuntime("TRANSFER_FROM_FAILED".into()));
    }
    Ok(())
}

fn _get_token_balance(token: LyquidID, account: Address) -> LyquidResult<U256> {
    let result = call!((token).balanceOf(account: Address = account) -> (balance: LyquidResult<U256>))?;
    Ok(result.balance?) 
}

/// Returns the output amount for a given input amount
/// Formula: amountOut = (amountIn * 997 * reserveOut) / (reserveIn * 1000 + amountIn * 997)
/// The 997/1000 factor accounts for the 0.3% fee
fn get_amount_out(amount_in: U256, reserve_in: U256, reserve_out: U256) -> LyquidResult<U256> {
    if amount_in == U256::ZERO {
        return Err(LyquidError::LyquidRuntime("INSUFFICIENT_INPUT_AMOUNT".into()));
    }
    if reserve_in == U256::ZERO || reserve_out == U256::ZERO {
        return Err(LyquidError::LyquidRuntime("INSUFFICIENT_LIQUIDITY".into()));
    }
    
    let amount_in_with_fee = amount_in * (FEE_DENOMINATOR - FEE_RATE);
    let numerator = amount_in_with_fee * reserve_out;
    let denominator = reserve_in * FEE_DENOMINATOR + amount_in_with_fee;
    
    Ok(numerator / denominator)
}

/// Calculate the required input amount for a desired output amount
/// Formula: amountIn = (reserveIn * amountOut * 1000) / ((reserveOut - amountOut) * 997) + 1
fn get_amount_in(amount_out: U256, reserve_in: U256, reserve_out: U256) -> LyquidResult<U256> {
    if amount_out == U256::ZERO {
        return Err(LyquidError::LyquidRuntime("INSUFFICIENT_OUTPUT_AMOUNT".into()));
    }
    if reserve_in == U256::ZERO || reserve_out == U256::ZERO {
        return Err(LyquidError::LyquidRuntime("INSUFFICIENT_LIQUIDITY".into()));
    }
    if amount_out >= reserve_out {
        return Err(LyquidError::LyquidRuntime("INSUFFICIENT_LIQUIDITY".into()));
    }
    
    let numerator = reserve_in * amount_out * FEE_DENOMINATOR;
    let denominator = (reserve_out - amount_out) * (FEE_DENOMINATOR - FEE_RATE);
    
    Ok(numerator / denominator + uint!(1_U256))
}

/// Updates reserves and synchronizes with actual token balances
/// This is called after every liquidity or swap operation
fn _update(self_address: Address, state: &mut __lyquid::NetworkState) -> LyquidResult<()> {
    let balance0 = _get_token_balance(*state.token0, self_address)?;
    let balance1 = _get_token_balance(*state.token1, self_address)?;
    
    *state.reserve0 = balance0;
    *state.reserve1 = balance1;
    
    lyquid::println!("Updated reserves: {} {}", balance0, balance1);
    Ok(())
}

/// mint LP tokens
fn _mint(
    state: &mut __lyquid::NetworkState,
    to: Address,
    amount: U256
) -> LyquidResult<()> {
    // Increase total supply
    *state.total_supply += amount;
    
    // Increase recipient's balance
    let current_balance = state.balances.get(&to).unwrap_or(&U256::ZERO).clone();
    state.balances.insert(to, current_balance + amount);
    
    lyquid::println!("Minted {} LP tokens to {}", amount, to);
    Ok(())
}

/// burn LP tokens
fn _burn(
    state: &mut __lyquid::NetworkState,
    from: Address,
    amount: U256
) -> LyquidResult<()> {
    // Check sufficient balance
    let current_balance = state.balances.get(&from).unwrap_or(&U256::ZERO).clone();
    if current_balance < amount {
        return Err(LyquidError::LyquidRuntime("INSUFFICIENT_BALANCE".into()));
    }
    
    // Decrease sender's balance
    state.balances.insert(from, current_balance - amount);
    
    // Decrease total supply
    *state.total_supply -= amount;
    
    lyquid::println!("Burned {} LP tokens from {}", amount, from);
    Ok(())
}

lyquid::state! {
    network token0: LyquidID = LyquidID::default();
    network token1: LyquidID = LyquidID::default();
    
    // Current reserves of each token
    network reserve0: U256 = U256::ZERO;
    network reserve1: U256 = U256::ZERO;
    
    // LP token tracking
    network total_supply: U256 = U256::ZERO;
    network balances: network::HashMap<Address, U256> = network::new_hashmap();
}

lyquid::method! {
    // Initialize the pair with two token addresses
    constructor(&mut ctx, _token0: RequiredLyquid, _token1: RequiredLyquid) {
        *ctx.network.token0 = _token0.0;
        *ctx.network.token1 = _token1.0;
        
        lyquid::println!("BasicSwap Pair initialized: token0={}, token1={}", 
                         ctx.network.token0, ctx.network.token1);
    }

    // Add liquidity to the pool, returns the amount of LP tokens minted
    network fn mint(&mut ctx, to: Address) -> LyquidResult<U256> {
        if to == Address::ZERO {
            return Err(LyquidError::LyquidRuntime("INVALID_TO_ADDRESS".into()));
        }

        // Calculate liquidity based on transferred tokens
        let reserve0 = *ctx.network.reserve0;
        let reserve1 = *ctx.network.reserve1;

        let (_, lyquid_id) = lyquor_api::whoami()?;
        let self_address: Address = lyquid_id.into();
        let balance0 = _get_token_balance(*ctx.network.token0, self_address)?;
        let balance1 = _get_token_balance(*ctx.network.token1, self_address)?;

        if balance0 <= reserve0 || balance1 <= reserve1 {
            return Err(LyquidError::LyquidRuntime("INSUFFICIENT_BALANCE_FOR_MIN".into()));
        }

        let amount0 = balance0 - reserve0;
        let amount1 = balance1 - reserve1;

        let liquidity = if *ctx.network.total_supply == U256::ZERO {
            // First liquidity provision - use geometric mean minus minimum liquidity
            let initial_liquidity = sqrt(amount0 * amount1);
            if initial_liquidity <= MINIMUM_LIQUIDITY {
                return Err(LyquidError::LyquidRuntime("INSUFFICIENT_LIQUIDITY_MINTED".into()));
            }
            
            // Lock minimum liquidity forever by minting to zero address
            _mint(&mut ctx.network, Address::ZERO, MINIMUM_LIQUIDITY)?;
            
            initial_liquidity - MINIMUM_LIQUIDITY
        } else {
            // Subsequent liquidity provision - use proportion of existing supply
            let liquidity0 = amount0 * *ctx.network.total_supply / reserve0;
            let liquidity1 = amount1 * *ctx.network.total_supply / reserve1;
            min(liquidity0, liquidity1)
        };
        
        if liquidity == U256::ZERO {
            return Err(LyquidError::LyquidRuntime("INSUFFICIENT_LIQUIDITY_MINTED".into()));
        }
        
        // Mint LP tokens to the liquidity provider
        _mint(&mut ctx.network, to, liquidity)?;
        
        // Update reserves to current balances
        *ctx.network.reserve0 = balance0;
        *ctx.network.reserve1 = balance1;
        
        lyquid::println!("Minted {} LP tokens to {} (amounts: {} token0, {} token1)", 
                         liquidity, to, amount0, amount1);
        Ok(liquidity)
    }

    // Remove liquidity from the pool
    network fn burn(&mut ctx, to: Address, liquidity: U256) -> LyquidResult<bool> {
        if to == Address::ZERO {
            return Err(LyquidError::LyquidRuntime("INVALID_TO_ADDRESS".into()));
        }
        
        let reserve0 = *ctx.network.reserve0;
        let reserve1 = *ctx.network.reserve1;
        
        if liquidity == U256::ZERO {
            return Err(LyquidError::LyquidRuntime("INSUFFICIENT_LIQUIDITY_BURNED".into()));
        }
        
        // Calculate proportional amounts to return
        let amount0 = liquidity * reserve0 / *ctx.network.total_supply;
        let amount1 = liquidity * reserve1 / *ctx.network.total_supply;
        
        if amount0 == U256::ZERO || amount1 == U256::ZERO {
            return Err(LyquidError::LyquidRuntime("INSUFFICIENT_LIQUIDITY_BURNED".into()));
        }
        
        // Burn LP tokens from the user
        _burn(&mut ctx.network, ctx.caller, liquidity)?;
        
        // Transfer tokens back to user
        _safe_transfer(*ctx.network.token0, to, amount0)?;
        _safe_transfer(*ctx.network.token1, to, amount1)?;
        
        let (_, lyquid_id) = lyquor_api::whoami()?;
        _update(lyquid_id.into(), &mut ctx.network)?;
        
        lyquid::println!("Burned {} LP tokens from {}, returned {} token0 and {} token1", 
                         liquidity, ctx.caller, amount0, amount1);
        Ok(true)
    }

    // Swap tokens, returns true if successful
    network fn swap(&mut ctx, amount0_out: U256, amount1_out: U256, to: Address, amount0_in: U256, amount1_in: U256) -> LyquidResult<bool> {
        if amount0_out == U256::ZERO && amount1_out == U256::ZERO {
            return Err(LyquidError::LyquidRuntime("INSUFFICIENT_OUTPUT_AMOUNT".into()));
        }
        
        let reserve0 = *ctx.network.reserve0;
        let reserve1 = *ctx.network.reserve1;
        let token0 = *ctx.network.token0;
        let token1 = *ctx.network.token1;
        let (_, lyquid_id) = lyquor_api::whoami()?;
        let self_address: Address = lyquid_id.into();
        
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
        
        //Verify K constraint (constant product formula)
        let balance0 = _get_token_balance(token0, self_address)?;
        let balance1 = _get_token_balance(token1, self_address)?;
        
        let balance0_adjusted = balance0 * FEE_DENOMINATOR - amount0_in * FEE_RATE;
        let balance1_adjusted = balance1 * FEE_DENOMINATOR - amount1_in * FEE_RATE;
        
        if balance0_adjusted * balance1_adjusted < reserve0 * reserve1 * FEE_DENOMINATOR * FEE_DENOMINATOR {
            return Err(LyquidError::LyquidRuntime("INSUFFICIENT_INVARIANT: Constant product formula violated (x*y=k)".into()));
        }
        
        _update(self_address, &mut ctx.network)?;
        
        lyquid::println!("Swapped: {} token0 and {} token1 to {}", amount0_out, amount1_out, to);
        Ok(true)
    }

    // Calculate output amount for a given input
    network fn getAmountOut(&ctx, amount_in: U256, reserve_in: U256, reserve_out: U256) -> LyquidResult<U256> {
        get_amount_out(amount_in, reserve_in, reserve_out)
    }

    // Calculate required input amount for a desired output
    network fn getAmountIn(&ctx, amount_out: U256, reserve_in: U256, reserve_out: U256) -> LyquidResult<U256> {
        get_amount_in(amount_out, reserve_in, reserve_out)
    }

    // Get the current price of token0 in terms of token1,
    // returns reserve1/reserve0 * 10^18 for precision
    network fn getPrice0(&ctx) -> LyquidResult<U256> {
        if *ctx.network.reserve0 == U256::ZERO {
            return Err(LyquidError::LyquidRuntime("INSUFFICIENT_LIQUIDITY".into()));
        }
        Ok(*ctx.network.reserve1 * uint!(1000000000000000000_U256) / *ctx.network.reserve0)
    }

    // Get the current price of token1 in terms of token0,
    // returns reserve0/reserve1 * 10^18 for precision
    network fn getPrice1(&ctx) -> LyquidResult<U256> {
        if *ctx.network.reserve1 == U256::ZERO {
            return Err(LyquidError::LyquidRuntime("INSUFFICIENT_LIQUIDITY".into()));
        }
        Ok(*ctx.network.reserve0 * uint!(1000000000000000000_U256) / *ctx.network.reserve1)
    }

    // Get LP token total supply
    network fn totalSupply(&ctx) -> LyquidResult<U256> {
        Ok(ctx.network.total_supply.clone())
    }

    // Get LP token balance of an address
    network fn balanceOf(&ctx, account: Address) -> LyquidResult<U256> {
        Ok(ctx.network.balances.get(&account).unwrap_or(&U256::ZERO).clone())
    }
} 