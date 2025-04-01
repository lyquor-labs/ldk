use lyquid::prelude::*;

// Written by following Solidity code in
// https://github.com/Uniswap/v2-core/blob/master/contracts/libraries/Math.sol

/// Returns the minimum of two U256 values
pub fn min(a: U256, b: U256) -> U256 {
    if a < b { a } else { b }
}

/// Calculates the square root of a number using binary search
/// Used for calculating LP tokens during initial liquidity provision
pub fn sqrt(y: U256) -> U256 {
    if y > uint!(3_U256) {
        let mut z = y;
        let mut x = y / uint!(2_U256) + uint!(1_U256);
        while x < z {
            z = x;
            x = (y / x + x) / uint!(2_U256);
        }
        z
    } else if y != U256::ZERO {
        uint!(1_U256)
    } else {
        U256::ZERO
    }
}
