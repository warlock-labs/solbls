// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

/**
 * @dev This file contains two libraries: ModexpInverse and ModexpSqrt
 *      Both use the `modexp` precompile at 0x05 for efficient computation
 *      of modular exponentiation operations on the BN254 curve's base field.
 *      It should be noted that these two libraries accept inputs that are
 *      larger than the modulus, and reduces accordingly.
 */

/**
 * @title Compute Inverse by Modular Exponentiation
 * @notice Compute base^(N - 2) mod N$.
 * Where     N = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
 * and   N - 2 = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45.
 * It should be noted here that the inverse function itself works by the fact that,
 * by Fermat's little theorem, $x^{-1} mod N = x^{N-2} mod N$, and by this merit,
 * consistent with the specification of `inv0` from RFC 9380, an input of 0 will
 * return 0 from this calculation, despite the modular inverse of 0 not existing,
 * consistent with the specification of EIP-198 that defines this precompile.
 */
library ModexpInverse {
    function run(uint256 base) internal view returns (uint256 result) {
        bool success;
        // slither-disable-next-line assembly
        assembly {
            let memPtr := mload(0x40)
            mstore(memPtr, 0x20)
            mstore(add(memPtr, 0x20), 0x20)
            mstore(add(memPtr, 0x40), 0x20)
            mstore(add(memPtr, 0x60), base)
            mstore(add(memPtr, 0x80), 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45)
            mstore(add(memPtr, 0xa0), 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47)
            success := staticcall(sub(gas(), 2000), 0x05, memPtr, 0xc0, memPtr, 0x20)
            result := mload(memPtr)
        }
    }
}

/**
 * @title Compute Square Root by Modular Exponentiation
 *     @notice Compute $input^{(N + 1) / 4} mod N$.
 *     Where           N = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
 *     and   (N + 1) / 4 = 0xc19139cb84c680a6e14116da060561765e05aa45a1c72a34f082305b61f3f52
 *     It should be noted that if the base's Legendre symbol is 1, $s^2 mod N = x$, yet if
 *     it is -1, $s$ is not a modular sqrt of x, though $x$ also does not have a sqrt, as $s$
 *     is a sqrt of $-x$. This fact, combined with the acceptance of inputs larger that the
 *     modulus means that the check `mulmod(x, x, N) == xx`, where `x = ModexpSqrt.run(xx)`
 *     will always be false if `xx >= N`, or if there is no sqrt existing mod N. Checks
 *     on this point are done in the main `sqrt` function in `BLS.sol`, and therefore
 *     users should only interact with that function, not this library itself, so that the
 *     user need not be aware of this subtle point.
 */
library ModexpSqrt {
    function run(uint256 base) internal view returns (uint256 result) {
        bool success;
        // slither-disable-next-line assembly
        assembly {
            let memPtr := mload(0x40)
            mstore(memPtr, 0x20)
            mstore(add(memPtr, 0x20), 0x20)
            mstore(add(memPtr, 0x40), 0x20)
            mstore(add(memPtr, 0x60), base)
            mstore(add(memPtr, 0x80), 0xc19139cb84c680a6e14116da060561765e05aa45a1c72a34f082305b61f3f52)
            mstore(add(memPtr, 0xa0), 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47)
            success := staticcall(sub(gas(), 2000), 0x05, memPtr, 0xc0, memPtr, 0x20)
            result := mload(memPtr)
        }
    }
}
