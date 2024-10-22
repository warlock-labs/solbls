// SPDX-License-Identifier: MIT
pragma solidity >=0.8.23;

import {ModexpInverse, ModexpSqrt} from "./ModExp.sol";

/// @title  Boneh–Lynn–Shacham (BLS) signature scheme on Barreto-Naehrig 254 bit curve (BN-254)
/// @notice We use BLS signature aggregation to reduce the size of signature data to store on chain.
/// @dev We use G1 points for signatures and messages, and G2 points for public keys
/// @dev Adapted from https://github.com/thehubbleproject/hubble-contracts
/// @dev Leveraging additional documentation from https://github.com/kevincharm/bls-bn254/blob/master/contracts/BLS.sol
/// @dev A long form article: https://hackmd.io/@liangcc/bls-solidity
/// @dev This contract has been audited by Zellic, and implements all remediations of that report.
library BLS {
    // Field order of BN254 curve
    uint256 private constant N =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Negated generator of G2 (required for pairing checks)
    uint256 private constant N_G2_X1 =
        11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 private constant N_G2_X0 =
        10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 private constant N_G2_Y1 =
        17805874995975841540914202342111839520379459829704422454583296818431106115052;
    uint256 private constant N_G2_Y0 =
        13392588948715843804641432497768002650278120570034223513918757245338268106653;

    // Constants for hash-to-field operations
    // slither-disable-next-line too-many-digits
    uint256 private constant T24 =
        0x1000000000000000000000000000000000000000000000000;
    uint256 private constant MASK24 =
        0xffffffffffffffffffffffffffffffffffffffffffffffff;

    // Curve parameters and constants for Simplified SWU mapping

    /// @notice Param A of BN254
    uint256 private constant A = 0;
    /// @notice Param B of BN254
    uint256 private constant B = 3;
    /// @notice Param Z for SVDW over E
    uint256 private constant Z = 1;
    /// @notice g(Z) where g(x) = x^3 + 3
    uint256 private constant C1 = 0x4;
    /// @notice -Z / 2 (mod N)
    uint256 private constant C2 =
        0x183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea3;
    /// @notice C3 = sqrt(-g(Z) * (3 * Z^2 + 4 * A)) (mod N)
    ///     and sgn0(C3) == 0
    uint256 private constant C3 =
        0x16789af3a83522eb353c98fc6b36d713d5d8d1cc5dffffffa;
    /// @notice 4 * -g(Z) / (3 * Z^2 + 4 * A) (mod N)
    uint256 private constant C4 =
        0x10216f7ba065e00de81ac1e7808072c9dd2b2385cd7b438469602eb24829a9bd;
    /// @notice (N - 1) / 2
    uint256 private constant C5 =
        0x183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea3;

    // Error messages

    error BNAddFailed(uint256[4] input);
    error InvalidFieldElement(uint256 x);
    error MapToPointFailed(uint256 noSqrt);
    error InvalidDSTLength(bytes dst);
    error ModExpFailed(uint256 base, uint256 exponent, uint256 modulus);

    /// @notice Verify a single BLS signature
    /// @param signature The signature to verify (G1 point)
    /// @param pubkey The public key (G2 point)
    /// @param message The message that was signed (G1 point)
    /// @return success True if the pairing check succeeds and if the precompile call to verify the signature succeeds
    function verifySingle(
        uint256[2] memory signature,
        uint256[4] memory pubkey,
        uint256[2] memory message
    ) internal view returns (bool) {
        // Prepare input for the pairing check
        uint256[12] memory input = [
            signature[0],
            signature[1],
            N_G2_X1,
            N_G2_X0,
            N_G2_Y1,
            N_G2_Y0,
            message[0],
            message[1],
            pubkey[1],
            pubkey[0],
            pubkey[3],
            pubkey[2]
        ];
        // Use the SNARKV precompile to verify the pairing
        bool callSuccess;
        uint256[1] memory out;
        // slither-disable-next-line assembly
        assembly {
            callSuccess := staticcall(
                sub(gas(), 2000),
                8,
                input,
                384,
                out,
                0x20
            )
        }
        return (callSuccess && (out[0] != 0));
    }

    /// @notice Hash a message to a point on the BN254 G1 curve
    /// @param domain Domain separation tag
    /// @param message Message to hash
    /// @return A point in G1
    function hashToPoint(
        bytes memory domain,
        bytes memory message
    ) internal view returns (uint256[2] memory) {
        // Hash the message to two field elements
        uint256[2] memory u = hashToField(domain, message);

        // Map each field element to a curve point and add them
        uint256[2] memory p0 = mapToPoint(u[0]);
        uint256[2] memory p1 = mapToPoint(u[1]);
        uint256[4] memory bnAddInput;
        bnAddInput[0] = p0[0];
        bnAddInput[1] = p0[1];
        bnAddInput[2] = p1[0];
        bnAddInput[3] = p1[1];

        bool success;
        // slither-disable-next-line assembly
        assembly {
            // Use the BN_ADD precompile
            success := staticcall(sub(gas(), 2000), 6, bnAddInput, 128, p0, 64)
        }
        if (!success) revert BNAddFailed(bnAddInput);
        return p0;
    }

    //// @notice Check if a given signature is valid (i.e., on the curve)
    /// @param signature The signature to check
    /// @return True if the signature is valid
    function isValidSignature(
        uint256[2] memory signature
    ) internal pure returns (bool) {
        if ((signature[0] >= N) || (signature[1] >= N)) {
            return false;
        } else {
            return isOnCurveG1(signature);
        }
    }

    /// @notice Check if a given public key is valid (i.e., on the curve AND in
    /// the correct r-torsion). The subgroup membership check critically involves
    /// identifying if $[r]Q = O$ for a point $Q$ on the curve defined over the
    /// quadratic extension, and $O$ the point at infinity.
    /// @param publicKey The public key to check
    /// @return True if the public key is valid
    function isValidPublicKey(
        uint256[4] memory publicKey
    ) internal view returns (bool) {
        if (
            (publicKey[0] >= N) ||
            (publicKey[1] >= N) ||
            (publicKey[2] >= N || (publicKey[3] >= N))
        ) {
            return false;
        } else {
            return isElementOfG2(publicKey);
        }
    }

    /// @notice Check if a point is on the G1 curve
    /// @param point The point to check
    /// @return isOnCurve True if the point is on the curve
    function isOnCurveG1(
        uint256[2] memory point
    ) internal pure returns (bool isOnCurve) {
        // slither-disable-next-line assembly
        assembly {
            // Load point coordinates
            let t0 := mload(point)
            let t1 := mload(add(point, 32))
            let t2 := mulmod(t0, t0, N)
            // Check if y^2 = x^3 + 3 (mod N)
            t2 := mulmod(t2, t0, N)
            t2 := addmod(t2, 3, N)
            t1 := mulmod(t1, t1, N)
            isOnCurve := eq(t1, t2)
        }
    }

    /// @notice Check if a point is in G2, namely the r-torsion of the elliptic curve over the quadratic extension. Note
    /// that this necessitates curve membership, which is also checked by the precompile. The verification of a public key
    /// should not be done often given the current expected lifetime of Warlock public keys, which should mitigate
    /// the gas of the precompile static call.
    /// @param point The point to check
    /// @return bool True if the point is in the r-torsion G2
    function isElementOfG2(
        uint256[4] memory point
    ) internal view returns (bool) {
        uint256[6] memory input = [
            0,
            0,
            point[1],
            point[0],
            point[3],
            point[2]
        ];
        bool callSuccess;
        uint256[1] memory out;
        // slither-disable-next-line assembly
        assembly {
            callSuccess := staticcall(
                sub(gas(), 2000),
                8,
                input,
                192,
                out,
                0x20
            )
        }
        return (callSuccess && (out[0] == 1));
    }

    /// @notice Compute the square root of a field element. Note that
    /// because we accept inputs larger than the modulus, simply doing
    /// the check `mulmod(x, x, N) == xx` is ambiguous, as this will always be false
    /// for $xx >= N$. We therefore check for comparison against $xx % N$, as this
    /// creates a boolean purely indicative of the presence of a valid moduluar square
    /// root mod N.
    /// @param xx The element to compute the square root of
    /// @return x The square root
    /// @return hasRoot True if the square root exists
    function sqrt(uint256 xx) internal view returns (uint256 x, bool hasRoot) {
        x = ModexpSqrt.run(xx);
        hasRoot = mulmod(x, x, N) == (xx % N);
    }

    /// @notice Compute the modular multiplicative inverse of a field element
    /// @param a The element to invert
    /// @return The inverse of a
    function inverse(uint256 a) internal view returns (uint256) {
        return ModexpInverse.run(a);
    }

    /// @notice Hash a message to two field elements
    /// @param domain Domain separation tag
    /// @param message Message to hash
    /// @return Two field elements
    function hashToField(
        bytes memory domain,
        bytes memory message
    ) internal pure returns (uint256[2] memory) {
        bytes memory _msg = expandMsgTo96(domain, message);
        uint256 u0;
        uint256 u1;
        uint256 a0;
        uint256 a1;
        // slither-disable-next-line assembly
        assembly {
            // Extract two 48-byte values from the expanded message
            // and reduce them modulo N
            let p := add(_msg, 24)
            u1 := and(mload(p), MASK24)
            p := add(_msg, 48)
            u0 := and(mload(p), MASK24)
            a0 := addmod(mulmod(u1, T24, N), u0, N)
            p := add(_msg, 72)
            u1 := and(mload(p), MASK24)
            p := add(_msg, 96)
            u0 := and(mload(p), MASK24)
            a1 := addmod(mulmod(u1, T24, N), u0, N)
        }
        return [a0, a1];
    }

    /// @notice Expand arbitrary message to 96 pseudorandom bytes, as described
    ///     in rfc9380 section 5.3.1, using H = keccak256.
    /// @param dst Domain separation tag
    /// @param message Message to expand
    function expandMsgTo96(
        bytes memory dst,
        bytes memory message
    ) internal pure returns (bytes memory) {
        uint256 domainLen = dst.length;
        if (domainLen > 255) {
            revert InvalidDSTLength(dst);
        }
        bytes memory zpad = new bytes(136);
        bytes memory b_0 = abi.encodePacked(
            zpad,
            message,
            uint8(0),
            uint8(96),
            uint8(0),
            dst,
            uint8(domainLen)
        );
        bytes32 b0 = keccak256(b_0);

        bytes memory b_i = abi.encodePacked(
            b0,
            uint8(1),
            dst,
            uint8(domainLen)
        );
        bytes32 bi = keccak256(b_i);

        bytes memory out = new bytes(96);
        uint256 ell = 3;
        for (uint256 i = 1; i < ell; i++) {
            b_i = abi.encodePacked(
                b0 ^ bi,
                uint8(1 + i),
                dst,
                uint8(domainLen)
            );
            // slither-disable-next-line assembly
            assembly {
                let p := add(32, out)
                p := add(p, mul(32, sub(i, 1)))
                mstore(p, bi)
            }
            bi = keccak256(b_i);
        }
        // slither-disable-next-line assembly
        assembly {
            let p := add(32, out)
            p := add(p, mul(32, sub(ell, 1)))
            mstore(p, bi)
        }
        return out;
    }

    /// @notice Map field element to E using SvdW
    /// @param u Field element to map
    /// @return p Point on curve
    function mapToPoint(uint256 u) internal view returns (uint256[2] memory p) {
        if (u >= N) revert InvalidFieldElement(u);

        uint256 tv1 = mulmod(mulmod(u, u, N), C1, N);
        uint256 tv2 = addmod(1, tv1, N);
        tv1 = addmod(1, N - tv1, N);
        uint256 tv3 = inverse(mulmod(tv1, tv2, N));
        uint256 tv5 = mulmod(mulmod(mulmod(u, tv1, N), tv3, N), C3, N);
        uint256 x1 = addmod(C2, N - tv5, N);
        uint256 x2 = addmod(C2, tv5, N);
        uint256 tv7 = mulmod(tv2, tv2, N);
        uint256 tv8 = mulmod(tv7, tv3, N);
        uint256 x3 = addmod(Z, mulmod(C4, mulmod(tv8, tv8, N), N), N);

        bool hasRoot;
        p[0] = x1;
        (p[1], hasRoot) = sqrt(g(p[0]));
        if (!hasRoot) {
            p[0] = x2;
            (p[1], hasRoot) = sqrt(g(p[0]));
            if (!hasRoot) {
                p[0] = x3;
                (p[1], hasRoot) = sqrt(g(p[0]));
                if (!hasRoot) revert MapToPointFailed(p[1]);
            }
        }
        if (sgn0(u) != sgn0(p[1])) {
            p[1] = N - p[1];
        }
    }

    /// @return g(x) = y^2 = x^3 + 3
    function g(uint256 x) private pure returns (uint256) {
        return addmod(mulmod(mulmod(x, x, N), x, N), B, N);
    }

    /// @notice Compute the sign of a field element
    /// @dev https://datatracker.ietf.org/doc/html/rfc9380#name-the-sgn0-function
    /// @param x The field element
    /// @return The sign (0 or 1)
    function sgn0(uint256 x) private pure returns (uint256) {
        return x % 2;
    }
}
