pragma solidity ^0.8;

import "forge-std/Test.sol";
import "forge-std/console2.sol";
import "../lib/solidity-BigNumber/src/BigNumbers.sol";
import {BLS} from "../src/BLS.sol";

// This is a Foundry contract written in Solidity, to test
// the BLS.sol library, via the the test contract of solbls.test.sol

// Many of the test cases are pulled from bn254_reference_transformed.json, generated using SAGE MATH

// json['G1_signatures'] list of format {'x': uint256, 'y': uint256}
// json['G2_public_keys'] list of format {'x': {'c0': uint256, 'c1': uint256}, 'y': {'c0': uint256, 'c1': uint256}}
// json['E2_non_G2'] list of format {'x': {'c0': uint256, 'c1': uint256}, 'y': {'c0': uint256, 'c1': uint256}}
// json['private_keys'] list of format uint256
// json['svdw'] list of format {'i': uint256, 'x': uint256, 'y': uint256}

// A reference Hardhat implementation of is found at BLS.ts
// BLS.ts relies upon a few functions from utils.ts

// bn254_reference.json stores all but 'private_keys' as STRINGS,
// by default. Fortunately, Foundry exposes a parseJSON() set of
// functions, to effectively read and feed these into the contract.

contract BLSUnitTest is Test {
    // EC Test Cases
    uint256[][] e2_non_g2;
    uint256[][] g1_signatures;
    uint256[][] g2_public_keys;
    uint256[][] svdw;

    // Hashing and Padding Variables
    uint256 zero = 0;
    string domain = "BLS_SIG_BN254G1_XMD:KECCAK-256_SSWU_RO_NUL_";
    bytes zpad = abi.encodePacked(abi.encodePacked(zero, zero, zero, zero), uint64(0));
    bytes field_order = hex"30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47";
    // BLSTest bls = new BLSTest();

    // Test Case Read
    string root = vm.projectRoot();
    string json = vm.readFile(string.concat(root, "/test/bn254_reference_transformed.json"));
    uint256[] private_keys = vm.parseJsonUintArray(json, ".private_keys");

    function setUp() public noGasMetering {
        for (uint256 i = 0; i < 1000; i++) {
            string memory strNum = vm.toString(i);
            string memory left = string.concat("[", strNum);
            string memory lookup = string.concat(left, "]");
            uint256[] memory rawG1 = vm.parseJsonUintArray(json, string.concat(".G1_signatures", lookup));
            uint256[] memory rawG2 = vm.parseJsonUintArray(json, string.concat(".G2_public_keys", lookup));
            uint256[] memory rawE2 = vm.parseJsonUintArray(json, string.concat(".E2_non_G2", lookup));
            uint256[] memory rawSVDW = vm.parseJsonUintArray(json, string.concat(".svdw", lookup));
            g1_signatures.push(rawG1);
            g2_public_keys.push(rawG2);
            e2_non_g2.push(rawE2);
            svdw.push(rawSVDW);
        }
    }

    function testExpand_Message(bytes memory expMsg) public view {
        // Hashing string to element of the field should work
        uint8 outputLen = 96;
        uint8 domainLength = 43;

        bytes memory b_0 = abi.encodePacked(
            zpad, expMsg, uint8(outputLen >> 8), uint8(outputLen & 255), uint8(0), bytes(domain), domainLength
        );
        bytes32 b_0_hashed = keccak256(b_0);

        // in BLS.ts this step is done in a for loop
        bytes memory b_i = abi.encodePacked(b_0_hashed, uint8(1), bytes(domain), domainLength);
        bytes32 b_i_hashed = keccak256(b_i);
        bytes memory newb_i = abi.encodePacked(b_i_hashed ^ b_0_hashed, uint8(2), bytes(domain), domainLength);
        bytes32 newHash = keccak256(newb_i);
        bytes memory newb_ii = abi.encodePacked(newHash ^ b_0_hashed, uint8(3), bytes(domain), domainLength);
        bytes32 secondHash = keccak256(newb_ii);

        // assert equivalence between our implementation and the library
        assert(
            keccak256(BLS.expandMsgTo96(bytes(domain), expMsg))
                == keccak256(abi.encodePacked(b_i_hashed, newHash, secondHash))
        );
    }

    function expand_message(bytes memory message) private view returns (bytes memory) {
        // same as above, but used by testHash_to_field, privately
        uint8 outputLen = 96;
        uint8 domainLength = 43;

        bytes memory b_0 = abi.encodePacked(
            zpad, message, uint8(outputLen >> 8), uint8(outputLen & 255), uint8(0), bytes(domain), domainLength
        );
        bytes32 b_0_hashed = keccak256(b_0);

        bytes memory b_i = abi.encodePacked(b_0_hashed, uint8(1), bytes(domain), domainLength);
        bytes32 b_i_hashed = keccak256(b_i);
        bytes memory newb_i = abi.encodePacked(b_i_hashed ^ b_0_hashed, uint8(2), bytes(domain), domainLength);
        bytes32 newHash = keccak256(newb_i);
        bytes memory newb_ii = abi.encodePacked(newHash ^ b_0_hashed, uint8(3), bytes(domain), domainLength);
        bytes32 secondHash = keccak256(newb_ii);

        return abi.encodePacked(b_i_hashed, newHash, secondHash);
    }

    function testHash_to_field(bytes memory rands) public view {
        // Hashing string to two elements of the field should work
        bytes memory expanded = expand_message(rands);
        bytes memory ord = hex"30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47";
        bytes memory left = new bytes(48);
        for (uint256 i = 0; i < 48; i++) {
            left[i] = expanded[i];
        }
        bytes memory right = new bytes(48);
        for (uint256 l = 0; l < 48; l++) {
            right[l] = expanded[l + 48];
        }
        BigNumber memory leftBig = BigNumbers.init(left, false);
        BigNumber memory rightBig = BigNumbers.init(right, false);
        BigNumber memory fieldOrder = BigNumbers.init(ord, false);
        BigNumber memory resOne = BigNumbers.mod(leftBig, fieldOrder);
        BigNumber memory resTwo = BigNumbers.mod(rightBig, fieldOrder);
        uint256[2] memory p = BLS.hashToField(bytes(domain), rands);
        assert(keccak256(abi.encodePacked(p[0])) == keccak256(resOne.val));
        assert(keccak256(abi.encodePacked(p[1])) == keccak256(resTwo.val));
    }

    function testG1() public noGasMetering {
        // Check that G1=[r]E(Fp) reference points are correctly accepted as signatures
        for (uint256 i = 0; i < 1000; i++) {
            uint256[] memory iq = g1_signatures[i];
            uint256[2] memory iqOw = [iq[0], iq[1]];
            assert(BLS.isValidSignature(iqOw));
        }
    }

    function testG2() public noGasMetering {
        // Check that G2=[r]E'(Fp2) reference points are correctly accepted as pubkeys
        for (uint256 i = 0; i < 1000; i++) {
            uint256[] memory iq = g2_public_keys[i];
            uint256[4] memory iqOw = [iq[0], iq[1], iq[2], iq[3]];
            assert(BLS.isValidPublicKey(iqOw));
        }
    }

    function testFail_E2noG2() public noGasMetering {
        // Check that E'(Fp2) reference points that are not in the r-torsion are correctly rejected from G2
        for (uint256 i = 0; i < 1000; i++) {
            uint256[] memory iq = e2_non_g2[i];
            uint256[4] memory iqOw = [iq[0], iq[1], iq[2], iq[3]];
            assert(BLS.isValidPublicKey(iqOw) == false);
        }
    }

    function testSVDW() public noGasMetering {
        // Verify SVDW implementation
        for (uint256 i = 0; i < 1000; i++) {
            uint256[] memory iq = svdw[i];
            uint256[2] memory targets = BLS.mapToPoint(iq[0]);
            assert(BLS.isOnCurveG1(targets));
            assert(targets[0] == iq[1]);
            assert(targets[1] == iq[2]);
        }
    }

    function testLibraryConsistent() public noGasMetering {
        // Check internal consistency of the library
        uint256[2] memory pt = BLS.hashToPoint(bytes(domain), bytes("Hello world!"));
        assert(BLS.isOnCurveG1(pt));
        for (uint256 i = 0; i < 1000; i++) {
            uint256[] memory iq = g1_signatures[i];
            uint256[] memory iqTwo = g2_public_keys[i];
            uint256[2] memory iqOw = [iq[0], iq[1]];
            uint256[4] memory iqTwoOw = [iqTwo[0], iqTwo[1], iqTwo[2], iqTwo[3]];
            assert(BLS.isValidPublicKey(iqTwoOw));
            assert(BLS.isValidSignature(iqOw));
            (bool pairingSuccess, bool callSuccess) = BLS.verifySingle(iqOw, iqTwoOw, pt);
            if (callSuccess) {
                assert(pairingSuccess);
            } else {
                assert(pairingSuccess == false);
            }
        }
    }

    function testLibConsistentTwo() public noGasMetering {
        // Check internal consistency of the library 2
        uint256[2] memory pt = BLS.hashToPoint(bytes(domain), bytes("Hello world!"));
        for (uint256 i = 0; i < 1000; i++) {
            uint256[] memory iq = g1_signatures[i];
            uint256[] memory iqTwo = e2_non_g2[i];
            uint256[2] memory iqOw = [iq[0], iq[1]];
            uint256[4] memory iqTwoOw = [iqTwo[0], iqTwo[1], iqTwo[2], iqTwo[3]];
            assert(BLS.isValidPublicKey(iqTwoOw));
            assert(BLS.isValidSignature(iqOw));
            (bool pairingSuccess, bool callSuccess) = BLS.verifySingle(iqOw, iqTwoOw, pt);
            if (callSuccess) {
                assert(pairingSuccess);
            } else {
                assert(pairingSuccess == false);
            }
        }
    }
}
