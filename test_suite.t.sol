pragma solidity ^0.8;
import "forge-std/Test.sol";
import "forge-std/console2.sol";
import "./Strings.sol";
import "./BigNumber.sol";
import {BLS} from "../src/BLS.sol";
import "../src/test_suite.sol";

// This is a Foundry contract written in Solidity, to test
// the BLS.sol library, via the the test contract of test_suite.sol

// test cases are pulled from bn254_reference.json, generated using SAGE MATH
// a = parseJSON("bn254_reference.json");

// a['G1_signatures'] list of format {'x': uint256, 'y': uint256}
// a['G2_public_keys'] list of format {'x': {'c0': uint256, 'c1': uint256}, 'y': {'c0': uint256, 'c1': uint256}}
// a['E2_non_G2'] list of format {'x': {'c0': uint256, 'c1': uint256}, 'y': {'c0': uint256, 'c1': uint256}}
// a['private_keys'] list of format uint256
// a['svdw'] list of format {'i': uint256, 'x': uint256, 'y': uint256}

// A reference Hardhat implementation of is found at BLS.ts
// BLS.ts relies upon a few functions from utils.ts

// bn254_reference.json stores all but 'private_keys' as STRINGS,
// by default. Fortunately, Foundry exposes a parseJSON() set of
// functions, to effectively read and feed these into the contract.

// TODO(COST FUNCTIONS + HASH_TO_FIELD_TESTER())

/*
struct G1SigPair
{
    uint256 x;
    uint256 y;
}

struct G2PubKeys
{
    uint256 x_c0;
    uint256 x_c1;
    uint256 y_c0;
    uint256 y_c1;
}

struct E2_non_G2
{
    uint256 x_c0;
    uint256 x_c1;
    uint256 y_c0;
    uint256 y_c1;
}

struct SVDW
{
    uint256 i;
    uint256 x;
    uint256 y;
}
struct JsonInputs
{
    uint256[][] e2_non_g2;
    uint256[][] g1_signatures;
    uint256[][] g2_public_keys;
    uint256[][] private_keys;
    uint256[][] svdw;
}
*/

contract test_suiteTest is Test
{
    uint256[][] e2_non_g2;
    uint256[][] g1_signatures;
    uint256[][] g2_public_keys;
    uint256[][] svdw;
    //bytes[] randByteTests;
    uint256 zero = 0;
    uint64 zeroSixFour = 0;
    string domain = "BLS_SIG_BN254G1_XMD:KECCAK-256_SSWU_RO_NUL_";
    bytes zpad = abi.encodePacked(abi.encodePacked(zero, zero, zero, zero), zeroSixFour);
    bytes field_order = hex"30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47";
    BLSTest bls = new BLSTest();
    string json = vm.readFile("/Users/mitch/Desktop/solBlsTest/blsTest/test/bn254_reference_transformed.json");
    uint256[] private_keys = vm.parseJsonUintArray(json, ".private_keys");
    // string jsonTwo = vm.readFile("/Users/mitch/Desktop/solBlsTest/blsTest/test/json3.json");
    function setUp() noGasMetering public
    {
        /*string memory left = string.concat(".", Strings.toString(10));
        string memory lookup = string.concat(left, "");
        randByteTests = vm.parseJsonBytesArray(jsonTwo, lookup);*/
        for(uint256 i = 0; i < 1000; i++)
        {
            string memory strNum = Strings.toString(i);
            string memory left = string.concat("[", strNum);
            string memory lookup = string.concat(left, "]");
            uint256[] memory rawG1 = vm.parseJsonUintArray(json, string.concat(".G1_signatures",lookup));
            uint256[] memory rawG2 = vm.parseJsonUintArray(json, string.concat(".G2_public_keys",lookup));
            uint256[] memory rawE2 = vm.parseJsonUintArray(json, string.concat(".E2_non_G2",lookup));
            uint256[] memory rawSVDW = vm.parseJsonUintArray(json, string.concat(".svdw",lookup));
            g1_signatures.push(rawG1);
            g2_public_keys.push(rawG2);
            e2_non_g2.push(rawE2);
            svdw.push(rawSVDW);
        }
    }
    //bytes rawG1 = vm.parseJson(json, ".G1_signatures[0]");
    //G1SigPair g1_signatures = abi.decode(rawG1, (G1SigPair));
    //JsonInputs jsonInput = abi.decode(data, (JsonInputs));
    /*function testPrint() public view
    {
        console.logBytes(randByteTests[0]);
        console.logBytes(randByteTests[1]);
        console.logBytes(abi.encodePacked(zpad));
        // Ok, these byte reads work
        // Its time for us to push a bunch of them through
        // encode_message and hash_to_field until they work

        /*console.log(private_keys[54]);
        console.log(g1_signatures[54][0],g1_signatures[54][1]);
        console.log(g2_public_keys[54][0],g2_public_keys[54][1],g2_public_keys[54][2],g2_public_keys[54][3]);
        console.log(e2_non_g2[54][0],e2_non_g2[54][1],e2_non_g2[54][2],e2_non_g2[54][3]);
        console.log(svdw[54][0],svdw[54][1],svdw[54][2]);
        //console.log(jsonInput.svdw[0]);
    }*/

    function testExpand_Message(bytes memory expMsg) public view
    {
        uint8 outputLen = 96;
        uint8 domainLength = 43;
        //console2.logBytes(msgData);
        console2.logBytes(expMsg);
        //string memory domain = "BLS_SIG_BN254G1_XMD:KECCAK-256_SSWU_RO_NUL_";
        bytes memory b_0 = abi.encodePacked(zpad,expMsg,uint8(outputLen >> 8),uint8(outputLen & 255), uint8(0),bytes(domain),domainLength);
        console2.logBytes(b_0);
        bytes32 b_0_hashed = keccak256(b_0);
        console2.logBytes32(b_0_hashed);
        bytes memory b_i = abi.encodePacked(b_0_hashed,uint8(1),bytes(domain),domainLength);
        bytes32 b_i_hashed = keccak256(b_i);
        console2.logBytes32(b_i_hashed);
        bytes memory newb_i = abi.encodePacked(b_i_hashed ^ b_0_hashed, uint8(2), bytes(domain),domainLength);
        bytes32 newHash =keccak256(newb_i);
        bytes memory newb_ii = abi.encodePacked(newHash ^ b_0_hashed, uint8(3), bytes(domain),domainLength);
        bytes32 secondHash = keccak256(newb_ii);
        console.logBytes(abi.encodePacked(b_i_hashed,newHash,secondHash));
        assert(keccak256(bls.expandMsgTo96(bytes(domain), expMsg)) == keccak256(abi.encodePacked(b_i_hashed,newHash,secondHash)));
        // copy first 32 bytes of b_i_hashed into a 96 byte array three times, then return array
        // return out
    }
    function expand_message(bytes memory message) private view returns (bytes memory)
    {
        uint8 outputLen = 96;
        uint8 domainLength = 43;
        //console2.logBytes(msgData);
        console2.logBytes(message);
        bytes memory b_0 = abi.encodePacked(zpad,message,uint8(outputLen >> 8),uint8(outputLen & 255), uint8(0),bytes(domain),domainLength);
        console2.logBytes(b_0);
        bytes32 b_0_hashed = keccak256(b_0);
        console2.logBytes32(b_0_hashed);
        bytes memory b_i = abi.encodePacked(b_0_hashed,uint8(1),bytes(domain),domainLength);
        bytes32 b_i_hashed = keccak256(b_i);
        console2.logBytes32(b_i_hashed);
        bytes memory newb_i = abi.encodePacked(b_i_hashed ^ b_0_hashed, uint8(2), bytes(domain),domainLength);
        bytes32 newHash =keccak256(newb_i);
        bytes memory newb_ii = abi.encodePacked(newHash ^ b_0_hashed, uint8(3), bytes(domain),domainLength);
        bytes32 secondHash = keccak256(newb_ii);
        console.logBytes(abi.encodePacked(b_i_hashed,newHash,secondHash));
        return abi.encodePacked(b_i_hashed,newHash,secondHash);
    }
    function testHash_to_field(bytes memory rands) public view
    {
        bytes memory expanded = expand_message(rands);
        bytes memory ord = hex"30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47";
        bytes memory left = new bytes(48);
        for (uint i = 0; i < 48; i++)
        {
          left[i] = expanded[i];
        }
        bytes memory right = new bytes(48);
        for (uint l = 0; l < 48; l++)
        {
          right[l] = expanded[l + 48];
        }
        BigNumber memory leftBig = BigNumbers.init(left, false);
        BigNumber memory rightBig = BigNumbers.init(right, false);
        BigNumber memory fieldOrder = BigNumbers.init(ord, false);
        console.logBytes(left);
        console.logBytes(right);
        BigNumber memory resOne = BigNumbers.mod(leftBig,fieldOrder);
        BigNumber memory resTwo = BigNumbers.mod(rightBig,fieldOrder);
        console.logBytes(resOne.val);
        console.logBytes(resTwo.val);
        uint256[2] memory p = bls.hashToField(bytes(domain), rands);
        assert(keccak256(abi.encodePacked(p[0])) == keccak256(resOne.val));
        assert(keccak256(abi.encodePacked(p[1])) == keccak256(resTwo.val));
    }
    function testG1() public noGasMetering
    {
        for(uint256 i = 0; i < 1000; i++)
        {
            uint[] memory iq = g1_signatures[i];
            uint[2] memory iqOw = [iq[0], iq[1]];
            assert(bls.isValidSignature(iqOw));
        }
    }
    function testG2() public noGasMetering
    {
        for(uint256 i = 0; i < 1000; i++)
        {
            uint[] memory iq = g2_public_keys[i];
            uint[4] memory iqOw = [iq[0], iq[1], iq[2], iq[3]];
            assert(bls.isValidPublicKey(iqOw));
        }
    }
    function testE2noG2() public noGasMetering
    {
        for(uint256 i = 0; i < 1000; i++)
        {
            uint[] memory iq = e2_non_g2[i];
            uint[4] memory iqOw = [iq[0], iq[1], iq[2], iq[3]];
            assert(bls.isValidPublicKey(iqOw) == false);
        }
    }
    function testSVDW() public noGasMetering
    {
        for(uint256 i = 0; i < 1000; i++)
        {
            uint256[] memory iq = svdw[i];
            uint256[2] memory targets = bls.mapToPoint(iq[0]);
            assert(bls.isOnCurveG1(targets));
            assert(targets[0] == iq[1]);
            assert(targets[1] == iq[2]);
        }
    }
    function testLibraryConsistent() public noGasMetering
    {
        uint256[2] memory pt = bls.hashToPoint(bytes(domain), bytes("Hello World!"));
        assert(bls.isOnCurveG1(pt));
        for(uint256 i = 0; i < 1000; i++)
        {
            uint[] memory iq = g1_signatures[i];
            uint[] memory iqTwo = g2_public_keys[i];
            uint[2] memory iqOw = [iq[0], iq[1]];
            uint[4] memory iqTwoOw = [iqTwo[0], iqTwo[1], iqTwo[2], iqTwo[3]];
            assert(bls.isValidPublicKey(iqTwoOw));
            assert(bls.isValidSignature(iqOw));
            (bool pairingSuccess, bool callSuccess) = bls.verifySingle(iqOw,iqTwoOw,pt);
            if(callSuccess)
            {
                assert(pairingSuccess);
            }
        }
    }
    function testLibConsistentTwo() public noGasMetering
    {
        uint256[2] memory pt = bls.hashToPoint(bytes(domain), bytes("Hello world!"));
        for(uint256 i = 0; i < 1000; i++)
        {
            uint[] memory iq = g1_signatures[i];
            uint[] memory iqTwo = e2_non_g2[i];
            uint[2] memory iqOw = [iq[0], iq[1]];
            uint[4] memory iqTwoOw = [iqTwo[0], iqTwo[1], iqTwo[2], iqTwo[3]];
            assert(bls.isValidPublicKey(iqTwoOw));
            assert(bls.isValidSignature(iqOw));
            (bool pairingSuccess, bool callSuccess) = bls.verifySingle(iqOw,iqTwoOw,pt);
            if(callSuccess)
            {
                assert(pairingSuccess);
            }
        }
    }
    // The next step is to implement hash_to_field and expand_message from
    // utils.ts

    // utils.ts is the Tristan-implemented typescript library that
    // is supposed to precisely mimic the on-chain solidity implementation
    // BLS.sol

    // WE SHOULD BE ABLE TO USE FUZZER UTILITY TO GENERATE RANDOM BYTES
    // BUT WE ALSO MIGHT NOT HAVE TO.

    /*/// Returns a random uint256 value.
    function randomUint() external returns (uint256);

    /// Returns random uin256 value between the provided range (=min..=max).
    function randomUint(uint256 min, uint256 max) external returns (uint256);*/

    // Verifying a correct implementation there is the first test done.

    // After that, we  switch to verifying the consistency and logic of the
    // library directly.

    // That just involves feeding our SAGE-generated JSON into the contracts
    // and correctly getting TRUE or FALSE

}
