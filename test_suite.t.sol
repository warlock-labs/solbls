pragma solidity ^0.8;
import "forge-std/Test.sol";
import "forge-std/console2.sol";
//import "./Strings.sol";

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


contract test_suiteTest is Test
{
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
    uint256[][] e2_non_g2;
    uint256[][] g1_signatures;
    uint256[][] g2_public_keys;
    uint256[][] svdw;
    uint256 field_order = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;
    BLSTest bls = BLSTest(address(BLSTest));
    string json = vm.readFile("/Users/mitch/Desktop/solBlsTest/blsTest/test/bn254_reference_transformed.json");
    uint256[] private_keys = vm.parseJsonUintArray(json, ".private_keys");
    function setUp() noGasMetering public
    {
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
    function testPrint() public view
    {
        console.log(private_keys[54]);
        console.log(g1_signatures[54][0],g1_signatures[54][1]);
        console.log(g2_public_keys[54][0],g2_public_keys[54][1],g2_public_keys[54][2],g2_public_keys[54][3]);
        console.log(e2_non_g2[54][0],e2_non_g2[54][1],e2_non_g2[54][2],e2_non_g2[54][3]);
        console.log(svdw[54][0],svdw[54][1],svdw[54][2]);
        //console.log(jsonInput.svdw[0]);
    }

    function expand_message(bytes[] message) public pure
    {
        uint256 outputLen = 96;
        string domain = "BLS_SIG_BN254G1_XMD:KECCAK-256_SSWU_RO_NUL_";
        uint8[136] zpad;
        bytes[] b_0 = abi.encodePacked(zpad,message,outputLen >> 8,outputLen & 0xff, 0,domain,domain.length);
        bytes[] b_0_hashed = keccak256(b_0);
        bytes[] b_i = abi.encodePacked(b_0_hashed,1,domain,domain.length);
        bytes[] b_i_hashed = keccak256(b_i);
        // copy first 32 bytes of b_i_hashed into a 96 byte array three times, then return array
        // return out
    }
    function hash_to_field(bytes[] message) public pure
    {
        uint256 count = 2;
        uint256 L = 48;
        uint lenInBytes = 96;
        bytes[] expanded = expand_message(message);
        uint256 resOne = expanded[0:48] % field_order;
        uint resTwo = expanded[48:] % field_order;
        return [resOne, resTwo];
        /*for (let i = 0; i < count; i++)
        {
            
        }*/

    }
    function testG1() public
    {
        for(uint256 i = 0; i < 1000; i++)
        {
            uint[] iq = g1_signatures[i];
            assert(bls.isValidSignature(iq[0], iq[1]));
        }
    }
    function testG2() public
    {
        for(uint256 i = 0; i < 1000; i++)
        {
            uint[] iq = g2_public_keys[i];
            assert(bls.isValidPublicKey(iq[0], iq[1], iq[2], iq[3]));
        }
    }
    function testE2noG2() public
    {
        for(uint256 i = 0; i < 1000; i++)
        {
            uint[] iq = e2_non_g2[i];
            assert(!bls.isValidPublicKey(iq[0], iq[1], iq[2], iq[3]));
        }
    }
    function testSVDW() public
    {
        for(uint256 i = 0; i < 1000; i++)
        {
            uint256[] iq = svdw[i];
            (uint256 targetOne, uint256 targetTwo) = bls.mapToPoint(iq[0]);
            uint256[2] targets = [targetOne,targetTwo];
            assert(bls.isOnCurveG1(targets));
            assert(targetOne == iq[1]);
            assert(targetTwo == iq[2]);
        }
    }
    function testLibraryConsistent() public
    {
        uint256[2] pt = bls.hashToPoint((bytes32) domain, (bytes32) "Hello World!");
        assert(bls.isOnCurveG1(pt));
        for(uint256 i = 0; i < 1000; i++)
        {
            uint[] iq = g1_signatures[i];
            uint[] iqTwo = g2_public_keys[i];
            assert(bls.isValidPublicKey(iqTwo));
            assert(bls.isValidSignature(iq[0], iq[1]));
            (bool pairingSuccess, bool callSuccess) = bls.verifySingle(iq,iqTwo,pt);
            if(callSuccess)
            {
                assert(pairingSuccess);
            }
        }
    }
    function testLibConsistentTwo()
    {
        // Should fail
        for(uint256 i = 0; i < 1000; i++)
        {
            uint[] iq = g1_signatures[i];
            uint[] iqTwo = e2_non_g2[i];
            assert(bls.isValidPublicKey(iqTwo));
            assert(bls.isValidSignature(iq[0], iq[1]));
            (bool pairingSuccess, bool callSuccess) = bls.verifySingle(iq,iqTwo,pt);
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
