pragma solidity ^0.8;
import "forge-std/Test.sol";
import "forge-std/console2.sol";
import "./Strings.sol";

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

contract test_suiteTest is Test
{
    struct G1SigPair
    {
        string x;
        string y;
    }

    struct CPair
    {
        string c0;
        string c1;
    }

    struct G2PubKeys
    {
        CPair x;
        CPair y;
    }

    struct E2_non_G2
    {
        CPair x;
        CPair y;
    }

    struct SVDW
    {
        string i;
        string x;
        string y;
    }
    struct JsonInputs
    {
        E2_non_G2[] e2_non_g2;
        G1SigPair[] g1_signatures;
        G2PubKeys[] g2_public_keys;
        uint256[] private_keys;
        SVDW[] svdw;
    }
    E2_non_G2[] e2_non_g2;
    G1SigPair[] g1_signatures;
    G2PubKeys[] g2_public_keys;
    SVDW[] svdw;
    string json = vm.readFile("/Users/mitch/Desktop/solBlsTest/blsTest/test/bn254_reference.json");
    uint256[] private_keys = vm.parseJsonUintArray(json, ".private_keys");
    function setUp() noGasMetering public
    {
        for(uint256 i = 0; i < 1000; i++)
        {
            string memory strNum = Strings.toString(i);
            string memory left = string.concat("[", strNum);
            string memory lookup = string.concat(left, "]");
            bytes memory rawG1 = vm.parseJson(json, string.concat(".G1_signatures",lookup));
            g1_signatures.push(abi.decode(rawG1, (G1SigPair)));
        }
    }
    
    //bytes rawG1 = vm.parseJson(json, ".G1_signatures[0]");
    //G1SigPair g1_signatures = abi.decode(rawG1, (G1SigPair));
    //JsonInputs jsonInput = abi.decode(data, (JsonInputs));
    function testPrint() public view
    {
        //uint256 num = jsonInput.e2_non_g2[0].x.c0;
        console.log(private_keys[0]);
        console.log(g1_signatures[54].x);
        //console.log(jsonInput.g1_signatures[0]);
        //console.log(jsonInput.g2_public_keys[0]);
        //console.log(jsonInput.private_keys[0]);
        //console.log(jsonInput.svdw[0]);
    }
    
}