// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {BLS} from "../src/BLS.sol";

contract BLSTest {
    function expandMsgTo96(bytes memory domain, bytes memory message) external pure returns (bytes memory exp_msg) {
        exp_msg = BLS.expandMsgTo96(domain, message);
    }

    function hashToField(bytes memory domain, bytes memory message) external pure returns (uint256[2] memory p) {
        p = BLS.hashToField(domain, message);
    }

    function mapToPoint(uint256 value) external view returns (uint256[2] memory p) {
        p = BLS.mapToPoint(value);
    }

    function hashToPoint(bytes memory domain, bytes memory message) external view returns (uint256[2] memory p) {
        p = BLS.hashToPoint(domain, message);
    }

    function verifySingle(uint256[2] memory signature, uint256[4] memory pubkey, uint256[2] memory message)
        external
        view
        returns (bool pairingSuccess, bool callSuccess)
    {
        (pairingSuccess, callSuccess) = BLS.verifySingle(signature, pubkey, message);
    }

    function isOnCurveG1(uint256[2] memory point) external pure returns (bool _isOnCurve) {
        _isOnCurve = BLS.isOnCurveG1(point);
    }

    function isOnCurveG2(uint256[4] memory point) external pure returns (bool _isOnCurve) {
        _isOnCurve = BLS.isOnCurveG2(point);
    }

    function isValidSignature(uint256[2] memory signature) external pure returns (bool isValid) {
        isValid = BLS.isValidSignature(signature);
    }

    function isValidPublicKey(uint256[4] memory publicKey) external pure returns (bool isValid) {
        isValid = BLS.isValidPublicKey(publicKey);
    }
}
