// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";

struct PackedUserOperation {
  address sender;
  uint256 nonce;
  bytes initCode;
  bytes callData;
  bytes32 accountGasLimits;
  uint256 preVerificationGas;
  bytes32 gasFees;
  bytes paymasterAndData;
  bytes signature;
}

/// @notice ERC-4337 forwarder account + entrypoint merged into one contract.
/// @dev handleOps validates (signature, authorized signer, nonce) and forwards, internally.
///      The ERC-2771 sender is appended ONLY when calling `erc2771Target` (fixed at
///      construction). It is never up to the signer, which would let a signer route a call
///      to an ERC-2771 target through the plain path with a forged trailing sender and
///      impersonate any account. Invariant: `erc2771Target` is the only ERC-2771 contract
///      that trusts this account as a forwarder.
contract UnifiedForwarderAccount {
  // userOpHash is computed exactly like EntryPoint v0.7 (binding the canonical EntryPoint
  // address + chainid) so the userop producers keep signing as they do today, unchanged.
  address private constant SIGNING_ENTRYPOINT = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;

  address public immutable erc2771Target;

  mapping(address signer => bool) public authorizedSigner;
  mapping(uint192 key => uint64 sequence) private _nonceSeq;

  error UnauthorizedSigner(address signer);
  error InvalidSignature(address recovered, address expected);
  error InvalidNonce(uint192 key, uint64 expected, uint64 actual);

  constructor(address erc2771Target_, address[] memory signers) {
    erc2771Target = erc2771Target_;
    for (uint256 i = 0; i < signers.length; ++i) authorizedSigner[signers[i]] = true;
  }

  function handleOps(PackedUserOperation[] calldata ops, address /* beneficiary */) external {
    for (uint256 i = 0; i < ops.length; ++i) _validate(ops[i]);
    for (uint256 i = 0; i < ops.length; ++i) _execute(ops[i]);
  }

  function _validate(PackedUserOperation calldata op) private {
    (address signer, , , ) = _decode(op.callData);
    address recovered = ECDSA.recover(MessageHashUtils.toEthSignedMessageHash(_userOpHash(op)), op.signature);
    require(recovered == signer, InvalidSignature(recovered, signer));
    require(authorizedSigner[signer], UnauthorizedSigner(signer));

    // TODO: We're currently using RANDOM_KEY_EVERYTIME to support multiple signers, userop reordering and userop dropping.
    // This wastes a lot of gas, which we could save with a different nonce scheme.
    // Get this account released and in use to get the bigger gains from dropping the standard EntryPoint, then fix this TODO.
    uint192 key = uint192(op.nonce >> 64);
    uint64 seq = uint64(op.nonce);
    uint64 expected = _nonceSeq[key];
    require(seq == expected, InvalidNonce(key, expected, seq));
    _nonceSeq[key] = expected + 1;
  }

  function _execute(PackedUserOperation calldata op) private {
    (address signer, address target, uint256 value, bytes memory data) = _decode(op.callData);
    if (target == erc2771Target) {
      Address.functionCallWithValue(target, abi.encodePacked(data, signer), value);
    } else {
      Address.functionCallWithValue(target, data, value);
    }
  }

  /// @dev callData == <4-byte tag> ++ abi.encode(signer, target, value, data), the format the
  ///      producers already build. The tag is ignored: the append decision is target-based.
  function _decode(
    bytes calldata callData
  ) private pure returns (address signer, address target, uint256 value, bytes memory data) {
    return abi.decode(callData[4:], (address, address, uint256, bytes));
  }

  function _userOpHash(PackedUserOperation calldata op) private view returns (bytes32) {
    bytes32 inner = keccak256(
      abi.encode(
        op.sender,
        op.nonce,
        keccak256(op.initCode),
        keccak256(op.callData),
        op.accountGasLimits,
        op.preVerificationGas,
        op.gasFees,
        keccak256(op.paymasterAndData)
      )
    );
    return keccak256(abi.encode(inner, SIGNING_ENTRYPOINT, block.chainid));
  }
}
