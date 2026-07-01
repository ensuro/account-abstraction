// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {AccessManaged} from "@openzeppelin/contracts/access/manager/AccessManaged.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";

/// @dev Only used to derive the accepted callData tag selectors by name+type (see EXECUTE_SELECTOR).
interface IExecute {
  function execute(address target, uint256 value, bytes calldata data) external;

  function executeUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash) external;
}

/// @notice ERC-4337 forwarder account + entrypoint merged into one contract.
/// @dev handleOps validates (signature, authorized signer, nonce) and forwards, internally.
///      The ERC-2771 sender is appended ONLY when calling `erc2771Target` (fixed at
///      construction). It is never up to the signer, which would let a signer route a call
///      to an ERC-2771 target through the plain path with a forged trailing sender and
///      impersonate any account.
///
///      Deployment invariant, assumed but NOT enforced on-chain: `erc2771Target` is the only
///      ERC-2771 contract that trusts this account as a forwarder. If any other ERC-2771 contract
///      trusts it, an authorized signer can impersonate arbitrary accounts on that contract via
///      the plain path. Wiring this up correctly is a deployment responsibility.
contract UnifiedForwarderAccount is AccessManaged {
  // Accepted callData tags (the 4-byte prefix). The encoded args after the tag are always
  // (signer, target, value, data) regardless of which tag is used.
  bytes4 private constant EXECUTE_SELECTOR = IExecute.execute.selector;
  bytes4 private constant EXECUTE_USER_OP_SELECTOR = IExecute.executeUserOp.selector;

  uint256 private constant SELECTOR_SIZE = 4; // 4-byte callData tag
  uint256 private constant WORD_SIZE = 32; // ABI head word
  uint256 private constant NONCE_SEQ_BITS = 64; // 2D nonce: high 192 bits = key, low 64 = sequence

  address public immutable erc2771Target;

  mapping(address signer => bool) public authorizedSigner;
  mapping(uint192 key => uint64 sequence) private _nonceSeq;

  event AuthorizedSignerSet(address indexed signer, bool authorized);

  error UnauthorizedSigner(address signer);
  error InvalidSignature(address recovered, address expected);
  error InvalidNonce(uint192 key, uint64 expected, uint64 actual);
  error UnsupportedSelector(bytes4 selector);
  error InvalidSender(address sender);
  error ZeroAddress();

  constructor(address authority, address erc2771Target_, address[] memory signers) AccessManaged(authority) {
    require(erc2771Target_ != address(0), ZeroAddress());
    erc2771Target = erc2771Target_;
    for (uint256 i = 0; i < signers.length; ++i) {
      require(signers[i] != address(0), ZeroAddress());
      authorizedSigner[signers[i]] = true;
    }
  }

  // solhint-disable-next-line no-empty-blocks
  receive() external payable {}

  /// @notice Add or remove an authorized signer. Gated by the AccessManager `authority`; the signer
  ///         set stays in plain storage so `_validate` reads it cheaply.
  function setAuthorizedSigner(address signer, bool authorized) external restricted {
    require(signer != address(0), ZeroAddress());
    authorizedSigner[signer] = authorized;
    emit AuthorizedSignerSet(signer, authorized);
  }

  function handleOps(PackedUserOperation[] calldata ops, address /* beneficiary */) external {
    bytes32[] memory hashes = new bytes32[](ops.length);
    for (uint256 i = 0; i < ops.length; ++i) hashes[i] = _validate(ops[i]);
    for (uint256 i = 0; i < ops.length; ++i) _execute(ops[i], hashes[i]);
  }

  /// @notice Next packed nonce for a 2D-nonce key, matching EntryPoint semantics.
  function getNonce(uint192 key) external view returns (uint256) {
    return (uint256(key) << NONCE_SEQ_BITS) | _nonceSeq[key];
  }

  /// @notice The userOp hash this account signs over and verifies (the same value reported as
  ///         `userOpHash` in UserOperationEvent). Exposed under the canonical EntryPoint signature
  ///         for bundler simulation/estimation; it is this account's own hash (see `_userOpHash`),
  ///         not the v0.8 EIP-712 hash.
  function getUserOpHash(PackedUserOperation calldata userOp) external view returns (bytes32) {
    return _userOpHash(userOp);
  }

  function _validate(PackedUserOperation calldata op) private returns (bytes32 userOpHash) {
    require(op.sender == address(this), InvalidSender(op.sender));
    bytes4 selector = bytes4(op.callData[:SELECTOR_SIZE]);
    require(selector == EXECUTE_SELECTOR || selector == EXECUTE_USER_OP_SELECTOR, UnsupportedSelector(selector));

    // signer is the first encoded word; reading it directly avoids decoding `data` into memory here
    // saves about 8k gas per op for large calldata
    address signer = abi.decode(op.callData[SELECTOR_SIZE:SELECTOR_SIZE + WORD_SIZE], (address));
    userOpHash = _userOpHash(op);
    address recovered = ECDSA.recover(MessageHashUtils.toEthSignedMessageHash(userOpHash), op.signature);
    require(recovered == signer, InvalidSignature(recovered, signer));
    require(authorizedSigner[signer], UnauthorizedSigner(signer));

    // TODO: We're currently using RANDOM_KEY_EVERYTIME to support multiple signers, userop reordering and userop dropping.
    // This wastes a lot of gas, which we could save with a different nonce scheme. At least 15k per userop.
    // Get this account released and in use to get the bigger gains from dropping the standard EntryPoint, then fix this TODO.
    uint192 key = uint192(op.nonce >> NONCE_SEQ_BITS);
    uint64 seq = uint64(op.nonce);
    uint64 expected = _nonceSeq[key];
    require(seq == expected, InvalidNonce(key, expected, seq));
    _nonceSeq[key] = expected + 1;
  }

  /// @dev A failing op does not revert the bundle: earlier ops are already paid for, so we just
  ///      report it via the canonical events and move on. The call is bounded by the op's signed
  ///      `callGasLimit` so a looping/heavy op can't starve the rest of the bundle.
  ///
  ///      This isolation only covers reverts INSIDE the forwarded call. `_validate` checks just the
  ///      signer word, so an op with a valid signature but malformed callData (a bogus tuple that
  ///      makes `_decode` below revert) reverts the whole bundle. Producers are trusted to build
  ///      well-formed callData, so this is accepted rather than guarded: an up-front full decode
  ///      isn't justified for this self-bundled, trusted-signer setup.
  function _execute(PackedUserOperation calldata op, bytes32 userOpHash) private {
    (address signer, address target, uint256 value, bytes memory data) = _decode(op.callData);
    bytes memory payload = target == erc2771Target ? abi.encodePacked(data, signer) : data;
    // low 128 bits of accountGasLimits = callGasLimit (EntryPoint packing)
    uint256 callGasLimit = uint128(uint256(op.accountGasLimits));

    // solhint-disable-next-line avoid-low-level-calls
    (bool success, bytes memory ret) = target.call{gas: callGasLimit, value: value}(payload);
    if (!success && ret.length > 0) emit IEntryPoint.UserOperationRevertReason(userOpHash, op.sender, op.nonce, ret);
    // paymaster is address(0) (none) and actualGasCost/actualGasUsed are 0: this self-bundled account
    // does no on-chain gas accounting or reimbursement (the caller pays the tx directly).
    emit IEntryPoint.UserOperationEvent(userOpHash, op.sender, address(0), op.nonce, success, 0, 0);
  }

  /// @dev callData == <4-byte tag> ++ abi.encode(signer, target, value, data), the format the
  ///      producers already build. The tag is only checked against the accepted selectors (see
  ///      _validate); it never influences the append, which is target-based.
  function _decode(
    bytes calldata callData
  ) private pure returns (address signer, address target, uint256 value, bytes memory data) {
    return abi.decode(callData[SELECTOR_SIZE:], (address, address, uint256, bytes));
  }

  /// @dev v0.7 userOpHash layout, but bound to this account's address (not the canonical
  ///      EntryPoint) for per-deployment domain separation. Producers sign over address(this).
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
    return keccak256(abi.encode(inner, address(this), block.chainid));
  }
}
