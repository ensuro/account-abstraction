// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.23;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {ERC2771Context} from "@openzeppelin/contracts/metatx/ERC2771Context.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {BaseAccount} from "@account-abstraction/contracts/core/BaseAccount.sol";
import {SIG_VALIDATION_SUCCESS, SIG_VALIDATION_FAILED} from "@account-abstraction/contracts/core/Helpers.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IAccountExecute} from "@account-abstraction/contracts/interfaces/IAccountExecute.sol";

/**
 * @title ERC2771ForwarderAccount
 *
 * @dev Smart Account that acts as an ERC2771 Trusted Forwarder, forwarding calls to other contract(s) where
 *      the account is the trusted forwarder, on behalf of the signer of the userOp.
 *
 * @custom:security-contact security@ensuro.co
 * @author Ensuro
 */
contract ERC2771ForwarderAccount is AccessControl, BaseAccount, IAccountExecute {
  bytes32 public constant WITHDRAW_ROLE = keccak256("WITHDRAW_ROLE");
  bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");

  IEntryPoint private immutable _entryPoint;
  address internal transient _userOpSigner;

  error RequiredEntryPointOrExecutor(address sender);
  error UserOpSignerNotSet();
  error CanCallOnlyIfTrustedForwarder(address target);
  error WrongArrayLength();

  /// @inheritdoc BaseAccount
  function entryPoint() public view virtual override returns (IEntryPoint) {
    return _entryPoint;
  }

  // solhint-disable-next-line no-empty-blocks
  receive() external payable {}

  constructor(IEntryPoint anEntryPoint, address admin, address[] memory executors) {
    _entryPoint = anEntryPoint;
    _grantRole(DEFAULT_ADMIN_ROLE, admin);
    for (uint256 i; i < executors.length; i++) {
      _grantRole(EXECUTOR_ROLE, executors[i]);
    }
  }

  // Require the function call went through EntryPoint or authorized executor
  function _requireFromEntryPointOrExecutor() internal view {
    require(
      msg.sender == address(_entryPoint) || hasRole(EXECUTOR_ROLE, msg.sender),
      RequiredEntryPointOrExecutor(msg.sender)
    );
  }

  /**
   * execute a transaction (called directly from executor, or by entryPoint)
   * @param dest destination address to call
   * @param value the value to pass in this call
   * @param func the calldata to pass in this call
   */
  function execute(address dest, uint256 value, bytes calldata func) external override {
    _requireFromEntryPointOrExecutor();
    require(_isTrustedByTarget(dest), CanCallOnlyIfTrustedForwarder(dest));
    Address.functionCallWithValue(dest, abi.encodePacked(func, address(this)), value);
  }

  function executeUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash) external override {
    _requireFromEntryPointOrExecutor();
    // No need to check the signer's permission here, as it's already validated in validateUserOp
    address signer = _getSigner(userOp, userOpHash);
    (address dest, uint256 value, bytes memory func) = abi.decode(userOp.callData[4:], (address, uint256, bytes));
    require(_isTrustedByTarget(dest), CanCallOnlyIfTrustedForwarder(dest));
    Address.functionCallWithValue(dest, abi.encodePacked(func, signer), value);
  }

  /**
   * execute a sequence of transactions
   * @dev to reduce gas consumption for trivial case (no value), use a zero-length array to mean zero value
   * @param dest an array of destination addresses
   * @param value an array of values to pass to each call. can be zero-length for no-value calls
   * @param func an array of calldata to pass to each call
   */
  function executeBatch(address[] calldata dest, uint256[] calldata value, bytes[] calldata func) external {
    _requireFromEntryPointOrExecutor();
    if (dest.length != func.length || (value.length != 0 && value.length != func.length)) revert WrongArrayLength();
    for (uint256 i = 0; i < dest.length; i++) {
      require(
        i == 0 ? _isTrustedByTarget(dest[0]) : (dest[i - 1] == dest[i] || _isTrustedByTarget(dest[i])),
        CanCallOnlyIfTrustedForwarder(dest[i])
      );
      Address.functionCallWithValue(
        dest[i],
        abi.encodePacked(func[i], address(this)),
        value.length == 0 ? 0 : value[i]
      );
    }
  }

  /// implement template method of BaseAccount
  function _validateSignature(
    PackedUserOperation calldata userOp,
    bytes32 userOpHash
  ) internal virtual override returns (uint256 validationData) {
    address recovered = _getSigner(userOp, userOpHash);
    if (!hasRole(EXECUTOR_ROLE, recovered)) return SIG_VALIDATION_FAILED;
    return SIG_VALIDATION_SUCCESS;
  }

  function _getSigner(PackedUserOperation calldata userop, bytes32 userOpHash) internal pure returns (address) {
    bytes32 hash = MessageHashUtils.toEthSignedMessageHash(userOpHash);
    return ECDSA.recover(hash, userop.signature);
  }

  /**
   * @dev Returns whether the target trusts this forwarder.
   *
   * This function performs a static call to the target contract calling the
   * {ERC2771Context-isTrustedForwarder} function.
   *
   * Copied from ERC2771Forwarder.sol (OZ-contracts)
   */
  function _isTrustedByTarget(address target) private view returns (bool) {
    bytes memory encodedParams = abi.encodeCall(ERC2771Context.isTrustedForwarder, (address(this)));

    bool success;
    uint256 returnSize;
    uint256 returnValue;
    // solhint-disable-next-line no-inline-assembly
    assembly ("memory-safe") {
      // Perform the staticcall and save the result in the scratch space.
      // | Location  | Content  | Content (Hex)                                                      |
      // |-----------|----------|--------------------------------------------------------------------|
      // |           |          |                                                           result ↓ |
      // | 0x00:0x1F | selector | 0x0000000000000000000000000000000000000000000000000000000000000001 |
      success := staticcall(gas(), target, add(encodedParams, 0x20), mload(encodedParams), 0, 0x20)
      returnSize := returndatasize()
      returnValue := mload(0)
    }

    return success && returnSize >= 0x20 && returnValue > 0;
  }

  /**
   * check current account deposit in the entryPoint
   */
  function getDeposit() public view returns (uint256) {
    return entryPoint().balanceOf(address(this));
  }

  /**
   * deposit more funds for this account in the entryPoint
   */
  function addDeposit() public payable {
    entryPoint().depositTo{value: msg.value}(address(this));
  }

  /**
   * withdraw value from the account's deposit
   * @param withdrawAddress target to send to
   * @param amount to withdraw
   */
  function withdrawDepositTo(address payable withdrawAddress, uint256 amount) public onlyRole(WITHDRAW_ROLE) {
    entryPoint().withdrawTo(withdrawAddress, amount);
  }
}
