// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.23;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {BaseAccount} from "@account-abstraction/contracts/core/BaseAccount.sol";
import {SIG_VALIDATION_SUCCESS, SIG_VALIDATION_FAILED} from "@account-abstraction/contracts/core/Helpers.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract AccessControlAccount is AccessControl, BaseAccount {
  bytes32 public constant WITHDRAW_ROLE = keccak256("WITHDRAW_ROLE");
  bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");

  IEntryPoint private immutable _entryPoint;

  error RequiredEntryPointOrExecutor(address sender);
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

  // Require the function call went through EntryPoint or owner
  function _requireFromEntryPointOrExecutor() internal view {
    if (msg.sender != address(entryPoint()) && !hasRole(EXECUTOR_ROLE, msg.sender))
      revert RequiredEntryPointOrExecutor(msg.sender);
  }

  /**
   * execute a transaction (called directly from owner, or by entryPoint)
   * @param dest destination address to call
   * @param value the value to pass in this call
   * @param func the calldata to pass in this call
   */
  function execute(address dest, uint256 value, bytes calldata func) external {
    _requireFromEntryPointOrExecutor();
    Address.functionCallWithValue(dest, func, value);
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
    if (value.length == 0) {
      for (uint256 i = 0; i < dest.length; i++) {
        Address.functionCallWithValue(dest[i], func[i], 0);
      }
    } else {
      for (uint256 i = 0; i < dest.length; i++) {
        Address.functionCallWithValue(dest[i], func[i], value[i]);
      }
    }
  }

  /// implement template method of BaseAccount
  function _validateSignature(
    PackedUserOperation calldata userOp,
    bytes32 userOpHash
  ) internal virtual override returns (uint256 validationData) {
    bytes32 hash = MessageHashUtils.toEthSignedMessageHash(userOpHash);
    address recovered = ECDSA.recover(hash, userOp.signature);
    if (!hasRole(EXECUTOR_ROLE, recovered)) return SIG_VALIDATION_FAILED;
    return SIG_VALIDATION_SUCCESS;
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
