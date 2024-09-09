// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.23;

import {AccessManager} from "@openzeppelin/contracts/access/manager/AccessManager.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {BaseAccount} from "@account-abstraction/contracts/core/BaseAccount.sol";
import {SIG_VALIDATION_SUCCESS, SIG_VALIDATION_FAILED} from "@account-abstraction/contracts/core/Helpers.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {BytesLib} from "solidity-bytes-utils/contracts/BytesLib.sol";

contract AccessManagerAccount is AccessManager, BaseAccount {
  using BytesLib for bytes;

  IEntryPoint private immutable _entryPoint;

  bytes4 private constant EXECUTE_SELECTOR = bytes4(keccak256("execute(address,uint256,bytes)"));

  error OnlyExecuteAllowedFromEntryPoint(bytes4 receivedSelector);
  error OnlyExternalTargets();
  error DelayNotAllowed();

  /// @inheritdoc BaseAccount
  function entryPoint() public view virtual override returns (IEntryPoint) {
    return _entryPoint;
  }

  // solhint-disable-next-line no-empty-blocks
  receive() external payable {}

  constructor(IEntryPoint anEntryPoint, address initialAdmin) AccessManager(initialAdmin) {
    _entryPoint = anEntryPoint;
  }

  /**
   * execute a transaction (called directly from owner, or by entryPoint)
   * @param dest destination address to call
   * @param value the value to pass in this call
   * @param func the calldata to pass in this call
   */
  function execute(address dest, uint256 value, bytes calldata func) external {
    _requireFromEntryPoint();
    Address.functionCallWithValue(dest, func, value);
  }

  // hashOperation variant that receives bytes memory
  function _hashOperation(address caller, address target, bytes memory data) internal pure returns (bytes32) {
    return keccak256(abi.encode(caller, target, data));
  }

  function _checkAAExecuteCall(address signer, bytes calldata userOpCallData) internal returns (uint256) {
    (address target, , bytes memory funcCall) = abi.decode(
      userOpCallData[4:userOpCallData.length - 4],
      (address, uint256, bytes)
    );
    // Calls to address(this) are not allowed through AA. It might be possible to implement, but this
    // complicates the testing and it might introduce security issues
    if (target == address(this)) revert OnlyExternalTargets();
    (bool immediate, uint32 delay) = canCall(signer, target, bytes4(funcCall.toBytes32(0)));
    if (immediate || delay == 0) return immediate ? SIG_VALIDATION_SUCCESS : SIG_VALIDATION_FAILED;
    _consumeScheduledOp(_hashOperation(signer, target, funcCall));
    return SIG_VALIDATION_SUCCESS;
  }

  /// implement template method of BaseAccount
  function _validateSignature(
    PackedUserOperation calldata userOp,
    bytes32 userOpHash
  ) internal virtual override returns (uint256 validationData) {
    // First check the initial selector, from EntryPoint only execute and executeBatch are allowed
    bytes4 selector = bytes4(userOp.callData[0:4]);
    if (selector != EXECUTE_SELECTOR) revert OnlyExecuteAllowedFromEntryPoint(selector);
    bytes32 hash = MessageHashUtils.toEthSignedMessageHash(userOpHash);
    address recovered = ECDSA.recover(hash, userOp.signature);
    // Check first the signer can call execute
    if (!_checkCanCall(recovered, userOp.callData, false)) return SIG_VALIDATION_FAILED;
    // Then check it can call the specific target/selector
    return _checkAAExecuteCall(recovered, userOp.callData);
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
   * @dev Adapted from AccessManaged._checkCanCall, checks a method can be called as if the AccessManagerAccount
   *      was an access managed contract (not validating against admin permissions)
   */
  function _checkCanCall(address caller, bytes calldata data, bool fail) internal returns (bool) {
    (bool immediate, uint32 delay) = canCall(caller, address(this), bytes4(data[0:4]));
    if (!immediate) {
      if (delay > 0) {
        revert DelayNotAllowed();
        // Is not possible to handle scheduled operations, because when target=address(this), schedule 
        // doesn't work the same way, otherwise here we should do just
        // _consumeScheduledOp(hashOperation(caller, address(this), data));
      } else {
        if (fail)
          revert AccessManagerUnauthorizedAccount(caller, getTargetFunctionRole(address(this), bytes4(data[0:4])));
        else return false;
      }
    }
    return true;
  }
  /**
   * withdraw value from the account's deposit
   * @param withdrawAddress target to send to
   * @param amount to withdraw
   */
  function withdrawDepositTo(address payable withdrawAddress, uint256 amount) public {
    _checkCanCall(_msgSender(), _msgData(), true);
    entryPoint().withdrawTo(withdrawAddress, amount);
  }
}
