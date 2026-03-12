// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.23;

import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {BaseAccount} from "@account-abstraction/contracts/core/BaseAccount.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {ERC2771Context} from "@openzeppelin/contracts/metatx/ERC2771Context.sol";
import {IAccountExecute} from "@account-abstraction/contracts/interfaces/IAccountExecute.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {SIG_VALIDATION_SUCCESS, SIG_VALIDATION_FAILED} from "@account-abstraction/contracts/core/Helpers.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/**
 * @title ERC2771ForwarderAccount
 *
 * @dev Smart Account that acts as an ERC2771 Trusted Forwarder, forwarding calls to a pre-defined contract
 *      on behalf of the signer of the userOp.
 *
 *      Assumes the target contract is designed to work with ERC2771Context and trusts this account as a forwarder.
 *
 *      This contract is designed to be used with an AccessManagedProxy for runtime access control management.
 *
 * @custom:security-contact security@ensuro.co
 * @author Ensuro
 */
contract ERC2771ForwarderAccount is UUPSUpgradeable, BaseAccount, IAccountExecute {
  IEntryPoint private immutable _entryPoint;

  /// @custom:storage-location erc7201:ensuro.storage.ERC2771ForwarderAccount
  struct ERC2771ForwarderAccountStorage {
    mapping(address => ERC2771Context) targets;
  }

  // keccak256(abi.encode(uint256(keccak256("ensuro.storage.ERC2771ForwarderAccount")) - 1)) & ~bytes32(uint256(0xff))
  // solhint-disable-next-line const-name-snakecase
  bytes32 internal constant ERC2771ForwarderAccountStorageLocation =
    0x32800a8a254400b8b55434a22b827759dcb96a572133b419f26b7155e3843000;

  function _getAccountStorage() internal pure returns (ERC2771ForwarderAccountStorage storage $) {
    // solhint-disable-next-line no-inline-assembly
    assembly {
      $.slot := ERC2771ForwarderAccountStorageLocation
    }
  }

  event ExecutorAdded(address indexed executor, ERC2771Context indexed target);
  event ExecutorRemoved(address indexed executor);

  error RequiredEntryPointOrExecutor(address sender);
  error InvalidTarget(ERC2771Context target, address signer);
  error OnlyExecuteUserOpAllowed();
  error InvalidCall();

  constructor(IEntryPoint anEntryPoint) {
    _entryPoint = anEntryPoint;
  }

  // solhint-disable-next-line no-empty-blocks
  function _authorizeUpgrade(address newImpl) internal view override {}

  /**
   * @dev This is a noop, for deployment convenience where an initializer is expected.
   */
  //solhint-disable-next-line no-empty-blocks
  function initialize() external {}

  // solhint-disable-next-line no-empty-blocks
  receive() external payable {}

  function executeBatch(Call[] calldata) external virtual override {
    revert OnlyExecuteUserOpAllowed();
  }

  function execute(address, uint256, bytes calldata) external virtual override {
    revert OnlyExecuteUserOpAllowed();
  }

  function _getSigner(PackedUserOperation calldata userop, bytes32 userOpHash) internal pure returns (address) {
    bytes32 hash = MessageHashUtils.toEthSignedMessageHash(userOpHash);
    return ECDSA.recover(hash, userop.signature);
  }

  /**
   * @dev Validates that the user operation is well formed and that the destination is correct. Does not validate signature.
   * @return call A Call struct containing the call to be made
   */
  function _validateAndDecodeCall(
    PackedUserOperation calldata userOp,
    bytes32 userOpHash
  ) internal pure returns (Call memory call) {
    require(userOp.callData.length >= 56 && bytes4(userOp.callData[0:4]) == this.executeUserOp.selector, InvalidCall());
    (call.target, call.value, call.data) = abi.decode(userOp.callData[4:], (address, uint256, bytes));
    if (call.target == address(0)) {
      // This is an if and not a require to avoid evaluating the _getSigner call in the happy path
      revert InvalidTarget(ERC2771Context(call.target), _getSigner(userOp, userOpHash));
    }
  }

  function _isAuthorized(address signer, address target) internal view returns (bool) {
    ERC2771ForwarderAccountStorage storage $ = _getAccountStorage();
    return $.targets[signer] == ERC2771Context(target);
  }

  /**
   * @notice Add an executor and its corresponding target contract.
   * @param executor The executor address to add
   * @param target The ERC2771Context target contract for this executor
   */
  function addExecutor(address executor, ERC2771Context target) external {
    ERC2771ForwarderAccountStorage storage $ = _getAccountStorage();
    $.targets[executor] = target;
    emit ExecutorAdded(executor, target);
  }

  /**
   * @notice Remove an executor by setting its target to the zero address.
   * @param executor The executor address to remove
   */
  function removeExecutor(address executor) external {
    ERC2771ForwarderAccountStorage storage $ = _getAccountStorage();
    $.targets[executor] = ERC2771Context(address(0));
    emit ExecutorRemoved(executor);
  }

  /// implement template method of BaseAccount
  function _validateSignature(
    PackedUserOperation calldata userOp,
    bytes32 userOpHash
  ) internal virtual override returns (uint256 validationData) {
    Call memory call = _validateAndDecodeCall(userOp, userOpHash);
    address signer = _getSigner(userOp, userOpHash);
    if (!_isAuthorized(signer, call.target)) {
      return SIG_VALIDATION_FAILED;
    }
    return SIG_VALIDATION_SUCCESS;
  }

  /**
   * @dev Executes a user operation by forwarding the call to the target contract with the signer as the msgSender.
   *      It re-validates the signature and checks that the signer is authorized. Reverts with InvalidTarget if it isn't.
   *      The calldata is expected to contain this function's selector followed by an ABI-encoded Call:
   *         - dest (address): the target contract address (must be the same as _target)
   *         - value (uint256): the amount of ETH to send with the call
   *         - func (bytes): the calldata for the target function
   *
   * @param userOp The packed user operation containing the call data and signature.
   * @param userOpHash The hash of the user operation, used for signature verification.
   */
  function executeUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash) external override {
    Call memory call = _validateAndDecodeCall(userOp, userOpHash);
    address signer = _getSigner(userOp, userOpHash);

    require(_isAuthorized(signer, call.target), InvalidTarget(ERC2771Context(call.target), signer));

    Address.functionCallWithValue(call.target, abi.encodePacked(call.data, signer), call.value);
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
  function withdrawDepositTo(address payable withdrawAddress, uint256 amount) public {
    entryPoint().withdrawTo(withdrawAddress, amount);
  }

  /// @inheritdoc BaseAccount
  function entryPoint() public view virtual override returns (IEntryPoint) {
    return _entryPoint;
  }
}
