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
  // 132 = 4 (method bytes4) + 32 (expectedSigner) + 32 (target) + 32 (value) + 32 (calldata offset)
  uint256 private constant MIN_USER_OP_CALLDATA = 132;
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
  error InvalidCall();
  error MethodNotSupported(bytes4 selector);

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
    revert InvalidCall();
  }

  function execute(address, uint256, bytes calldata) external virtual override {
    revert InvalidCall();
  }

  function _getSigner(PackedUserOperation calldata userop, bytes32 userOpHash) internal pure returns (address) {
    bytes32 hash = MessageHashUtils.toEthSignedMessageHash(userOpHash);
    return ECDSA.recover(hash, userop.signature);
  }

  /**
   * @dev Validates that the user operation is well formed and that the destination is correct. Does not validate signature.
   * @return expectedSigner The address included in the call data, expected to be the signer of the userOp
   * @return call A Call struct containing the call to be made
   * @return selector The selector used (execute or executeUserOp)
   */
  function _validateAndDecodeCall(
    PackedUserOperation calldata userOp,
    bytes32 userOpHash
  ) internal pure returns (address expectedSigner, Call memory call, bytes4 selector) {
    if (userOp.callData.length < MIN_USER_OP_CALLDATA) revert InvalidCall();
    selector = bytes4(userOp.callData[0:4]);
    if (selector != this.executeUserOp.selector && selector != this.erc2771Forward.selector) {
      revert MethodNotSupported(selector);
    }
    (expectedSigner, call.target, call.value, call.data) = abi.decode(
      userOp.callData[4:],
      (address, address, uint256, bytes)
    );
    if (call.target == address(0)) {
      revert InvalidTarget(ERC2771Context(call.target), _getSigner(userOp, userOpHash));
    }
  }

  function _isAuthorized(address signer, address expectedSigner, address target) internal view returns (bool) {
    ERC2771ForwarderAccountStorage storage $ = _getAccountStorage();
    return signer == expectedSigner && $.targets[signer] == ERC2771Context(target);
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
    (address expectedSigner, Call memory call, ) = _validateAndDecodeCall(userOp, userOpHash);
    address signer = _getSigner(userOp, userOpHash);
    if (!_isAuthorized(signer, expectedSigner, call.target)) {
      return SIG_VALIDATION_FAILED;
    }
    return SIG_VALIDATION_SUCCESS;
  }

  /**
   * @dev Executes a user operation by forwarding the call to the target contract with the signer as the msgSender.
   *      The calldata is expected to contain this function's selector followed by the signer and the ABI-encoded call:
   *         - signer (address): the signer of the userop, must match the signature
   *         - dest (address): the target contract address (must be the same as _target)
   *         - value (uint256): the amount of ETH to send with the call
   *         - func (bytes): the calldata for the target function
   *
   * @param userOp The packed user operation containing the call data and signature.
   * @param userOpHash The hash of the user operation, used for signature verification.
   */
  function executeUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash) external override {
    _requireFromEntryPoint();

    (address expectedSigner, Call memory call, ) = _validateAndDecodeCall(userOp, userOpHash);

    Address.functionCallWithValue(call.target, abi.encodePacked(call.data, expectedSigner), call.value);
  }

  /**
   * @notice Forwards a call to the target contract with `caller` as the msgSender.
   * @dev Since this method is called from the entryPoint, the method _validateSignature was passed before,
   *      validating the signer of the userOp is equal to `caller` and `caller` is authorized to call `target`.
   *
   * @param caller The real caller of the operation that will be appended to the call, and decoded by the target
   *               contract as _msgSender()
   * @param target The target contract to be called
   * @param value The amount of ETH to send with the call
   * @param func The calldata for the target function
   */
  function erc2771Forward(address caller, address target, uint256 value, bytes calldata func) external virtual {
    _requireFromEntryPoint();
    Address.functionCallWithValue(target, abi.encodePacked(func, caller), value);
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
