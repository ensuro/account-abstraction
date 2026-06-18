// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {ERC1155Holder} from "@openzeppelin/contracts/token/ERC1155/utils/ERC1155Holder.sol";
import {IERC1155Receiver} from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";
import {ERC721Holder} from "@openzeppelin/contracts/token/ERC721/utils/ERC721Holder.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {BaseAccount} from "@account-abstraction/contracts/core/BaseAccount.sol";
import {IAccount} from "@account-abstraction/contracts/interfaces/IAccount.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {SIG_VALIDATION_SUCCESS, SIG_VALIDATION_FAILED} from "@account-abstraction/contracts/core/Helpers.sol";

/**
 * Simple7702AccountV07
 *
 * Copy of eth-infinitism's Simple7702Account (v0.8.0, accounts/Simple7702Account.sol in the
 * account-abstraction package) retargeted to the v0.7 EntryPoint. Copied instead of
 * inherited+overridden because the original does not mark `entryPoint()` / `_checkSignature()`
 * as `virtual`.
 *
 * Only two things differ from the original:
 *   1. `entryPoint()` returns the v0.7 EntryPoint (`0x0000000071727De22E5E9d8BAf0edAc6f37da032`).
 *   2. `_checkSignature()` recovers from the EIP-191 personal-sign digest of the hash
 *      (`toEthSignedMessageHash(hash)`) before comparing against `address(this)`.
 */
contract Simple7702AccountV07 is BaseAccount, IERC165, IERC1271, ERC1155Holder, ERC721Holder {
  function entryPoint() public pure override returns (IEntryPoint) {
    return IEntryPoint(0x0000000071727De22E5E9d8BAf0edAc6f37da032);
  }

  /**
   * Make this account callable through ERC-4337 EntryPoint.
   * The UserOperation should be signed by this account's private key.
   */
  function _validateSignature(
    PackedUserOperation calldata userOp,
    bytes32 userOpHash
  ) internal virtual override returns (uint256 validationData) {
    return _checkSignature(userOpHash, userOp.signature) ? SIG_VALIDATION_SUCCESS : SIG_VALIDATION_FAILED;
  }

  function isValidSignature(bytes32 hash, bytes memory signature) public view returns (bytes4 magicValue) {
    return _checkSignature(hash, signature) ? this.isValidSignature.selector : bytes4(0xffffffff);
  }

  function _checkSignature(bytes32 hash, bytes memory signature) internal view returns (bool) {
    return ECDSA.recover(MessageHashUtils.toEthSignedMessageHash(hash), signature) == address(this);
  }

  function _requireForExecute() internal view virtual override {
    // solhint-disable-next-line gas-custom-errors
    require(msg.sender == address(this) || msg.sender == address(entryPoint()), "not from self or EntryPoint");
  }

  function supportsInterface(bytes4 id) public pure override(ERC1155Holder, IERC165) returns (bool) {
    return
      id == type(IERC165).interfaceId ||
      id == type(IAccount).interfaceId ||
      id == type(IERC1271).interfaceId ||
      id == type(IERC1155Receiver).interfaceId ||
      id == type(IERC721Receiver).interfaceId;
  }

  // accept incoming calls (with or without value), to mimic an EOA.
  // solhint-disable-next-line no-empty-blocks
  fallback() external payable {}

  // solhint-disable-next-line no-empty-blocks
  receive() external payable {}
}
