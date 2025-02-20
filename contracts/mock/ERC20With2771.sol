//SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC2771Context} from "@openzeppelin/contracts/metatx/ERC2771Context.sol";
import {Context} from "@openzeppelin/contracts/utils/Context.sol";

contract ERC20With2771 is ERC20, ERC2771Context {
  uint8 internal immutable _decimals;

  constructor(
    string memory name_,
    string memory symbol_,
    uint256 initialSupply,
    uint8 decimals_,
    address trustedForwarder
  ) ERC20(name_, symbol_) ERC2771Context(trustedForwarder) {
    _decimals = decimals_;
    _mint(msg.sender, initialSupply);
  }

  function decimals() public view virtual override returns (uint8) {
    return _decimals;
  }

  /// @inheritdoc ERC2771Context
  function _contextSuffixLength() internal view override(Context, ERC2771Context) returns (uint256) {
    return ERC2771Context._contextSuffixLength();
  }

  /// @inheritdoc ERC2771Context
  function _msgSender() internal view override(Context, ERC2771Context) returns (address) {
    return ERC2771Context._msgSender();
  }

  /// @inheritdoc ERC2771Context
  function _msgData() internal view override(Context, ERC2771Context) returns (bytes calldata) {
    return ERC2771Context._msgData();
  }
}
