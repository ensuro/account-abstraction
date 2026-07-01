//SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

import {ERC2771Context} from "@openzeppelin/contracts/metatx/ERC2771Context.sol";

/// @dev Test target that reveals how it was called: the ERC2771 sender, the calldata length
///      (4 with no appended sender, 24 when the forwarder appends one) and the forwarded value.
contract ERC2771Probe is ERC2771Context {
  event Pinged(address sender, uint256 dataLength, uint256 value);

  constructor(address trustedForwarder) ERC2771Context(trustedForwarder) {}

  function ping() external payable {
    emit Pinged(_msgSender(), msg.data.length, msg.value);
  }
}
