//SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

import {ERC2771Context} from "@openzeppelin/contracts/metatx/ERC2771Context.sol";

/// @dev A contract simulating a realistic workload for userops and bundles: looping over a large
///      calldata payload with several storage writes per item.
contract MockWorkload is ERC2771Context {
  struct Record {
    bytes32 hash;
    bytes32 derived;
    address caller;
  }

  uint256 private constant ROUNDS = 8;

  mapping(uint256 id => Record) public records;
  mapping(bytes32 digest => uint256 id) public digests;
  mapping(address caller => uint256) public itemsBy;
  uint256 public count;

  event Stored(uint256 indexed id, address indexed caller);

  constructor(address forwarder) ERC2771Context(forwarder) {}

  function store(bytes[] calldata items) external {
    address caller = _msgSender();
    uint256 n = count;
    for (uint256 i = 0; i < items.length; ++i) {
      bytes32 h = _digest(items[i]);
      records[++n] = Record(h, keccak256(abi.encode(h, caller)), caller);
      digests[h] = n;
      emit Stored(n, caller);
    }
    count = n;
    itemsBy[caller] += items.length;
  }

  function _digest(bytes calldata blob) private pure returns (bytes32 h) {
    h = keccak256(blob);
    for (uint256 i = 0; i < ROUNDS; ++i) h = keccak256(abi.encode(h, i));
  }
}
