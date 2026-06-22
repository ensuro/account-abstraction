//SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

import {AccessManager} from "@openzeppelin/contracts/access/manager/AccessManager.sol";

/// @dev Stock OZ AccessManager, exposed for tests as the authority of an AccessManaged contract
///      (the local artifact name avoids the collision with the forked dependencies/AccessManager).
contract MockAccessManager is AccessManager {
  constructor(address admin) AccessManager(admin) {}
}
