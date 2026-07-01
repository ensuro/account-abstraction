import hre from "hardhat";
import { setupChain } from "@ensuro/utils/js/test-utils";
import { DefaultsForUserOp } from "../js/userOp.js";

const connectionCache = {};

export async function loadFixtureOnFork(fixture, forkBlock = null) {
  const connection = connectionCache[forkBlock] || (await setupChain(forkBlock));
  connectionCache[forkBlock] = connection;
  return connection.networkHelpers.loadFixture(fixture);
}

// For contracts with no mainnet dependency (e.g. UnifiedForwarderAccount): runs on the in-memory
// network, so it needs no ALCHEMY_URL and is much faster than forking.
let localConnection = null;
export async function loadFixtureLocal(fixture) {
  localConnection = localConnection || (await hre.network.connect());
  return localConnection.networkHelpers.loadFixture(fixture);
}

export const TestUserOp = {
  ...DefaultsForUserOp,
  callGasLimit: 200000n,
  verificationGasLimit: 200000n,
  preVerificationGas: 100000n,
};
