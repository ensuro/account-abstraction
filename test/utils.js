import { setupChain } from "@ensuro/utils/js/test-utils";
import { DefaultsForUserOp } from "../js/userOp.js";

const connectionCache = {};

export async function loadFixtureOnFork(fixture, forkBlock = null) {
  const connection = connectionCache[forkBlock] || (await setupChain(forkBlock));
  connectionCache[forkBlock] = connection;
  return connection.networkHelpers.loadFixture(fixture);
}

export const TestUserOp = {
  ...DefaultsForUserOp,
  callGasLimit: 200000n,
  verificationGasLimit: 200000n,
  preVerificationGas: 100000n,
};
