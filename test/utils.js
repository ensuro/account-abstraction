import { setupChain } from "@ensuro/utils/js/test-utils";

export async function loadFixtureOnFork(fixture, forkBlock = null) {
  const connection = await setupChain(forkBlock);
  return connection.networkHelpers.loadFixture(fixture);
}
