import { getAddress } from "@ensuro/utils/js/utils";
import { expect } from "chai";
import { id } from "ethers";

import { packUserOp, packedUserOpAsArray, signUserOp, fillUserOpDefaults } from "../js/userOp.js";
import { loadFixtureLocal, TestUserOp } from "./utils.js";

// Reference-scale bundle: 5 userops over a large, storage-heavy workload
// Gas is read from `--gas-stats` (the handleOps row), not asserted here.
const OPS = 5;
const ITEMS_PER_OP = 28;
const BLOB_BYTES = 256;
const TAG = id("executeUserOp((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes),bytes32)").slice(0, 10);

function buildCallData(ethers, signer, target, value, data) {
  return ethers.concat([
    TAG,
    ethers.AbiCoder.defaultAbiCoder().encode(["address", "address", "uint256", "bytes"], [signer, target, value, data]),
  ]);
}

async function setup(connection) {
  const { ethers } = connection;
  const [deployer, signer1, signer2, anon] = await ethers.getSigners();

  const UnifiedForwarderAccount = await ethers.getContractFactory("UnifiedForwarderAccount");
  const startNonce = await deployer.getNonce();
  const predictedWorkload = ethers.getCreateAddress({ from: deployer.address, nonce: startNonce + 1 });

  const account = await UnifiedForwarderAccount.deploy(predictedWorkload, [signer1, signer2]);
  const workload = await (await ethers.getContractFactory("MockWorkload")).deploy(getAddress(account));
  const { chainId } = await ethers.provider.getNetwork();

  return { ethers, account, workload, signer1, signer2, anon, chainId };
}

describe("UnifiedForwarderAccount realistic workload", function () {
  it("Processes a reference-scale storage-heavy bundle", async () => {
    const { ethers, account, workload, signer1, signer2, anon, chainId } = await loadFixtureLocal(setup);
    expect(await account.erc2771Target()).to.equal(getAddress(workload));

    // distinct blobs so every item writes cold storage slots (no warm-slot discounts)
    let seq = 0;
    const makeItems = () =>
      Array.from(
        { length: ITEMS_PER_OP },
        () => "0x" + (seq++).toString(16).padStart(64, "0") + "cd".repeat(BLOB_BYTES - 32)
      );

    const opSigners = [signer1, signer1, signer1, signer1, signer2];
    const ops = [];
    for (let i = 0; i < OPS; i++) {
      const storeData = workload.interface.encodeFunctionData("store", [makeItems()]);
      const callData = buildCallData(ethers, getAddress(opSigners[i]), getAddress(workload), 0, storeData);
      const op = await signUserOp(
        fillUserOpDefaults(
          { sender: getAddress(account), nonce: BigInt(i + 1) << 64n, callData, callGasLimit: 3000000n },
          TestUserOp
        ),
        opSigners[i],
        getAddress(account),
        chainId
      );
      ops.push(packedUserOpAsArray(packUserOp(op), true));
    }

    const rcpt = await (await account.handleOps(ops, getAddress(anon), { gasLimit: 16000000n })).wait();

    const ev = account.interface.getEvent("UserOperationEvent");
    const ok = rcpt.logs.filter(
      (l) => l.topics[0] === ev.topicHash && account.interface.decodeEventLog(ev, l.data, l.topics).success
    ).length;
    expect(ok).to.equal(OPS);

    expect(await workload.count()).to.equal(OPS * ITEMS_PER_OP);
    expect(await workload.itemsBy(signer1)).to.equal(4 * ITEMS_PER_OP);
    expect(await workload.itemsBy(signer2)).to.equal(1 * ITEMS_PER_OP);

    // The assertions on these test are not very relevant, it's mostly used to measure gas usage
    // and provide a baseline for future optimizations.
  });
});
