import { _W } from "@ensuro/utils/js/utils";
import { expect } from "chai";
import { anyValue } from "@nomicfoundation/hardhat-ethers-chai-matchers/withArgs";

import { getUserOpHash, packUserOp, packedUserOpAsArray, signUserOp, fillUserOpDefaults } from "../js/userOp.js";
import { loadFixtureOnFork, TestUserOp } from "./utils.js";

// Concise smoke tests for Simple7702AccountV07: delegate an EOA to the implementation via EIP-7702,
// then drive it through the v0.7 EntryPoint. Not exhaustive.

const ENTRYPOINT = "0x0000000071727De22E5E9d8BAf0edAc6f37da032"; // canonical v0.7 EntryPoint

async function setup(connection) {
  const { ethers, networkHelpers: helpers } = connection;
  const [deployer, recipient, anon] = await ethers.getSigners();

  const ep = await ethers.getContractAt("IEntryPoint", ENTRYPOINT);
  const Simple7702AccountV07 = await ethers.getContractFactory("Simple7702AccountV07");
  const impl = await Simple7702AccountV07.deploy();

  // The EOA whose key we control; after the 7702 delegation it *is* the account.
  const eoa = ethers.Wallet.createRandom(ethers.provider);
  await helpers.setBalance(eoa.address, _W(10));

  const auth = await eoa.authorize({ address: await impl.getAddress() });
  await deployer.sendTransaction({ type: 4, to: eoa.address, authorizationList: [auth] });
  const account = Simple7702AccountV07.attach(eoa.address);

  await helpers.impersonateAccount(ENTRYPOINT);
  const epSigner = await ethers.getSigner(ENTRYPOINT);

  return { account, anon, eoa, ep, epSigner, ethers, impl, recipient };
}

async function buildUserOp(ethers, account, eoa, signer, callData) {
  const { chainId } = await ethers.provider.getNetwork();
  const userOp = await signUserOp(
    fillUserOpDefaults({ sender: eoa.address, nonce: await account.getNonce(), callData }, TestUserOp),
    signer,
    ENTRYPOINT,
    chainId
  );
  return {
    packedUserOp: packedUserOpAsArray(packUserOp(userOp), true),
    userOpHash: getUserOpHash(userOp, ENTRYPOINT, chainId),
  };
}

describe("Simple7702AccountV07 smoke tests", function () {
  it("entryPoint() returns the v0.7 EntryPoint", async () => {
    const { impl } = await loadFixtureOnFork(setup);
    expect(await impl.entryPoint()).to.equal(ENTRYPOINT);
  });

  it("executes a userOp end-to-end through the v0.7 EntryPoint", async () => {
    const { account, anon, eoa, ep, epSigner, ethers, recipient } = await loadFixtureOnFork(setup);

    const callData = account.interface.encodeFunctionData("execute", [recipient.address, _W(1), "0x"]);
    const { packedUserOp, userOpHash } = await buildUserOp(ethers, account, eoa, eoa, callData);

    // Sanity: the signature (EIP-191 personal-sign of userOpHash, recovered to address(this) == eoa) validates.
    const validationData = await account.connect(epSigner).validateUserOp.staticCall(packedUserOp, userOpHash, 0n);
    expect(validationData).to.equal(0n);

    const tx = await ep.handleOps([packedUserOp], anon.address, { gasLimit: 1000000n });

    // These assertions cannot be chained (see test-forwarder-account.js).
    await expect(tx)
      .to.emit(ep, "UserOperationEvent")
      .withArgs(userOpHash, eoa.address, anyValue, anyValue, true, anyValue, anyValue);
    await expect(tx).to.changeEtherBalance(ethers, recipient, _W(1));
  });

  it("only allows execute() from the account itself or the EntryPoint", async () => {
    const { account, anon, eoa, ethers, recipient } = await loadFixtureOnFork(setup);

    await expect(account.connect(anon).execute(recipient.address, 0, "0x")).to.be.revertedWith(
      "not from self or EntryPoint"
    );

    await expect(account.connect(eoa).execute(recipient.address, 123n, "0x")).to.changeEtherBalance(
      ethers,
      recipient,
      123n
    );
  });

  it("rejects a userOp signed by a different key (no revert)", async () => {
    const { account, anon, eoa, epSigner, ethers, recipient } = await loadFixtureOnFork(setup);

    const callData = account.interface.encodeFunctionData("execute", [recipient.address, _W(1), "0x"]);
    const { packedUserOp, userOpHash } = await buildUserOp(ethers, account, eoa, anon, callData);

    const validationData = await account.connect(epSigner).validateUserOp.staticCall(packedUserOp, userOpHash, 0n);
    expect(validationData).to.equal(1n);
  });
});
