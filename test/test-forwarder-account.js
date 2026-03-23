import { initCurrency } from "@ensuro/utils/js/test-utils";
import { _W, amountFunction, getAddress, getRole, AM_ROLES } from "@ensuro/utils/js/utils";
import { expect } from "chai";
import { MaxUint256, ZeroAddress } from "ethers";
import hre from "hardhat";
import { anyValue } from "@nomicfoundation/hardhat-ethers-chai-matchers/withArgs";

import { getUserOpHash, packUserOp, packedUserOpAsArray, signUserOp, fillUserOpDefaults } from "../js/userOp.js";
import { loadFixtureOnFork, TestUserOp } from "./utils.js";

const _A = amountFunction(6);
const ADDRESSES = {
  // polygon mainnet addresses
  USDC: "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174",
  USDCWhale: "0x4d97dcd97ec945f40cf65f87097ace5ea0476045",
  ENTRYPOINT: "0x0000000071727De22E5E9d8BAf0edAc6f37da032",
};

async function setup(connection) {
  const { ethers, networkHelpers: helpers } = connection;
  const [deployer, exec1, exec2, anon, withdraw, admin] = await ethers.getSigners();

  const ep = await ethers.getContractAt("IEntryPoint", ADDRESSES.ENTRYPOINT);
  const ERC2771ForwarderAccount = await ethers.getContractFactory("ERC2771ForwarderAccount");
  const account = await ERC2771ForwarderAccount.deploy(ep);

  await helpers.impersonateAccount(ep.target);
  const epSigner = await ethers.getSigner(ep.target);

  const usdc = await initCurrency(
    ethers,
    { decimals: 6, initial_supply: _A(10000), extraArgs: [account], contractClass: "ERC20With2771" },
    [exec1, exec2],
    [_A(100), _A(100)]
  );

  await account.addExecutor(getAddress(exec1), usdc);
  await account.addExecutor(getAddress(exec2), usdc);

  await expect(account.addDeposit({ value: _W(9) })).to.changeEtherBalance(ethers, ep, _W(9));

  return {
    account,
    admin,
    anon,
    connection,
    ep,
    epSigner,
    ERC2771ForwarderAccount,
    ethers,
    exec1,
    exec2,
    helpers: connection.networkHelpers,
    usdc,
    withdraw,
  };
}

describe(`ERC2771ForwarderAccount specific tests`, function () {
  it("Forwards the signer as sender to the target contract", async () => {
    const { account, anon, exec1, exec2, admin, roles, usdc, ethers, helpers, ep, epSigner } =
      await loadFixtureOnFork(setup);

    // Account 'exec2' has granted infinite allowance to 'exec1' on 'usdc'
    await usdc.connect(exec2).approve(getAddress(exec1), MaxUint256);
    expect(await usdc.allowance(exec2, exec1)).to.equal(MaxUint256);

    // UserOp call signed by 'exec1', forwards exec1 as sender
    const transferCall = usdc.interface.encodeFunctionData("transferFrom", [
      getAddress(exec2),
      getAddress(anon),
      _A(10),
    ]);

    const executeUserOpData = ethers.concat([
      account.interface.getFunction("executeUserOp").selector,
      ethers.AbiCoder.defaultAbiCoder().encode(
        ["address", "address", "uint256", "bytes"],
        [getAddress(exec1), usdc.target, 0, transferCall]
      ),
    ]);

    const nonce = await account.getNonce();
    const { chainId } = await ethers.provider.getNetwork();
    const userOp = await signUserOp(
      fillUserOpDefaults(
        {
          sender: getAddress(account),
          nonce: nonce,
          callData: executeUserOpData,
        },
        TestUserOp
      ),
      exec1,
      ADDRESSES.ENTRYPOINT,
      chainId
    );
    const packedUserOp = packedUserOpAsArray(packUserOp(userOp), true);
    const userOpHash = getUserOpHash(userOp, ADDRESSES.ENTRYPOINT, chainId);

    // Sanity check: the user op's signature validates

    const validationData = await account.connect(epSigner).validateUserOp.staticCall(packedUserOp, userOpHash, 0n);
    await expect(validationData).to.equal(0);

    // Send the userOp
    const tx = await ep.handleOps([packedUserOp], anon, { gasLimit: 1000000n });

    // These assertions cannot be chained: https://hardhat.org/docs/plugins/hardhat-ethers-chai-matchers#chaining-async-matchers
    // The UserOperationEvent check is not really necessary, but helps understand what's failing if the test fails
    await expect(tx)
      .to.emit(ep, "UserOperationEvent")
      .withArgs(userOpHash, getAddress(account), anyValue, anyValue, true, anyValue, anyValue);

    await expect(tx).to.changeTokenBalances(
      ethers,
      usdc,
      [exec2, anon, exec1, account],
      [_A(-10), _A(10), _A(0), _A(0)]
    );
  });

  it("erc2771Forward works the same as executeUserOp", async () => {
    const { account, anon, exec1, exec2, admin, roles, usdc, ethers, helpers, ep, epSigner } =
      await loadFixtureOnFork(setup);

    const transferCall = usdc.interface.encodeFunctionData("transfer", [getAddress(anon), _A(5)]);

    const erc2771ForwardData = ethers.concat([
      account.interface.getFunction("erc2771Forward").selector,
      ethers.AbiCoder.defaultAbiCoder().encode(
        ["address", "address", "uint256", "bytes"],
        [getAddress(exec1), usdc.target, 0, transferCall]
      ),
    ]);

    // The call to erc2771Forward can be made more easily, without encoding black magic
    const erc2771ForwardDataSimple = account.interface.encodeFunctionData("erc2771Forward", [
      getAddress(exec1),
      usdc.target,
      0,
      transferCall,
    ]);
    expect(erc2771ForwardData).to.equal(erc2771ForwardDataSimple);

    const nonce = await account.getNonce();
    const { chainId } = await ethers.provider.getNetwork();
    const userOp = await signUserOp(
      fillUserOpDefaults(
        {
          sender: getAddress(account),
          nonce: nonce,
          callData: erc2771ForwardData,
        },
        TestUserOp
      ),
      exec1,
      ADDRESSES.ENTRYPOINT,
      chainId
    );
    const packedUserOp = packedUserOpAsArray(packUserOp(userOp), true);
    const userOpHash = getUserOpHash(userOp, ADDRESSES.ENTRYPOINT, chainId);

    const validationData = await account.connect(epSigner).validateUserOp.staticCall(packedUserOp, userOpHash, 0n);
    await expect(validationData).to.equal(0);

    const tx = await ep.handleOps([packedUserOp], anon, { gasLimit: 1000000n });

    await expect(tx)
      .to.emit(ep, "UserOperationEvent")
      .withArgs(userOpHash, getAddress(account), anyValue, anyValue, true, anyValue, anyValue);

    await expect(tx).to.changeTokenBalances(ethers, usdc, [exec1, anon], [_A(-5), _A(5)]);
  });

  it("Does not allow execute or executeBatch", async () => {
    const { account, anon, exec1, exec2, admin, roles, usdc, ethers, helpers, ep, epSigner } =
      await loadFixtureOnFork(setup);

    await expect(account.connect(anon).execute(getAddress(usdc), 0, "0x")).to.be.revertedWithCustomError(
      account,
      "InvalidCall"
    );
    await expect(
      account.connect(anon).executeBatch([{ target: getAddress(usdc), value: 0, data: "0x" }])
    ).to.be.revertedWithCustomError(account, "InvalidCall");
  });

  it("Allows deposit and withdraw into the EntryPoint", async () => {
    const { account, anon, exec1, exec2, admin, roles, usdc, ethers, helpers, ep, withdraw } =
      await loadFixtureOnFork(setup);

    const balanceBefore = await account.getDeposit();
    await expect(account.addDeposit({ value: _W(1) })).to.changeEtherBalance(ethers, ep, _W(1));
    expect(await account.getDeposit()).to.equal(balanceBefore + _W(1));

    await expect(account.withdrawDepositTo(getAddress(withdraw), _W(0.5))).to.changeEtherBalance(
      ethers,
      withdraw,
      _W(0.5)
    );
  });

  it("Can add executors", async () => {
    const { account, anon, exec1, exec2, admin, roles, usdc, ethers, helpers, ep, epSigner } =
      await loadFixtureOnFork(setup);

    const transferCall = usdc.interface.encodeFunctionData("transferFrom", [
      getAddress(exec2),
      getAddress(anon),
      _A(10),
    ]);

    const executeUserOpData = ethers.concat([
      account.interface.getFunction("executeUserOp").selector,
      ethers.AbiCoder.defaultAbiCoder().encode(
        ["address", "address", "uint256", "bytes"],
        [getAddress(anon), usdc.target, 0, transferCall]
      ),
    ]);

    const { chainId } = await ethers.provider.getNetwork();
    const userOp = await signUserOp(
      fillUserOpDefaults(
        {
          sender: getAddress(account),
          nonce: await account.getNonce(),
          callData: executeUserOpData,
        },
        TestUserOp
      ),
      anon, // signed by 'anon', who is not an executor
      ADDRESSES.ENTRYPOINT,
      chainId
    );
    const packedUserOp = packedUserOpAsArray(packUserOp(userOp), true);
    const userOpHash = getUserOpHash(userOp, ADDRESSES.ENTRYPOINT, chainId);

    // The signature is not accepted
    const validationData = await account.connect(epSigner).validateUserOp.staticCall(packedUserOp, userOpHash, 0n);
    await expect(validationData).to.equal(1);

    // Add 'anon' as executor with 'usdc' as target
    await expect(account.addExecutor(getAddress(anon), usdc))
      .to.emit(account, "ExecutorAdded")
      .withArgs(getAddress(anon), usdc);

    // The signature is now accepted
    const validationDataAfterAddition = await account
      .connect(epSigner)
      .validateUserOp.staticCall(packedUserOp, userOpHash, 0n);
    await expect(validationDataAfterAddition).to.equal(0);
  });

  it("Can remove executors", async () => {
    const { account, anon, exec1, exec2, admin, roles, usdc, ethers, helpers, ep, epSigner } =
      await loadFixtureOnFork(setup);

    const { chainId } = await ethers.provider.getNetwork();
    const userOp = await signUserOp(
      fillUserOpDefaults(
        {
          sender: getAddress(account),
          nonce: await account.getNonce(),
          callData: ethers.concat([
            account.interface.getFunction("executeUserOp").selector,
            ethers.AbiCoder.defaultAbiCoder().encode(
              ["address", "address", "uint256", "bytes"],
              [getAddress(exec1), usdc.target, 0, usdc.interface.encodeFunctionData("decimals", [])]
            ),
          ]),
        },
        TestUserOp
      ),
      exec1,
      ADDRESSES.ENTRYPOINT,
      chainId
    );
    const packedUserOp = packedUserOpAsArray(packUserOp(userOp), true);
    const userOpHash = getUserOpHash(userOp, ADDRESSES.ENTRYPOINT, chainId);

    // The signature is accepted
    const validationData = await account.connect(epSigner).validateUserOp.staticCall(packedUserOp, userOpHash, 0n);
    await expect(validationData).to.equal(0);

    // Remove exec1 as executor
    await expect(account.removeExecutor(getAddress(exec1)))
      .to.emit(account, "ExecutorRemoved")
      .withArgs(getAddress(exec1));

    // The signature is no longer accepted
    const validationDataAfterRemoval = await account
      .connect(epSigner)
      .validateUserOp.staticCall(packedUserOp, userOpHash, 0n);
    await expect(validationDataAfterRemoval).to.equal(1);
  });

  it("Validates that the expected signer matches the actual signer", async () => {
    const { account, anon, exec1, exec2, admin, roles, usdc, ethers, helpers, ep, epSigner } =
      await loadFixtureOnFork(setup);

    // UserOp call signed by 'exec1', forwards exec2 as sender
    const transferCall = usdc.interface.encodeFunctionData("transfer", [getAddress(anon), _A(10)]);

    const executeUserOpData = ethers.concat([
      account.interface.getFunction("executeUserOp").selector,
      ethers.AbiCoder.defaultAbiCoder().encode(
        ["address", "address", "uint256", "bytes"],
        // wrongly set the expectedSigner as exec2 instead of exec1
        [getAddress(exec2), usdc.target, 0, transferCall]
      ),
    ]);

    const nonce = await account.getNonce();
    const { chainId } = await ethers.provider.getNetwork();
    const userOp = await signUserOp(
      fillUserOpDefaults(
        {
          sender: getAddress(account),
          nonce: nonce,
          callData: executeUserOpData,
        },
        TestUserOp
      ),
      exec1, // expectedSigner was set to exec2, but the userOp is signed by exec1
      ADDRESSES.ENTRYPOINT,
      chainId
    );
    const packedUserOp = packedUserOpAsArray(packUserOp(userOp), true);
    const userOpHash = getUserOpHash(userOp, ADDRESSES.ENTRYPOINT, chainId);

    // The userOp signature does not validate, even though exec2 is an executor
    const validationData = await account.connect(epSigner).validateUserOp.staticCall(packedUserOp, userOpHash, 0n);
    await expect(validationData).to.equal(1);

    // Calling executeUserOp directly is not allowed
    await expect(account.connect(exec1).executeUserOp(packedUserOp, userOpHash)).to.be.revertedWith(
      "account: not from EntryPoint"
    );

    // A malicious entrypoint could do that though, in that case usdc sees exec2 as sender
    await expect(account.connect(epSigner).executeUserOp(packedUserOp, userOpHash))
      .to.emit(usdc, "Transfer")
      .withArgs(getAddress(exec2), getAddress(anon), _A(10));
  });
});
