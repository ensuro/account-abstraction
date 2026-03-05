import { initCurrency, initForkCurrency } from "@ensuro/utils/js/test-utils";
import { _W, amountFunction, getAddress, getRole } from "@ensuro/utils/js/utils";
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
  const { ethers } = connection;
  const [, exec1, exec2, anon, withdraw, admin] = await ethers.getSigners();

  const ep = await ethers.getContractAt("IEntryPoint", ADDRESSES.ENTRYPOINT);
  const ERC2771ForwarderAccount = await ethers.getContractFactory("ERC2771ForwarderAccount");
  const account = await ERC2771ForwarderAccount.deploy(ep, admin, [exec1, exec2]);
  await expect(account.addDeposit({ value: _W(9) })).to.changeEtherBalance(ethers, ep, _W(9));
  const usdc = await initCurrency(
    ethers,
    { decimals: 6, initial_supply: _A(10000), extraArgs: [account], contractClass: "ERC20With2771" },
    [exec1, exec2],
    [_A(100), _A(100)]
  );
  const roles = {
    admin: getRole("DEFAULT_ADMIN_ROLE"),
    exec: getRole("EXECUTOR_ROLE"),
    withdraw: getRole("WITHDRAW_ROLE"),
  };

  return {
    ep,
    ERC2771ForwarderAccount,
    account,
    exec1,
    exec2,
    anon,
    withdraw,
    admin,
    roles,
    usdc,
    ethers,
    connection,
    helpers: connection.networkHelpers,
  };
}

describe(`ERC2771ForwarderAccount specific tests`, function () {
  it("Forwards the signer as sender to the target contract", async () => {
    const { account, anon, exec1, exec2, admin, roles, usdc, ethers, helpers, ep } = await loadFixtureOnFork(setup);

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
      ethers.AbiCoder.defaultAbiCoder().encode(["address", "uint256", "bytes"], [usdc.target, 0, transferCall]),
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
    await helpers.impersonateAccount(ep.target);
    const epSigner = await ethers.getSigner(ep.target);
    const validationData = await account.connect(epSigner).validateUserOp.staticCall(packedUserOp, userOpHash, 0n);
    await expect(validationData).to.equal(0);

    // Send the userOp
    const tx = await ep.handleOps([packedUserOp], anon);

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
});
