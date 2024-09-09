const { expect } = require("chai");
const { _W, getRole, amountFunction, getAddress } = require("@ensuro/core/js/utils");
const { setupChain, initForkCurrency } = require("@ensuro/core/js/test-utils");
const hre = require("hardhat");
const helpers = require("@nomicfoundation/hardhat-network-helpers");
const withArgs = require("@nomicfoundation/hardhat-chai-matchers/withArgs");

const { ethers } = hre;
const { MaxUint256, ZeroAddress } = hre.ethers;
const { getUserOpHash, packUserOp, packedUserOpAsArray, packAccountGasLimits } = require("../js/userOp.js");

const _A = amountFunction(6);
const ADDRESSES = {
  // polygon mainnet addresses
  USDC: "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174",
  USDCWhale: "0x4d97dcd97ec945f40cf65f87097ace5ea0476045",
  ENTRYPOINT: "0x0000000071727De22E5E9d8BAf0edAc6f37da032",
};

const ADMIN_ROLE = 0;
const EXECUTOR_ROLE = 1;
const WITHDRAW_ROLE = 2;
const USDC_ROLE = 3;

async function setUp() {
  const [, exec1, exec2, anon, withdraw, admin] = await ethers.getSigners();

  const roles = {
    admin: ADMIN_ROLE,
    exec: EXECUTOR_ROLE,
    withdraw: WITHDRAW_ROLE,
    usdc: USDC_ROLE,
  };

  const usdc = await initForkCurrency(ADDRESSES.USDC, ADDRESSES.USDCWhale, [exec1, exec2], [_A(100), _A(100)]);
  const ep = await ethers.getContractAt("IEntryPoint", ADDRESSES.ENTRYPOINT);
  const AccessManagerAccount = await ethers.getContractFactory("AccessManagerAccount");

  // Setup executor role
  const acAcc = await AccessManagerAccount.deploy(ep, admin);
  await acAcc.connect(admin).labelRole(roles.exec, "EXECUTOR_ROLE");
  await acAcc.connect(admin).grantRole(roles.exec, exec1, 0);
  await acAcc.connect(admin).grantRole(roles.exec, exec2, 0);
  await acAcc
    .connect(admin)
    .setTargetFunctionRole(acAcc, [acAcc.interface.getFunction("execute(address,uint256,bytes)").selector], roles.exec);

  // Setup withdraw role
  await acAcc.connect(admin).labelRole(roles.withdraw, "WITHDRAW_ROLE");
  await acAcc
    .connect(admin)
    .setTargetFunctionRole(acAcc, [acAcc.interface.getFunction("withdrawDepositTo").selector], roles.withdraw);

  // Setup USDC role
  await acAcc.connect(admin).labelRole(roles.usdc, "USDC_ROLE");
  await acAcc.connect(admin).setTargetFunctionRole(usdc, [usdc.interface.getFunction("approve").selector], roles.usdc);
  await acAcc.connect(admin).setTargetFunctionRole(usdc, [usdc.interface.getFunction("transfer").selector], roles.usdc);

  return {
    ep,
    AccessManagerAccount,
    acAcc,
    exec1,
    exec2,
    roles,
    anon,
    withdraw,
    admin,
    usdc,
  };
}

describe("AccessControlAccount contract tests", function () {
  before(async () => {
    await setupChain(null);
  });

  it("Constructs with the right permissions and EP", async () => {
    const { acAcc, anon, exec1, exec2, admin, roles } = await helpers.loadFixture(setUp);
    expect(await acAcc.hasRole(roles.admin, admin)).to.deep.equal([true, 0]);
    expect(await acAcc.hasRole(roles.admin, anon)).to.deep.equal([false, 0]);
    expect(await acAcc.hasRole(roles.exec, exec1)).to.deep.equal([true, 0]);
    expect(await acAcc.hasRole(roles.exec, exec2)).to.deep.equal([true, 0]);
    expect(await acAcc.hasRole(roles.exec, anon)).to.deep.equal([false, 0]);
    expect(await acAcc.entryPoint()).to.equal(ADDRESSES.ENTRYPOINT);
  });

  it("Can receive eth, deposits and only WITHDRAW_ROLE can withdraw", async () => {
    const { acAcc, anon, withdraw, admin, roles, ep } = await helpers.loadFixture(setUp);
    expect(await hre.ethers.provider.getBalance(acAcc)).to.equal(0);
    await expect(() => withdraw.sendTransaction({ to: acAcc, value: _W(1) })).to.changeEtherBalance(acAcc, _W(1));
    expect(await hre.ethers.provider.getBalance(acAcc)).to.equal(_W(1));

    await expect(() => acAcc.addDeposit({ value: _W(2) })).to.changeEtherBalance(ep, _W(2));
    expect(await ep.balanceOf(acAcc)).to.equal(_W(2));

    await expect(acAcc.connect(withdraw).withdrawDepositTo(anon, _W(1)))
      .to.be.revertedWithCustomError(acAcc, "AccessManagerUnauthorizedAccount")
      .withArgs(withdraw, roles.withdraw);

    await expect(acAcc.connect(anon).grantRole(roles.withdraw, withdraw, 0))
      .to.be.revertedWithCustomError(acAcc, "AccessManagerUnauthorizedAccount")
      .withArgs(anon, roles.admin);

    await expect(acAcc.connect(admin).grantRole(roles.withdraw, withdraw, 0)).not.to.be.reverted;
    expect(await acAcc.hasRole(roles.withdraw, withdraw)).to.deep.equal([true, 0]);

    await expect(() => acAcc.connect(withdraw).withdrawDepositTo(anon, _W("0.5"))).to.changeEtherBalance(
      anon,
      _W("0.5")
    );
    expect(await ep.balanceOf(acAcc)).to.equal(_W("1.5"));
    expect(await acAcc.getDeposit()).to.equal(_W("1.5"));
  });

  it("Can receive eth, deposits and only WITHDRAW_ROLE can withdraw - delay variant", async () => {
    const { acAcc, anon, withdraw, admin, roles, ep } = await helpers.loadFixture(setUp);
    expect(await hre.ethers.provider.getBalance(acAcc)).to.equal(0);
    await expect(() => withdraw.sendTransaction({ to: acAcc, value: _W(1) })).to.changeEtherBalance(acAcc, _W(1));
    expect(await hre.ethers.provider.getBalance(acAcc)).to.equal(_W(1));

    await expect(() => acAcc.addDeposit({ value: _W(2) })).to.changeEtherBalance(ep, _W(2));
    expect(await ep.balanceOf(acAcc)).to.equal(_W(2));

    await expect(acAcc.connect(withdraw).withdrawDepositTo(anon, _W(1)))
      .to.be.revertedWithCustomError(acAcc, "AccessManagerUnauthorizedAccount")
      .withArgs(withdraw, roles.withdraw);

    await expect(acAcc.connect(anon).grantRole(roles.withdraw, withdraw, 0))
      .to.be.revertedWithCustomError(acAcc, "AccessManagerUnauthorizedAccount")
      .withArgs(anon, roles.admin);

    await expect(acAcc.connect(admin).grantRole(roles.withdraw, withdraw, 600)).not.to.be.reverted;
    expect(await acAcc.hasRole(roles.withdraw, withdraw)).to.deep.equal([true, 600]);

    await expect(acAcc.connect(withdraw).withdrawDepositTo(anon, _W(1))).to.be.revertedWithCustomError(
      acAcc,
      "DelayNotAllowed"
    );

    // Leaving the rest of the test disabled because schedule doesn't work for withdrawDepositTo.
    // The reason is https://github.com/OpenZeppelin/openzeppelin-contracts/blob/c01a0fa27fb2d1546958be5d2cbbdd3fb565e4fa/contracts/access/manager/AccessManager.sol#L619
    // doesn't allow schedule of non-AccessManager methods, and checks differently the permissions when the target
    // is address(this)

    // const now = await helpers.time.latest();

    // const withdrawCall = acAcc.interface.encodeFunctionData("withdrawDepositTo", [getAddress(anon), _W("0.5")]);
    // const operationId = await acAcc.hashOperation(withdraw, acAcc, withdrawCall);

    // await expect(await acAcc.connect(withdraw).schedule(acAcc, withdrawCall, now + 1000))
    //   .to.emit(acAcc, "OperationScheduled")
    //   .withArgs(operationId, 0, now + 1000, withdraw, acAcc, withdrawCall);

    // await expect(() => acAcc.connect(withdraw).withdrawDepositTo(anon, _W("0.5"))).to.changeEtherBalance(
    //   anon,
    //   _W("0.5")
    // );
    // expect(await ep.balanceOf(acAcc)).to.equal(_W("1.5"));
    // expect(await acAcc.getDeposit()).to.equal(_W("1.5"));
  });

  it("Can execute when called through entryPoint", async () => {
    const { acAcc, anon, exec1, usdc, ep, admin, roles } = await helpers.loadFixture(setUp);
    const approveExec1 = usdc.interface.encodeFunctionData("approve", [getAddress(exec1), MaxUint256]);
    const executeCall = acAcc.interface.encodeFunctionData("execute(address,uint256,bytes)", [
      getAddress(usdc),
      0,
      approveExec1,
    ]);

    await expect(() => acAcc.addDeposit({ value: _W(9) })).to.changeEtherBalance(ep, _W(9));
    expect(await ep.balanceOf(acAcc)).to.equal(_W(9));

    // Construct the userOp manually
    const nonce = await acAcc.getNonce();
    const userOp = [
      getAddress(acAcc),
      nonce,
      ethers.toUtf8Bytes(""),
      executeCall,
      packAccountGasLimits(999999, 999999),
      999999,
      packAccountGasLimits(1e9, 1e9),
      ethers.toUtf8Bytes(""),
    ];
    const userOpHash = await ep.getUserOpHash([...userOp, ethers.toUtf8Bytes("")]);

    // Same but using UserOp object and compare userOpHash
    const userOpObj = {
      sender: getAddress(acAcc),
      nonce: nonce,
      initCode: "0x",
      callData: executeCall,
      callGasLimit: 999999,
      verificationGasLimit: 999999,
      preVerificationGas: 999999,
      maxFeePerGas: 1e9,
      maxPriorityFeePerGas: 1e9,
      paymaster: ZeroAddress,
      paymasterData: "0x",
      paymasterVerificationGasLimit: 0,
      paymasterPostOpGasLimit: 0,
      signature: "0x",
    };
    const { chainId } = await hre.ethers.provider.getNetwork();
    expect(getUserOpHash(userOpObj, ADDRESSES.ENTRYPOINT, chainId)).to.equal(userOpHash);

    // Sign the hash
    const message = userOpHash;
    const anonSignature = await anon.signMessage(ethers.getBytes(message));
    const signature = await exec1.signMessage(ethers.getBytes(message));
    await expect(ep.handleOps([[...userOp, anonSignature]], anon))
      .to.be.revertedWithCustomError(ep, "FailedOp")
      .withArgs(0, "AA24 signature error");

    // With the correct signature also fails, because the user doesn't have the USDC_ROLE yet
    await expect(ep.handleOps([[...userOp, signature]], anon))
      .to.be.revertedWithCustomError(ep, "FailedOp")
      .withArgs(0, "AA24 signature error");

    await expect(acAcc.connect(admin).grantRole(roles.usdc, exec1, 0)).not.to.be.reverted;

    expect(await usdc.allowance(acAcc, exec1)).to.equal(0);
    await expect(ep.handleOps([[...userOp, signature]], anon)).not.to.be.reverted;
    expect(await usdc.allowance(acAcc, exec1)).to.equal(MaxUint256);
  });

  it("Can execute when called through entryPoint - Delay on USDC.approve variant", async () => {
    const { acAcc, anon, exec1, usdc, ep, admin, roles } = await helpers.loadFixture(setUp);
    const approveExec1 = usdc.interface.encodeFunctionData("approve", [getAddress(exec1), MaxUint256]);
    const executeCall = acAcc.interface.encodeFunctionData("execute(address,uint256,bytes)", [
      getAddress(usdc),
      0,
      approveExec1,
    ]);

    await expect(() => acAcc.addDeposit({ value: _W(9) })).to.changeEtherBalance(ep, _W(9));
    expect(await ep.balanceOf(acAcc)).to.equal(_W(9));

    const nonce = await acAcc.getNonce();
    const userOpObj = {
      sender: getAddress(acAcc),
      nonce: nonce,
      initCode: "0x",
      callData: executeCall,
      callGasLimit: 999999,
      verificationGasLimit: 999999,
      preVerificationGas: 999999,
      maxFeePerGas: 1e9,
      maxPriorityFeePerGas: 1e9,
      paymaster: ZeroAddress,
      paymasterData: "0x",
      paymasterVerificationGasLimit: 0,
      paymasterPostOpGasLimit: 0,
      signature: "0x",
    };
    const { chainId } = await hre.ethers.provider.getNetwork();
    const userOpHash = getUserOpHash(userOpObj, ADDRESSES.ENTRYPOINT, chainId);
    const userOp = packedUserOpAsArray(packUserOp(userOpObj), false);

    // Sign the hash
    const message = userOpHash;
    const anonSignature = await anon.signMessage(ethers.getBytes(message));
    const signature = await exec1.signMessage(ethers.getBytes(message));
    await expect(ep.handleOps([[...userOp, anonSignature]], anon))
      .to.be.revertedWithCustomError(ep, "FailedOp")
      .withArgs(0, "AA24 signature error");

    // Require 600 seconds delay for execute
    await acAcc.connect(admin).grantRole(roles.exec, exec1, 0);
    await expect(acAcc.connect(admin).grantRole(roles.usdc, exec1, 600)).not.to.be.reverted;
    // With the correct signature fails because the operation is not scheduled
    await expect(ep.handleOps([[...userOp, signature]], anon))
      .to.be.revertedWithCustomError(ep, "FailedOpWithRevert")
      .withArgs(0, "AA23 reverted", withArgs.anyValue);

    const now = await helpers.time.latest();
    const operationId = await acAcc.hashOperation(exec1, usdc, approveExec1);

    await expect(await acAcc.connect(exec1).schedule(usdc, approveExec1, now + 1000))
      .to.emit(acAcc, "OperationScheduled")
      .withArgs(operationId, 1, now + 1000, exec1, usdc, approveExec1);

    // Keeps failing because time not increased
    await expect(ep.handleOps([[...userOp, signature]], anon))
      .to.be.revertedWithCustomError(ep, "FailedOpWithRevert")
      .withArgs(0, "AA23 reverted", withArgs.anyValue);

    await helpers.time.increase(1100);

    expect(await usdc.allowance(acAcc, exec1)).to.equal(0);
    await expect(ep.handleOps([[...userOp, signature]], anon)).not.to.be.reverted;
    expect(await usdc.allowance(acAcc, exec1)).to.equal(MaxUint256);
  });
});
