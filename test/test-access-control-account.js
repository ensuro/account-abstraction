const { expect } = require("chai");
const { _W, getRole, amountFunction, getAddress } = require("@ensuro/core/js/utils");
const { setupChain, initForkCurrency } = require("@ensuro/core/js/test-utils");
const hre = require("hardhat");

const { ethers } = hre;
const { MaxUint256, ZeroAddress } = hre.ethers;
const { getUserOpHash, packUserOp, packedUserOpAsArray } = require("./UserOp.js");

const _A = amountFunction(6);
const ADDRESSES = {
  // polygon mainnet addresses
  USDC: "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174",
  USDCWhale: "0x4d97dcd97ec945f40cf65f87097ace5ea0476045",
  ENTRYPOINT: "0x0000000071727De22E5E9d8BAf0edAc6f37da032",
};

function packAccountGasLimits(verificationGasLimit, callGasLimit) {
  return ethers.toBeHex(verificationGasLimit, 16) + ethers.toBeHex(callGasLimit, 16).slice(2);
}

async function setUp() {
  const [, exec1, exec2, anon, withdraw, admin] = await ethers.getSigners();

  const usdc = await initForkCurrency(ADDRESSES.USDC, ADDRESSES.USDCWhale, [exec1, exec2], [_A(100), _A(100)]);
  const ep = await ethers.getContractAt("IEntryPoint", ADDRESSES.ENTRYPOINT);
  const AccessControlAccount = await ethers.getContractFactory("AccessControlAccount");
  const acAcc = await AccessControlAccount.deploy(ep, admin, [exec1, exec2]);
  const roles = {
    admin: getRole("DEFAULT_ADMIN_ROLE"),
    exec: getRole("EXECUTOR_ROLE"),
    withdraw: getRole("WITHDRAW_ROLE"),
  };

  return {
    ep,
    AccessControlAccount,
    acAcc,
    exec1,
    exec2,
    anon,
    withdraw,
    admin,
    roles,
    usdc,
  };
}

describe("AccessControlAccount contract tests", function () {
  before(async () => {
    await setupChain(null);
  });

  it("Constructs with the right permissions and EP", async () => {
    const { acAcc, anon, exec1, exec2, admin, roles } = await setUp();
    expect(await acAcc.hasRole(roles.admin, admin)).to.equal(true);
    expect(await acAcc.hasRole(roles.admin, anon)).to.equal(false);
    expect(await acAcc.hasRole(roles.exec, exec1)).to.equal(true);
    expect(await acAcc.hasRole(roles.exec, exec2)).to.equal(true);
    expect(await acAcc.hasRole(roles.exec, anon)).to.equal(false);
    expect(await acAcc.entryPoint()).to.equal(ADDRESSES.ENTRYPOINT);
  });

  it("Can receive eth, deposits and only WITHDRAW_ROLE can withdraw", async () => {
    const { acAcc, anon, withdraw, admin, roles, ep } = await setUp();
    expect(await hre.ethers.provider.getBalance(acAcc)).to.equal(0);
    await expect(() => withdraw.sendTransaction({ to: acAcc, value: _W(1) })).to.changeEtherBalance(acAcc, _W(1));
    expect(await hre.ethers.provider.getBalance(acAcc)).to.equal(_W(1));

    await expect(() => acAcc.addDeposit({ value: _W(2) })).to.changeEtherBalance(ep, _W(2));
    expect(await ep.balanceOf(acAcc)).to.equal(_W(2));

    await expect(acAcc.connect(withdraw).withdrawDepositTo(anon, _W(1)))
      .to.be.revertedWithCustomError(acAcc, "AccessControlUnauthorizedAccount")
      .withArgs(withdraw, roles.withdraw);

    await expect(acAcc.connect(anon).grantRole(roles.withdraw, withdraw))
      .to.be.revertedWithCustomError(acAcc, "AccessControlUnauthorizedAccount")
      .withArgs(anon, roles.admin);

    await expect(acAcc.connect(admin).grantRole(roles.withdraw, withdraw)).not.to.be.reverted;

    await expect(() => acAcc.connect(withdraw).withdrawDepositTo(anon, _W("0.5"))).to.changeEtherBalance(
      anon,
      _W("0.5")
    );
    expect(await ep.balanceOf(acAcc)).to.equal(_W("1.5"));
    expect(await acAcc.getDeposit()).to.equal(_W("1.5"));
  });

  it("Can execute when called directly", async () => {
    const { acAcc, anon, exec1, usdc } = await setUp();
    const approveExec1 = usdc.interface.encodeFunctionData("approve", [getAddress(exec1), MaxUint256]);
    await expect(acAcc.connect(anon).execute(usdc, 0, approveExec1))
      .to.be.revertedWithCustomError(acAcc, "RequiredEntryPointOrExecutor")
      .withArgs(anon);
    expect(await usdc.allowance(acAcc, exec1)).to.equal(0);
    await expect(acAcc.connect(exec1).execute(usdc, 0, approveExec1)).not.to.be.reverted;
    expect(await usdc.allowance(acAcc, exec1)).to.equal(MaxUint256);
  });

  it("Can execute when called through entryPoint", async () => {
    const { acAcc, anon, exec1, usdc, ep } = await setUp();
    const approveExec1 = usdc.interface.encodeFunctionData("approve", [getAddress(exec1), MaxUint256]);
    const executeCall = acAcc.interface.encodeFunctionData("execute", [getAddress(usdc), 0, approveExec1]);

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

    expect(await usdc.allowance(acAcc, exec1)).to.equal(0);
    await expect(ep.handleOps([[...userOp, signature]], anon)).not.to.be.reverted;
    expect(await usdc.allowance(acAcc, exec1)).to.equal(MaxUint256);
  });

  it("Can executeBatch when called directly", async () => {
    const { acAcc, anon, exec1, exec2, usdc } = await setUp();

    // Setup - send some initial money
    await usdc.connect(exec1).transfer(acAcc, _A(10));
    await usdc.connect(exec2).transfer(acAcc, _A(20));
    expect(await usdc.balanceOf(acAcc)).to.equal(_A(30));

    const calls = [
      usdc.interface.encodeFunctionData("transfer", [getAddress(exec1), _A(5)]),
      usdc.interface.encodeFunctionData("transfer", [getAddress(exec2), _A(10)]),
    ];
    await expect(acAcc.connect(anon).executeBatch([usdc, usdc], [], calls))
      .to.be.revertedWithCustomError(acAcc, "RequiredEntryPointOrExecutor")
      .withArgs(anon);
    await expect(() => acAcc.connect(exec2).executeBatch([usdc, usdc], [], calls)).to.changeTokenBalances(
      usdc,
      [exec1, exec2],
      [_A(5), _A(10)]
    );
    expect(await usdc.balanceOf(acAcc)).to.equal(_A(15));
  });

  it("Can executeBatch when called directly (with value)", async () => {
    const { acAcc, anon, exec1, exec2, ep } = await setUp();

    // Setup - send some eth to acAcc and deposit
    await expect(() => acAcc.addDeposit({ value: _W(5) })).to.changeEtherBalance(ep, _W(5));
    expect(await ep.balanceOf(acAcc)).to.equal(_W(5));
    await expect(() => exec1.sendTransaction({ to: acAcc, value: _W(3) })).to.changeEtherBalance(acAcc, _W(3));

    const calls = [
      ep.interface.encodeFunctionData("depositTo", [getAddress(exec2)]),
      ep.interface.encodeFunctionData("addStake", [3600]),
    ];
    await expect(acAcc.connect(exec1).executeBatch([ep, ep], [], calls)).to.be.revertedWith("no stake specified");
    await expect(acAcc.connect(exec1).executeBatch([ep, ep], [_W(1)], calls)).to.be.revertedWithCustomError(
      acAcc,
      "WrongArrayLength"
    );
    await expect(acAcc.connect(exec1).executeBatch([ep], [], calls)).to.be.revertedWithCustomError(
      acAcc,
      "WrongArrayLength"
    );
    await expect(() => acAcc.connect(exec1).executeBatch([ep, ep], [_W(1), _W(2)], calls)).to.changeEtherBalance(
      ep,
      _W(3)
    );
    expect(await ep.balanceOf(acAcc)).to.equal(_W(5));
    expect(await ep.balanceOf(exec2)).to.equal(_W(1)); // The deposit was made on behalft of exec2
    expect((await ep.getDepositInfo(acAcc)).stake).to.equal(_W(2));
  });

  it("Can executeBatch when called through entryPoint", async () => {
    const { acAcc, anon, exec1, exec2, usdc, ep } = await setUp();
    // Setup - send some initial money
    await usdc.connect(exec1).transfer(acAcc, _A(10));
    await usdc.connect(exec2).transfer(acAcc, _A(20));
    expect(await usdc.balanceOf(acAcc)).to.equal(_A(30));

    const calls = [
      usdc.interface.encodeFunctionData("transfer", [getAddress(exec1), _A(5)]),
      usdc.interface.encodeFunctionData("transfer", [getAddress(exec2), _A(10)]),
    ];
    const executeBatchCall = acAcc.interface.encodeFunctionData("executeBatch", [
      [getAddress(usdc), getAddress(usdc)],
      [],
      calls,
    ]);

    await expect(() => acAcc.addDeposit({ value: _W(9) })).to.changeEtherBalance(ep, _W(9));
    expect(await ep.balanceOf(acAcc)).to.equal(_W(9));

    const nonce = await acAcc.getNonce();
    const userOpObj = {
      sender: getAddress(acAcc),
      nonce: nonce,
      initCode: "0x",
      callData: executeBatchCall,
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

    expect(await usdc.balanceOf(acAcc)).to.equal(_A(30));
    await expect(() => ep.handleOps([[...userOp, signature]], anon)).to.changeTokenBalances(
      usdc,
      [exec1, exec2],
      [_A(5), _A(10)]
    );
    expect(await usdc.balanceOf(acAcc)).to.equal(_A(15));
  });
});
