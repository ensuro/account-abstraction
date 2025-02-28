const { expect } = require("chai");
const { _W, getRole, amountFunction, getAddress } = require("@ensuro/utils/js/utils");
const { setupChain, initForkCurrency, initCurrency } = require("@ensuro/utils/js/test-utils");
const hre = require("hardhat");
const helpers = require("@nomicfoundation/hardhat-network-helpers");

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

const variants = [
  {
    name: "AccessControlAccount",
    fixture: async () => {
      await setupChain(null);
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
    },
  },
  {
    name: "ERC2771ForwarderAccount",
    fixture: async () => {
      await setupChain(null);
      const [, exec1, exec2, anon, withdraw, admin] = await ethers.getSigners();

      const ep = await ethers.getContractAt("IEntryPoint", ADDRESSES.ENTRYPOINT);
      const ERC2771ForwarderAccount = await ethers.getContractFactory("ERC2771ForwarderAccount");
      const acAcc = await ERC2771ForwarderAccount.deploy(ep, admin, [exec1, exec2]);
      const usdc = await initCurrency(
        { decimals: 6, initial_supply: _A(10000), extraArgs: [acAcc], contractClass: "ERC20With2771" },
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
        acAcc,
        exec1,
        exec2,
        anon,
        withdraw,
        admin,
        roles,
        usdc,
      };
    },
  },
];

variants.forEach((variant) => {
  describe(`${variant.name} contract tests`, function () {
    it("Constructs with the right permissions and EP", async () => {
      const { acAcc, anon, exec1, exec2, admin, roles } = await helpers.loadFixture(variant.fixture);
      expect(await acAcc.hasRole(roles.admin, admin)).to.equal(true);
      expect(await acAcc.hasRole(roles.admin, anon)).to.equal(false);
      expect(await acAcc.hasRole(roles.exec, exec1)).to.equal(true);
      expect(await acAcc.hasRole(roles.exec, exec2)).to.equal(true);
      expect(await acAcc.hasRole(roles.exec, anon)).to.equal(false);
      expect(await acAcc.entryPoint()).to.equal(ADDRESSES.ENTRYPOINT);
    });

    it("Can receive eth, deposits and only WITHDRAW_ROLE can withdraw", async () => {
      const { acAcc, anon, withdraw, admin, roles, ep } = await helpers.loadFixture(variant.fixture);
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
      const { acAcc, anon, exec1, exec2, usdc } = await helpers.loadFixture(variant.fixture);
      const approveExec1 = usdc.interface.encodeFunctionData("approve", [getAddress(exec1), MaxUint256]);
      await expect(acAcc.connect(anon).execute(usdc, 0, approveExec1))
        .to.be.revertedWithCustomError(acAcc, "RequiredEntryPointOrExecutor")
        .withArgs(anon);
      // The msgSender that interacts with the ERC20 contract changes from one variant to the other
      const msgSender = variant.name === "AccessControlAccount" ? acAcc : exec2;
      expect(await usdc.allowance(msgSender, exec1)).to.equal(0);
      await expect(acAcc.connect(exec2).execute(usdc, 0, approveExec1)).not.to.be.reverted;
      expect(await usdc.allowance(msgSender, exec1)).to.equal(MaxUint256);
    });

    it("Can execute when called directly (with value)", async () => {
      const { acAcc, exec1, ep } = await helpers.loadFixture(variant.fixture);

      // Setup - send some eth to acAcc and deposit
      await expect(() => acAcc.addDeposit({ value: _W(5) })).to.changeEtherBalance(ep, _W(5));
      expect(await ep.balanceOf(acAcc)).to.equal(_W(5));
      await expect(() => exec1.sendTransaction({ to: acAcc, value: _W(3) })).to.changeEtherBalance(acAcc, _W(3));

      const addStakeCall = ep.interface.encodeFunctionData("addStake", [3600]);

      if (variant.name == "AccessControlAccount") {
        await expect(acAcc.connect(exec1).execute(ep, 0, addStakeCall)).to.be.revertedWith("no stake specified");
      } else {
        await expect(acAcc.connect(exec1).execute(ep, 0, addStakeCall))
          .to.be.revertedWithCustomError(acAcc, "CanCallOnlyIfTrustedForwarder")
          .withArgs(ep);
      }
      if (variant.name == "AccessControlAccount") {
        await expect(() => acAcc.connect(exec1).execute(ep, _W(2), addStakeCall)).to.changeEtherBalance(ep, _W(2));
        expect(await ep.balanceOf(acAcc)).to.equal(_W(5));
        expect((await ep.getDepositInfo(acAcc)).stake).to.equal(_W(2));
      } else {
        // Keeps failing because it can't call the EP
        await expect(acAcc.connect(exec1).execute(ep, _W(2), addStakeCall))
          .to.be.revertedWithCustomError(acAcc, "CanCallOnlyIfTrustedForwarder")
          .withArgs(ep);
      }
    });

    it("Can execute when called through entryPoint", async () => {
      const { acAcc, anon, exec1, exec2, usdc, ep } = await helpers.loadFixture(variant.fixture);
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
      const signature = await exec2.signMessage(ethers.getBytes(message));
      await expect(ep.handleOps([[...userOp, anonSignature]], anon))
        .to.be.revertedWithCustomError(ep, "FailedOp")
        .withArgs(0, "AA24 signature error");

      // Call the validateUserOp function on the wallet contract
      await helpers.impersonateAccount(ep.target);
      const epSigner = await hre.ethers.getSigner(ep.target);
      const validateTx = await acAcc.connect(epSigner).validateUserOp(
        [...userOp, signature],
        userOpHash,
        0 // missingAccountFunds
      );
      await validateTx.wait();

      // Use debug_traceTransaction to get the execution trace of the validation call
      const trace = await hre.network.provider.send("debug_traceTransaction", [
        validateTx.hash,
        { disableStorage: true, disableMemory: true, disableStack: true },
      ]);

      const executedOpcodes = trace.structLogs.map((log) => log.op);
      await expect(executedOpcodes).to.not.contain("TIMESTAMP");

      const msgSender = variant.name === "AccessControlAccount" ? acAcc : exec2;
      expect(await usdc.allowance(msgSender, exec1)).to.equal(0);
      await expect(ep.handleOps([[...userOp, signature]], anon)).not.to.be.reverted;
      expect(await usdc.allowance(msgSender, exec1)).to.equal(MaxUint256);
    });

    it("Can executeBatch when called directly", async () => {
      const { acAcc, anon, exec1, exec2, usdc } = await helpers.loadFixture(variant.fixture);

      if (variant.name === "AccessControlAccount") {
        // Setup - send some initial money
        await usdc.connect(exec1).transfer(acAcc, _A(10));
        await usdc.connect(exec2).transfer(acAcc, _A(20));
        expect(await usdc.balanceOf(acAcc)).to.equal(_A(30));
      }

      const calls = [
        usdc.interface.encodeFunctionData("transfer", [getAddress(exec1), _A(5)]),
        usdc.interface.encodeFunctionData("transfer", [getAddress(anon), _A(10)]),
      ];
      await expect(acAcc.connect(anon).executeBatch([usdc, usdc], [], calls))
        .to.be.revertedWithCustomError(acAcc, "RequiredEntryPointOrExecutor")
        .withArgs(anon);
      const msgSender = variant.name === "AccessControlAccount" ? acAcc : exec2;
      await expect(() => acAcc.connect(exec2).executeBatch([usdc, usdc], [], calls)).to.changeTokenBalances(
        usdc,
        [exec1, anon, msgSender],
        [_A(5), _A(10), _A(-15)]
      );
    });

    it("Can executeBatch when called directly (with value)", async () => {
      const { acAcc, exec1, exec2, ep } = await helpers.loadFixture(variant.fixture);

      // Setup - send some eth to acAcc and deposit
      await expect(() => acAcc.addDeposit({ value: _W(5) })).to.changeEtherBalance(ep, _W(5));
      expect(await ep.balanceOf(acAcc)).to.equal(_W(5));
      await expect(() => exec1.sendTransaction({ to: acAcc, value: _W(3) })).to.changeEtherBalance(acAcc, _W(3));

      const calls = [
        ep.interface.encodeFunctionData("depositTo", [getAddress(exec2)]),
        ep.interface.encodeFunctionData("addStake", [3600]),
      ];
      if (variant.name == "AccessControlAccount") {
        await expect(acAcc.connect(exec1).executeBatch([ep, ep], [], calls)).to.be.revertedWith("no stake specified");
      } else {
        await expect(acAcc.connect(exec1).executeBatch([ep, ep], [], calls))
          .to.be.revertedWithCustomError(acAcc, "CanCallOnlyIfTrustedForwarder")
          .withArgs(ep);
      }
      await expect(acAcc.connect(exec1).executeBatch([ep, ep], [_W(1)], calls)).to.be.revertedWithCustomError(
        acAcc,
        "WrongArrayLength"
      );
      await expect(acAcc.connect(exec1).executeBatch([ep], [], calls)).to.be.revertedWithCustomError(
        acAcc,
        "WrongArrayLength"
      );
      if (variant.name == "AccessControlAccount") {
        await expect(() => acAcc.connect(exec1).executeBatch([ep, ep], [_W(1), _W(2)], calls)).to.changeEtherBalance(
          ep,
          _W(3)
        );
        expect(await ep.balanceOf(acAcc)).to.equal(_W(5));
        expect(await ep.balanceOf(exec2)).to.equal(_W(1)); // The deposit was made on behalft of exec2
        expect((await ep.getDepositInfo(acAcc)).stake).to.equal(_W(2));
      } else {
        // Keeps failing because it can't call the EP
        await expect(acAcc.connect(exec1).executeBatch([ep, ep], [_W(1), _W(2)], calls))
          .to.be.revertedWithCustomError(acAcc, "CanCallOnlyIfTrustedForwarder")
          .withArgs(ep);
      }
    });

    it("Can executeBatch when called through entryPoint", async () => {
      const { acAcc, anon, exec1, exec2, usdc, ep } = await helpers.loadFixture(variant.fixture);

      if (variant.name === "AccessControlAccount") {
        // Setup - send some initial money
        await usdc.connect(exec1).transfer(acAcc, _A(10));
        await usdc.connect(exec2).transfer(acAcc, _A(20));
        expect(await usdc.balanceOf(acAcc)).to.equal(_A(30));
      }

      const calls = [
        usdc.interface.encodeFunctionData("transfer", [getAddress(exec1), _A(5)]),
        usdc.interface.encodeFunctionData("transfer", [getAddress(anon), _A(10)]),
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
      const signature = await exec2.signMessage(ethers.getBytes(message));
      await expect(ep.handleOps([[...userOp, anonSignature]], anon))
        .to.be.revertedWithCustomError(ep, "FailedOp")
        .withArgs(0, "AA24 signature error");

      const msgSender = variant.name === "AccessControlAccount" ? acAcc : exec2;
      await expect(() => ep.handleOps([[...userOp, signature]], anon)).to.changeTokenBalances(
        usdc,
        [exec1, anon, msgSender],
        [_A(5), _A(10), _A(-15)]
      );
    });
  });
});
