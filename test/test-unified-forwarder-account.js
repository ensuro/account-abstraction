import { initCurrency } from "@ensuro/utils/js/test-utils";
import { _W, amountFunction, getAddress } from "@ensuro/utils/js/utils";
import { anyValue } from "@nomicfoundation/hardhat-ethers-chai-matchers/withArgs";
import { expect } from "chai";
import { id, MaxUint256, ZeroAddress } from "ethers";

import { getUserOpHash, packUserOp, packedUserOpAsArray, signUserOp, fillUserOpDefaults } from "../js/userOp.js";
import { loadFixtureLocal, TestUserOp } from "./utils.js";

const _A = amountFunction(6);

const SELECTOR_SIZE = 4; // bytes
const ADDRESS_SIZE = 20; // bytes (appended ERC-2771 sender)
const NONCE_SEQ_BITS = 64n; // 2D nonce: high 192 bits = key, low 64 = sequence

const selectorOf = (sig) => id(sig).slice(0, 2 + 2 * SELECTOR_SIZE); // "0x" + 2 hex per byte

// 4-byte tags the contract accepts as the callData prefix.
const EXECUTE_SELECTOR = selectorOf("execute(address,uint256,bytes)");
const EXECUTE_USER_OP_SELECTOR = selectorOf(
  "executeUserOp((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes),bytes32)"
);

function buildCallData(ethers, signer, target, value, data, selector = EXECUTE_SELECTOR) {
  return ethers.concat([
    selector,
    ethers.AbiCoder.defaultAbiCoder().encode(["address", "address", "uint256", "bytes"], [signer, target, value, data]),
  ]);
}

// Builds, signs (over the account address as the v0.7 domain) and packs a userOp.
async function makeOp(
  ethers,
  account,
  signerWallet,
  { signerField, sender, target, value, data, nonce, callGasLimit, selector },
  chainId
) {
  const callData = buildCallData(
    ethers,
    signerField ?? signerWallet.address,
    getAddress(target),
    value,
    data,
    selector
  );
  const op = await signUserOp(
    fillUserOpDefaults({ sender: sender ?? getAddress(account), nonce, callData, callGasLimit }, TestUserOp),
    signerWallet,
    getAddress(account),
    chainId
  );
  return {
    packed: packedUserOpAsArray(packUserOp(op), true),
    hash: getUserOpHash(op, getAddress(account), chainId),
  };
}

// erc2771Target is fixed at construction but the ERC2771 token needs the account as its trusted
// forwarder, so we predict the token address (deployed right after the account by the same signer).
// The AccessManager (signer add/remove authority) is deployed by `admin` so the deployer's nonce
// sequence — and the CREATE address prediction below — stays unchanged.
async function setup(connection) {
  const { ethers } = connection;
  const [deployer, signer1, signer2, anon, beneficiary, admin] = await ethers.getSigners();

  const am = await (await ethers.getContractFactory("MockAccessManager")).connect(admin).deploy(admin.address);
  const UnifiedForwarderAccount = await ethers.getContractFactory("UnifiedForwarderAccount");
  const startNonce = await deployer.getNonce();
  const predictedToken = ethers.getCreateAddress({ from: deployer.address, nonce: startNonce + 1 });

  const account = await UnifiedForwarderAccount.deploy(getAddress(am), predictedToken, [signer1, signer2]);
  const usdc = await initCurrency(
    ethers,
    { decimals: 6, initial_supply: _A(10000), extraArgs: [getAddress(account)], contractClass: "ERC20With2771" },
    [signer1, signer2],
    [_A(100), _A(100)]
  );

  const plainProbe = await (await ethers.getContractFactory("ERC2771Probe")).deploy(ZeroAddress);
  const { chainId } = await ethers.provider.getNetwork();

  return { account, usdc, plainProbe, am, deployer, signer1, signer2, anon, beneficiary, admin, ethers, chainId };
}

// Variant whose erc2771Target is an ERC2771Probe (trusting the account), to assert the appended
// bytes precisely.
async function setupProbeTarget(connection) {
  const { ethers } = connection;
  const [deployer, signer1, signer2, anon, beneficiary, admin] = await ethers.getSigners();

  const am = await (await ethers.getContractFactory("MockAccessManager")).connect(admin).deploy(admin.address);
  const UnifiedForwarderAccount = await ethers.getContractFactory("UnifiedForwarderAccount");
  const ERC2771Probe = await ethers.getContractFactory("ERC2771Probe");
  const startNonce = await deployer.getNonce();
  const predictedProbe = ethers.getCreateAddress({ from: deployer.address, nonce: startNonce + 1 });

  const account = await UnifiedForwarderAccount.deploy(getAddress(am), predictedProbe, [signer1, signer2]);
  const targetProbe = await ERC2771Probe.deploy(getAddress(account));
  const { chainId } = await ethers.provider.getNetwork();

  return { account, targetProbe, am, signer1, signer2, anon, beneficiary, admin, ethers, chainId };
}

describe("UnifiedForwarderAccount contract tests", function () {
  it("Constructs with the right target, authority, signers and nonces", async () => {
    const { account, usdc, am, signer1, signer2, anon } = await loadFixtureLocal(setup);
    expect(await account.erc2771Target()).to.equal(getAddress(usdc));
    expect(await account.authority()).to.equal(getAddress(am));
    expect(await account.authorizedSigner(signer1)).to.equal(true);
    expect(await account.authorizedSigner(signer2)).to.equal(true);
    expect(await account.authorizedSigner(anon)).to.equal(false);
    expect(await account.getNonce(0)).to.equal(0);
  });

  it("Rejects construction with a zero target or a zero signer", async () => {
    const { account, am, signer1, ethers } = await loadFixtureLocal(setup);
    const UnifiedForwarderAccount = await ethers.getContractFactory("UnifiedForwarderAccount");
    await expect(
      UnifiedForwarderAccount.deploy(getAddress(am), ZeroAddress, [getAddress(signer1)])
    ).to.be.revertedWithCustomError(account, "ZeroAddress");
    await expect(
      UnifiedForwarderAccount.deploy(getAddress(am), getAddress(account), [getAddress(signer1), ZeroAddress])
    ).to.be.revertedWithCustomError(account, "ZeroAddress");
  });

  it("Lets the access manager add and remove authorized signers", async () => {
    const { account, usdc, signer1, signer2, anon, admin, beneficiary, ethers, chainId } =
      await loadFixtureLocal(setup);
    const toS2 = usdc.interface.encodeFunctionData("transfer", [getAddress(signer2), _A(1)]);

    // anon is unauthorized: its op is rejected
    expect(await account.authorizedSigner(anon)).to.equal(false);
    const rejected = await makeOp(ethers, account, anon, { target: usdc, value: 0, data: toS2, nonce: 0 }, chainId);
    await expect(account.handleOps([rejected.packed], getAddress(beneficiary)))
      .to.be.revertedWithCustomError(account, "UnauthorizedSigner")
      .withArgs(getAddress(anon));

    // admin authorizes anon, funds it, and now its op goes through
    await expect(account.connect(admin).setAuthorizedSigner(getAddress(anon), true))
      .to.emit(account, "AuthorizedSignerSet")
      .withArgs(getAddress(anon), true);
    expect(await account.authorizedSigner(anon)).to.equal(true);
    await usdc.connect(signer1).transfer(getAddress(anon), _A(2));

    const fromAnon = usdc.interface.encodeFunctionData("transfer", [getAddress(signer2), _A(1)]);
    const okOp = await makeOp(ethers, account, anon, { target: usdc, value: 0, data: fromAnon, nonce: 0 }, chainId);
    await expect(account.handleOps([okOp.packed], getAddress(beneficiary))).to.changeTokenBalances(
      ethers,
      usdc,
      [anon, signer2],
      [_A(-1), _A(1)]
    );

    // admin revokes signer1: its op is now rejected
    await account.connect(admin).setAuthorizedSigner(getAddress(signer1), false);
    const s1op = await makeOp(ethers, account, signer1, { target: usdc, value: 0, data: toS2, nonce: 0 }, chainId);
    await expect(account.handleOps([s1op.packed], getAddress(beneficiary)))
      .to.be.revertedWithCustomError(account, "UnauthorizedSigner")
      .withArgs(getAddress(signer1));
  });

  it("Rejects signer management from an unauthorized caller and for the zero address", async () => {
    const { account, anon, admin } = await loadFixtureLocal(setup);
    await expect(account.connect(anon).setAuthorizedSigner(getAddress(anon), true))
      .to.be.revertedWithCustomError(account, "AccessManagedUnauthorized")
      .withArgs(getAddress(anon));
    await expect(account.connect(admin).setAuthorizedSigner(ZeroAddress, true)).to.be.revertedWithCustomError(
      account,
      "ZeroAddress"
    );
  });

  it("Forwards the recovered signer as ERC-2771 sender", async () => {
    const { account, usdc, signer1, signer2, anon, beneficiary, ethers, chainId } = await loadFixtureLocal(setup);

    // signer2 lets signer1 move its tokens; signer1 then drives the transferFrom through the account
    await usdc.connect(signer2).approve(getAddress(signer1), MaxUint256);
    const data = usdc.interface.encodeFunctionData("transferFrom", [getAddress(signer2), getAddress(anon), _A(10)]);
    const { packed, hash } = await makeOp(
      ethers,
      account,
      signer1,
      { target: usdc, value: 0, data, nonce: 0 },
      chainId
    );

    const tx = await account.handleOps([packed], getAddress(beneficiary));
    await expect(tx)
      .to.emit(account, "UserOperationEvent")
      .withArgs(hash, getAddress(account), ZeroAddress, 0, true, anyValue, anyValue);
    await expect(tx).to.changeTokenBalances(ethers, usdc, [signer2, anon, signer1], [_A(-10), _A(10), _A(0)]);
  });

  it("Exposes getUserOpHash matching the off-chain hash and the emitted userOpHash", async () => {
    const { account, usdc, signer1, anon, beneficiary, ethers, chainId } = await loadFixtureLocal(setup);
    const data = usdc.interface.encodeFunctionData("transfer", [getAddress(anon), _A(1)]);
    const { packed, hash } = await makeOp(
      ethers,
      account,
      signer1,
      { target: usdc, value: 0, data, nonce: 0 },
      chainId
    );

    expect(await account.getUserOpHash(packed)).to.equal(hash);

    await expect(account.handleOps([packed], getAddress(beneficiary)))
      .to.emit(account, "UserOperationEvent")
      .withArgs(hash, getAddress(account), ZeroAddress, 0, true, anyValue, anyValue);
  });

  it("Accepts both the execute and executeUserOp tags, rejects any other", async () => {
    const { account, usdc, signer1, anon, beneficiary, ethers, chainId } = await loadFixtureLocal(setup);
    const data = usdc.interface.encodeFunctionData("transfer", [getAddress(anon), _A(1)]);

    for (const [i, selector] of [EXECUTE_SELECTOR, EXECUTE_USER_OP_SELECTOR].entries()) {
      const { packed } = await makeOp(
        ethers,
        account,
        signer1,
        { target: usdc, value: 0, data, nonce: i, selector },
        chainId
      );
      await expect(account.handleOps([packed], getAddress(beneficiary))).to.changeTokenBalances(
        ethers,
        usdc,
        [signer1, anon],
        [_A(-1), _A(1)]
      );
    }

    const bad = await makeOp(
      ethers,
      account,
      signer1,
      { target: usdc, value: 0, data, nonce: 2, selector: "0x12345678" },
      chainId
    );
    await expect(account.handleOps([bad.packed], getAddress(beneficiary)))
      .to.be.revertedWithCustomError(account, "UnsupportedSelector")
      .withArgs("0x12345678");
  });

  it("Appends exactly the recovered signer when calling the ERC-2771 target", async () => {
    const { account, targetProbe, signer1, beneficiary, ethers, chainId } = await loadFixtureLocal(setupProbeTarget);
    expect(await account.erc2771Target()).to.equal(getAddress(targetProbe));

    const data = targetProbe.interface.encodeFunctionData("ping", []);
    const { packed } = await makeOp(
      ethers,
      account,
      signer1,
      { target: targetProbe, value: 0, data, nonce: 0 },
      chainId
    );

    // ping selector + appended signer
    await expect(account.handleOps([packed], getAddress(beneficiary)))
      .to.emit(targetProbe, "Pinged")
      .withArgs(getAddress(signer1), SELECTOR_SIZE + ADDRESS_SIZE, 0);
  });

  it("Cannot impersonate another account by forging a trailing sender", async () => {
    const { account, targetProbe, signer1, anon, beneficiary, ethers, chainId } =
      await loadFixtureLocal(setupProbeTarget);

    // Attacker appends a fake sender to data; the account still appends the recovered signer last,
    // so _msgSender() is signer1, not anon (calldata = selector + forged sender + real signer).
    const data = ethers.concat([targetProbe.interface.encodeFunctionData("ping", []), getAddress(anon)]);
    const { packed } = await makeOp(
      ethers,
      account,
      signer1,
      { target: targetProbe, value: 0, data, nonce: 0 },
      chainId
    );

    await expect(account.handleOps([packed], getAddress(beneficiary)))
      .to.emit(targetProbe, "Pinged")
      .withArgs(getAddress(signer1), SELECTOR_SIZE + 2 * ADDRESS_SIZE, 0);
  });

  it("Plain path forwards data and value unchanged, without appending a sender", async () => {
    const { account, plainProbe, signer1, deployer, beneficiary, ethers, chainId } = await loadFixtureLocal(setup);
    await deployer.sendTransaction({ to: account, value: _W(1) });

    const data = plainProbe.interface.encodeFunctionData("ping", []);
    const { packed, hash } = await makeOp(
      ethers,
      account,
      signer1,
      { target: plainProbe, value: _W(1), data, nonce: 0 },
      chainId
    );

    const tx = await account.handleOps([packed], getAddress(beneficiary));
    // only the selector (no append) and sender == account (probe does not trust it as forwarder)
    await expect(tx).to.emit(plainProbe, "Pinged").withArgs(getAddress(account), SELECTOR_SIZE, _W(1));
    await expect(tx).to.changeEtherBalance(ethers, plainProbe, _W(1));
    await expect(tx)
      .to.emit(account, "UserOperationEvent")
      .withArgs(hash, getAddress(account), ZeroAddress, 0, true, anyValue, anyValue);
  });

  it("Rejects a userOp whose sender is not the account", async () => {
    const { account, usdc, signer1, anon, beneficiary, ethers, chainId } = await loadFixtureLocal(setup);
    const data = usdc.interface.encodeFunctionData("transfer", [getAddress(anon), _A(1)]);
    const { packed } = await makeOp(
      ethers,
      account,
      signer1,
      { sender: getAddress(anon), target: usdc, value: 0, data, nonce: 0 },
      chainId
    );
    await expect(account.handleOps([packed], getAddress(beneficiary)))
      .to.be.revertedWithCustomError(account, "InvalidSender")
      .withArgs(getAddress(anon));
  });

  it("Rejects a userOp whose recovered signer != decoded signer", async () => {
    const { account, usdc, signer1, signer2, anon, beneficiary, ethers, chainId } = await loadFixtureLocal(setup);

    const data = usdc.interface.encodeFunctionData("transfer", [getAddress(anon), _A(1)]);
    // signed by signer1 but the decoded signer claims signer2 (an authorized signer)
    const { packed } = await makeOp(
      ethers,
      account,
      signer1,
      { signerField: getAddress(signer2), target: usdc, value: 0, data, nonce: 0 },
      chainId
    );

    await expect(account.handleOps([packed], getAddress(beneficiary)))
      .to.be.revertedWithCustomError(account, "InvalidSignature")
      .withArgs(getAddress(signer1), getAddress(signer2));
  });

  it("Rejects a userOp signed by an unauthorized signer", async () => {
    const { account, usdc, anon, beneficiary, ethers, chainId } = await loadFixtureLocal(setup);

    const data = usdc.interface.encodeFunctionData("transfer", [getAddress(anon), _A(1)]);
    const { packed } = await makeOp(ethers, account, anon, { target: usdc, value: 0, data, nonce: 0 }, chainId);

    await expect(account.handleOps([packed], getAddress(beneficiary)))
      .to.be.revertedWithCustomError(account, "UnauthorizedSigner")
      .withArgs(getAddress(anon));
  });

  it("Rejects an out-of-order nonce and replays", async () => {
    const { account, usdc, signer1, anon, beneficiary, ethers, chainId } = await loadFixtureLocal(setup);
    const data = usdc.interface.encodeFunctionData("transfer", [getAddress(anon), _A(1)]);

    const wrong = await makeOp(ethers, account, signer1, { target: usdc, value: 0, data, nonce: 5 }, chainId);
    await expect(account.handleOps([wrong.packed], getAddress(beneficiary)))
      .to.be.revertedWithCustomError(account, "InvalidNonce")
      .withArgs(0, 0, 5);

    const op = await makeOp(ethers, account, signer1, { target: usdc, value: 0, data, nonce: 0 }, chainId);
    await expect(account.handleOps([op.packed], getAddress(beneficiary))).to.changeTokenBalances(
      ethers,
      usdc,
      [signer1, anon],
      [_A(-1), _A(1)]
    );
    expect(await account.getNonce(0)).to.equal(1);

    // Same op again is now stale
    await expect(account.handleOps([op.packed], getAddress(beneficiary)))
      .to.be.revertedWithCustomError(account, "InvalidNonce")
      .withArgs(0, 1, 0);
  });

  it("Does not revert the bundle when one op fails, and reports it via events", async () => {
    const { account, usdc, signer1, signer2, anon, beneficiary, ethers, chainId } = await loadFixtureLocal(setup);

    const ok0 = usdc.interface.encodeFunctionData("transfer", [getAddress(anon), _A(10)]);
    const fail = usdc.interface.encodeFunctionData("transfer", [getAddress(anon), _A(1000)]); // exceeds balance
    const ok2 = usdc.interface.encodeFunctionData("transfer", [getAddress(anon), _A(5)]);

    const op0 = await makeOp(ethers, account, signer1, { target: usdc, value: 0, data: ok0, nonce: 0 }, chainId);
    const op1 = await makeOp(ethers, account, signer1, { target: usdc, value: 0, data: fail, nonce: 1 }, chainId);
    const op2 = await makeOp(ethers, account, signer2, { target: usdc, value: 0, data: ok2, nonce: 2 }, chainId);

    const tx = await account.handleOps([op0.packed, op1.packed, op2.packed], getAddress(beneficiary));

    await expect(tx)
      .to.emit(account, "UserOperationEvent")
      .withArgs(op0.hash, getAddress(account), ZeroAddress, 0, true, anyValue, anyValue);
    await expect(tx)
      .to.emit(account, "UserOperationEvent")
      .withArgs(op1.hash, getAddress(account), ZeroAddress, 1, false, anyValue, anyValue);
    await expect(tx)
      .to.emit(account, "UserOperationEvent")
      .withArgs(op2.hash, getAddress(account), ZeroAddress, 2, true, anyValue, anyValue);
    await expect(tx).to.emit(account, "UserOperationRevertReason").withArgs(op1.hash, getAddress(account), 1, anyValue);

    // Only the two successful ops moved funds; the failed op's nonce was still consumed
    await expect(tx).to.changeTokenBalances(ethers, usdc, [signer1, signer2, anon], [_A(-10), _A(-5), _A(15)]);
    expect(await account.getNonce(0)).to.equal(3);
    await expect(account.handleOps([op1.packed], getAddress(beneficiary)))
      .to.be.revertedWithCustomError(account, "InvalidNonce")
      .withArgs(0, 3, 1);
  });

  it("Caps execution gas per op so a heavy op can't starve the bundle", async () => {
    const { account, usdc, signer1, signer2, anon, beneficiary, ethers, chainId } = await loadFixtureLocal(setup);

    const cold = ethers.Wallet.createRandom().address; // fresh recipient → cold SSTORE on transfer
    const d0 = usdc.interface.encodeFunctionData("transfer", [getAddress(anon), _A(10)]);
    const d1 = usdc.interface.encodeFunctionData("transfer", [cold, _A(20)]);
    const d2 = usdc.interface.encodeFunctionData("transfer", [getAddress(anon), _A(5)]);

    const op0 = await makeOp(ethers, account, signer1, { target: usdc, value: 0, data: d0, nonce: 0 }, chainId);
    // callGasLimit below what a transfer to a cold recipient needs: this op runs out of gas
    const op1 = await makeOp(
      ethers,
      account,
      signer1,
      { target: usdc, value: 0, data: d1, nonce: 1, callGasLimit: 21000n },
      chainId
    );
    const op2 = await makeOp(ethers, account, signer2, { target: usdc, value: 0, data: d2, nonce: 2 }, chainId);

    const tx = await account.handleOps([op0.packed, op1.packed, op2.packed], getAddress(beneficiary));

    await expect(tx)
      .to.emit(account, "UserOperationEvent")
      .withArgs(op0.hash, getAddress(account), ZeroAddress, 0, true, anyValue, anyValue);
    await expect(tx)
      .to.emit(account, "UserOperationEvent")
      .withArgs(op1.hash, getAddress(account), ZeroAddress, 1, false, anyValue, anyValue);
    await expect(tx)
      .to.emit(account, "UserOperationEvent")
      .withArgs(op2.hash, getAddress(account), ZeroAddress, 2, true, anyValue, anyValue);
    // out-of-gas leaves empty returndata, so no revert-reason event is emitted (matches EntryPoint)
    await expect(tx).to.not.emit(account, "UserOperationRevertReason");

    await expect(tx).to.changeTokenBalances(ethers, usdc, [signer1, signer2, anon], [_A(-10), _A(-5), _A(15)]);
    expect(await account.getNonce(0)).to.equal(3);
  });

  it("Tracks nonce sequences per key independently", async () => {
    const { account, usdc, signer1, anon, beneficiary, ethers, chainId } = await loadFixtureLocal(setup);
    const data = usdc.interface.encodeFunctionData("transfer", [getAddress(anon), _A(1)]);

    const nonce = 7n << NONCE_SEQ_BITS; // key 7, seq 0
    const { packed } = await makeOp(ethers, account, signer1, { target: usdc, value: 0, data, nonce }, chainId);

    await expect(account.handleOps([packed], getAddress(beneficiary))).to.changeTokenBalances(
      ethers,
      usdc,
      [signer1, anon],
      [_A(-1), _A(1)]
    );
    expect(await account.getNonce(7)).to.equal((7n << NONCE_SEQ_BITS) | 1n);
    expect(await account.getNonce(0)).to.equal(0);
  });
});
