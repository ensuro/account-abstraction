import { defineConfig } from "hardhat/config";
import hardhatToolboxMochaEthers from "@nomicfoundation/hardhat-toolbox-mocha-ethers";
import HardhatContractSizer from "@solidstate/hardhat-contract-sizer";

export default defineConfig({
  plugins: [hardhatToolboxMochaEthers, HardhatContractSizer],
  solidity: {
    version: "0.8.30",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
      evmVersion: "prague",
    },
    npmFilesToBuild: [
      "@openzeppelin/contracts/token/ERC20/IERC20.sol",
      "@account-abstraction/contracts/interfaces/IEntryPoint.sol",
    ],
  },
  contractSizer: {
    alphaSort: true,
    runOnCompile: false,
  },
});
