---
title: "Solidity Documentation"
description: "Design and Architecture of the Solidity Language"
extra:
  date: 2022-05-09
  version: "0.0.2"
---


## V1: Architecture, design and threat modeling

## Control Objective

Architecture, design and threat modeling in the context of creating secure smart contracts.
Consider all possible threats before the implementation of the smart contract.

Ensure that a verified contract satisfies the following high-level requirements:
* All related smart contracts are identified and used properly,
* Specific smart contracts security assumptions are considered during the design phase.

Category “V1” lists requirements related to the architecture, design and threat modeling of the smart contracts.

## Security Verification Requirements

| # | Description |
| --- | --- |
| **1.1** | Verify that the every introduced design change is preceded by an earlier threat modeling. | 
| **1.2** | Verify that the documentation clearly and precisely defines all trust boundaries in the contract (trusted relations with other contracts and significant data flows).  | 
| **1.3** | Verify that the SCSVS, security requirements or policy is available to all developers and testers. | 
| **1.4** | Verify that there exists an upgrade process for the contract which allows to deploy the security fixes or it is clearly stated that the contract is not upgradeable. | 
| **1.5** | Verify that the events for the (state changing/crucial for business) operations are defined |
| **1.6** | Verify that there is a component that monitors the contract activity using events. | 
| **1.7** | Verify that there exists a mechanism that can temporarily stop the sensitive functionalities of the contract in case of a new attack. This mechanism should not block access to the assets (e.g. tokens) for the owners. | 
| **1.8** | Verify that there is a policy to track new security bugs and to update the libraries to the latest secure version. | 
| **1.9** | Verify that the value of cryptocurrencies kept on contract is controlled and at the minimal acceptable level. | 
| **1.10** | Verify that if the fallback function can be called by anyone it is included in the threat modelling. | 
| **1.11** | Verify that the business logic in contracts is consistent. Important changes in the logic should be allowed for all or none of the contracts. | 
| **1.12** | Verify that code analysis tools are in use that can detect potentially malicious code. | 
| **1.13** | Verify that the latest version of the major Solidity release is used. |  
| **1.14** | Verify that, when using the external implementation of contract, you use the current version which has not been superseded. | 
| **1.15** | Verify that there are no vulnerabilities associated with system architecture and design. | 


## Contract

```solidity


pragma solidity ^0.6.12;
pragma experimental ABIEncoderV2;


contract MultiCall {
    
    struct Call {
        address to;
        bytes data;
    }
    
   function multicall(Call[] memory calls) public returns (bytes[] memory results) {
        results = new bytes[](calls.length);
        for (uint i = 0; i < calls.length; i++) {
            (, results[i]) = calls[i].to.call(calls[i].data);
        }
    }
    
    
    // be careful with calls.length == 0
    function multicallWithGasLimitation(Call[] memory calls, uint256 gasBuffer) public returns (bytes[] memory results, uint256 lastSuccessIndex) {
        results = new bytes[](calls.length);
        for (uint i = 0; i < calls.length; i++) {
            (, results[i]) = calls[i].to.call(calls[i].data);
            if (gasleft() < gasBuffer) {
                return (results, i);
            }
        }
        return (results, calls.length - 1);
    }
    
   function multicallWithGas(Call[] memory calls) public returns (bytes[] memory results, uint256[] memory gasUsed) {
        results = new bytes[](calls.length);
        gasUsed = new uint256[](calls.length);
        for (uint i = 0; i < calls.length; i++) {
            uint256 initialGas = gasleft();
            (, results[i]) = calls[i].to.call(calls[i].data);
            gasUsed[i] = initialGas - gasleft();
        }
    }
    
    function gaslimit() external view returns (uint256) {
        return block.gaslimit;
    }
    
    function gasLeft() external view returns (uint256) {
        return gasleft();
    }
}
```

## Provider

```typescript
import { Provider } from "@ethersproject/providers";
import { HardhatRuntimeEnvironment } from "hardhat/types";
import { URL } from "url";

/**
 * Return either an HTTP Provider or a WebSocket provider
 * depending on the network URL given to Hardhat.
 */
export function getProvider(hre: HardhatRuntimeEnvironment): Provider {
  // @ts-ignore
  const url = new URL(hre.network.config.url);
  switch (url.protocol) {
    case "http:":
    case "https:":
      return new hre.ethers.providers.JsonRpcProvider(url.href);
    case "wss:":
      return new hre.ethers.providers.WebSocketProvider(url.href);
    default:
      throw new Error(`Network URL not valid: '${url.href}'`);
  }
}


import { HardhatRuntimeEnvironment } from 'hardhat/types';
import { WebSocketProvider } from '@ethersproject/providers';

/**
 * Start a keep-alive WebSocket connection in Hardhat.
 * 
 * The function will periodically check whether the connection is still
 * open, and restart it if it is not.
 *
 * Usage:
 *
 *   startConnection(hre, async (hre, provider) => {
 *       // Your code here
 *   }
 *
 * Source: https://github.com/ethers-io/ethers.js/issues/1053#issuecomment-808736570
 */
export function startConnection(
  hre: HardhatRuntimeEnvironment,
  onOpen: (hre: HardhatRuntimeEnvironment, p: WebSocketProvider) => void,
  expectedPongBack: number = 15000,
  keepAliveCheckInterval: number = 7500
): void {
  const logger = new hre.ethers.utils.Logger('v1.0');
  const provider: WebSocketProvider = getProvider(hre) as WebSocketProvider;

  let pingTimeout: NodeJS.Timeout;
  let keepAliveInterval: NodeJS.Timeout;

  provider._websocket.on('open', () => {
    keepAliveInterval = setInterval(() => {
      logger.debug('> Checking if the connection is alive, sending a ping');
      provider._websocket.ping();
      // Delay should be equal to the interval at which your server
      // sends out pings plus a conservative assumption of the latency.
      pingTimeout = setTimeout(() => {
        provider._websocket.terminate();
      }, expectedPongBack);
    }, keepAliveCheckInterval);

    onOpen(hre, provider);
  });

  provider._websocket.on('close', () => {
    logger.warn('> WARNING: The websocket connection was closed');
    clearInterval(keepAliveInterval);
    clearTimeout(pingTimeout);
    startConnection(hre, onOpen);
  });

  provider._websocket.on('pong', () => {
    logger.debug('> Received pong, so connection is alive, clearing the timeout');
    clearInterval(pingTimeout);
  });
}
```