// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Vulnerable: mint() has no access control — anyone can call it.
/// Expected finding: MINT-001 (CRITICAL)
contract UnguardedMint {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    /// @dev No onlyOwner / role check — pure MINT-001 target.
    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
    }
}
