// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Vulnerable: issueBatch() updates totalSupply without updating balances.
/// Expected finding: MINT-004 (MEDIUM) — totalSupply written, no balance update.
contract SupplyMismatch {
    address public owner;
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    /// @dev Increments totalSupply but never touches balanceOf — MINT-004 target.
    function issueBatch(uint256 amount) external onlyOwner {
        totalSupply += amount;
    }
}
