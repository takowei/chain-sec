// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Vulnerable: mint() is owner-gated but has no supply cap.
/// The contract deliberately avoids cap/limit/max/supply variable names
/// so the MINT-007 pattern rule fires.
/// Expected finding: MINT-007 (LOW)
contract NoCap {
    address public owner;
    mapping(address => uint256) public balances;
    uint256 public issued;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    /// @dev Access-controlled, but no cap/limit/max variable — MINT-007 target.
    function mint(address to, uint256 amount) external onlyOwner {
        balances[to] += amount;
        issued += amount;
    }
}
