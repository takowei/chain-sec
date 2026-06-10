// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./MathLib.sol";
import "@fakelib/tokens/contracts/IERC20Mintable.sol";

/// @dev Deliberately unguarded mint — triggers MINT-001 in project mode.
/// The contract also lacks a supply cap, so MINT-007 should fire too.
contract ProjectMint {
    using MathLib for uint256;

    mapping(address => uint256) private _balances;
    uint256 private _totalSupply;

    /// @dev No onlyOwner / access control modifier — intentional for testing MINT-001.
    function mint(address to, uint256 amount) external {
        _totalSupply = _totalSupply.safeAdd(amount);
        _balances[to] = _balances[to].safeAdd(amount);
    }

    function totalSupply() external view returns (uint256) {
        return _totalSupply;
    }

    function balanceOf(address account) external view returns (uint256) {
        return _balances[account];
    }
}
