// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// INV-002 negative: mint gives user floor amount — correct direction.

library PMath {
    /// @dev Ceiling division: rounds UP, favours receiver.
    function divUp(uint256 a, uint256 b) internal pure returns (uint256) {
        return (a + b - 1) / b;
    }

    /// @dev Floor division: rounds DOWN, favours protocol.
    function divDown(uint256 a, uint256 b) internal pure returns (uint256) {
        return a / b;
    }
}

/// @dev Mint path uses divDown to compute amountOut — rounding favours protocol.
///      INV-002 should NOT fire.
contract FloorToUserNeg {
    using PMath for uint256;

    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    function mint(address to, uint256 syAmount, uint256 index) external returns (uint256 amountOut) {
        // Correct: divDown means protocol keeps the rounding error
        amountOut = syAmount.divDown(index);
        balanceOf[to] += amountOut;
        totalSupply += amountOut;
    }
}
