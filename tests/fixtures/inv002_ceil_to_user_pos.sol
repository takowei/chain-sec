// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// INV-002 positive: mint gives user ceil amount — wrong direction, exploitable.

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

/// @dev Mint path uses divUp to compute amountOut — rounding favours user.
///      INV-002 should fire.
contract CeilToUserPos {
    using PMath for uint256;

    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    function mint(address to, uint256 syAmount, uint256 index) external returns (uint256 amountOut) {
        // BUG: divUp here means user gets slightly more per mint
        amountOut = syAmount.divUp(index);
        balanceOf[to] += amountOut;
        totalSupply += amountOut;
    }
}
