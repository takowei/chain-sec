// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// INV-003 negative: mint amount derived from a stored cumulative index — not manipulable.

/// @dev Minting amount computed from a stored (checkpoint-based) index.
///      INV-003 should NOT fire.
contract StoredIndexMintNeg {
    /// @dev Accumulated exchange index, updated via checkpoint mechanism.
    uint256 public storedIndex;

    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    function mint(address to, uint256 inputAmount) external {
        // Safe: storedIndex is a checkpoint value, not a live spot price
        uint256 amountOut = (inputAmount * storedIndex) / 1e18;
        balanceOf[to] += amountOut;
        totalSupply += amountOut;
    }
}
