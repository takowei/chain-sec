// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Contract with view/pure helper functions that contain "mint" in the name.
/// These are read-only preview/quote helpers (like Pendle router-static).
/// MINT-001 must NOT fire here (view/pure cannot mutate state).
contract ViewMint {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    /// @dev Read-only preview of how many tokens would be minted — not a real mint.
    function previewMint(uint256 amount) external view returns (uint256) {
        return (totalSupply + amount) * 2;
    }

    /// @dev Pure calculation helper with "mint" in the name.
    function calcMintAmount(uint256 assets) external pure returns (uint256) {
        return assets * 1e18;
    }
}
