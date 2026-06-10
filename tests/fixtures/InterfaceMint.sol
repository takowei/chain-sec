// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Interface declaration — no function body.
/// MINT-001 must NOT fire here (no implementation, no state mutation possible).
interface InterfaceMint {
    function mint(address to, uint256 amount) external;

    function mintByYT(address to, uint256 amount) external;

    function totalSupply() external view returns (uint256);
}
