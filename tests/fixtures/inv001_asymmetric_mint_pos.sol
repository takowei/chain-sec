// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// INV-001 positive: only mints PT, never YT — asymmetric supply creation.

interface IERC20Mintable {
    function mint(address to, uint256 amount) external;
    function burn(address from, uint256 amount) external;
}

/// @dev Contract holds both PT and YT addresses but only mints PT.
///      This is the asymmetric-mint pattern: INV-001 should fire.
contract AsymmetricMintPos {
    address public PT;
    address public YT;

    /// @dev Only mints PT, missing the matching YT mint.
    function mintPT(address to, uint256 amount) external {
        IERC20Mintable(PT).mint(to, amount);
        // BUG: IERC20Mintable(YT).mint(to, amount) is missing
    }
}
