// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// INV-001 negative: mints both PT and YT symmetrically — correct accounting.

interface IERC20Mintable {
    function mint(address to, uint256 amount) external;
    function burn(address from, uint256 amount) external;
}

/// @dev Both PT and YT are minted together with the same amount.
///      INV-001 should NOT fire.
contract SymmetricMintNeg {
    address public PT;
    address public YT;

    /// @dev Mints matching PT and YT — correct paired supply.
    function mintPY(address to, uint256 amount) external {
        IERC20Mintable(PT).mint(to, amount);
        IERC20Mintable(YT).mint(to, amount);
    }
}
