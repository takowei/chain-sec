// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Abstract contract with unimplemented mint — no body to exploit.
/// MINT-001 must NOT fire on the abstract declaration itself.
/// Only a concrete subclass that does NOT add access control would be a real finding.
abstract contract AbstractMint {
    /// @dev Declared but not implemented — subclasses must override.
    function mint(address to, uint256 amount) external virtual;
}
