// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @dev Simple library imported by the main contract to exercise multi-file compilation.
library MathLib {
    /// @dev Saturating add — result capped at type(uint256).max.
    function safeAdd(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        // overflow check: c must be >= a
        require(c >= a, "MathLib: overflow");
        return c;
    }
}
