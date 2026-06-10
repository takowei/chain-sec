// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Contract where the mint logic lives in internal/private functions.
/// Internal functions are not directly callable from outside the contract,
/// so access control must be enforced by the public callers, not here.
/// MINT-001 must NOT fire on internal/private mint helpers.
contract InternalMint {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    /// @dev Internal mint helper — access control enforced by callers.
    function _mint(address to, uint256 amount) internal {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    /// @dev Private mint implementation.
    function __mint(address to, uint256 amount) private {
        _mint(to, amount);
    }

    /// @dev Public entry point with access control calling the internal helper.
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function mint(address to, uint256 amount) external onlyOwner {
        __mint(to, amount);
    }
}
