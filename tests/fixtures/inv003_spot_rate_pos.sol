// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// INV-003 positive: mint amount derived from latestRoundData — spot price, manipulable.

interface IChainlinkOracle {
    function latestRoundData()
        external
        view
        returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);
}

/// @dev Minting amount computed from spot Chainlink price.
///      INV-003 should fire.
contract SpotRateMintPos {
    IChainlinkOracle public oracle;

    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    function mint(address to, uint256 inputAmount) external {
        // BUG: latestRoundData is a spot price — can be manipulated in the same tx
        (, int256 rate, , , ) = oracle.latestRoundData();
        uint256 amountOut = (inputAmount * uint256(rate)) / 1e18;
        balanceOf[to] += amountOut;
        totalSupply += amountOut;
    }
}
