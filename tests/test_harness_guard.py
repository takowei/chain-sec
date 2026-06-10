"""Tests for AnvilHarness mainnet-RPC guard (_assert_not_mainnet).

Red tests: mainnet / public-RPC URLs must raise MainnetRpcError.
Green tests: localhost / 127.x.x.x URLs must pass silently.
"""

from __future__ import annotations

import pytest

from src.poc.harness import MainnetRpcError, _assert_not_mainnet


class TestMainnetBlocked:
    """URLs that identify mainnet must raise MainnetRpcError."""

    @pytest.mark.parametrize(
        "url",
        [
            "https://mainnet.infura.io/v3/abc123",
            "https://eth-mainnet.alchemyapi.io/v2/abc123",
            "https://cloudflare-eth.com",
            "https://rpc.ankr.com/eth",
            "https://1rpc.io/eth",
            "https://eth.llamarpc.com",
            "https://rpc.flashbots.net",
            "https://mainnet.example.com/rpc",
        ],
    )
    def test_mainnet_url_raises(self, url):
        with pytest.raises(MainnetRpcError):
            _assert_not_mainnet(url)


class TestLocalAllowed:
    """Localhost and 127.x.x.x URLs must be accepted without raising."""

    @pytest.mark.parametrize(
        "url",
        [
            "http://127.0.0.1:8545",
            "http://127.0.0.1:8555",
            "http://localhost:8545",
            "https://localhost:8545",
            "http://127.1.2.3:9000",
        ],
    )
    def test_local_url_allowed(self, url):
        _assert_not_mainnet(url)  # must not raise
