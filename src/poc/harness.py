"""Local anvil fork harness for PoC validation.

SECURITY CONTRACT
-----------------
- Mainnet RPC endpoints are BLOCKED at the code level (see _assert_not_mainnet).
- Only loopback (127.0.0.1 / localhost) and explicitly whitelisted testnet
  RPC prefixes are allowed.
- This module must NEVER be modified to allow mainnet connections.
  Any such modification violates RULES-OF-ENGAGEMENT.md.

Usage
-----
    harness = AnvilHarness(fork_url="http://127.0.0.1:8545")
    with harness.start() as rpc:
        # rpc is the local anvil JSON-RPC endpoint
        ...
"""

from __future__ import annotations

import re
import shutil
import subprocess
import time
from collections.abc import Generator
from contextlib import contextmanager

# ---------------------------------------------------------------------------
# Mainnet RPC block-list
# ---------------------------------------------------------------------------

# Patterns that identify mainnet (Ethereum L1) or high-value chain RPC URLs.
# Any URL matching these patterns is REFUSED.
_MAINNET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"mainnet", re.IGNORECASE),
    re.compile(r"eth-mainnet", re.IGNORECASE),
    re.compile(r"infura\.io/v\d+/[0-9a-f]{32}", re.IGNORECASE),
    re.compile(r"alchemyapi\.io/v\d+/[^/]+$", re.IGNORECASE),
    re.compile(r"alchemy\.com/v\d+/[^/]+$", re.IGNORECASE),
    re.compile(r"cloudflare-eth\.com", re.IGNORECASE),
    re.compile(r"rpc\.ankr\.com/eth$", re.IGNORECASE),
    re.compile(r"1rpc\.io/eth$", re.IGNORECASE),
    re.compile(r"eth\.llamarpc\.com", re.IGNORECASE),
    re.compile(r"rpc\.flashbots\.net", re.IGNORECASE),
    # Block all non-local HTTP(S) by default; only localhost passes.
    re.compile(r"^https?://(?!localhost)(?!127\.\d+\.\d+\.\d+)", re.IGNORECASE),
]

# Whitelisted RPC prefixes that ARE allowed (local + testnet).
_ALLOWED_PREFIXES: list[str] = [
    "http://127.",
    "http://localhost",
    "https://127.",
    "https://localhost",
    # Common public testnets — add more as needed.
    "https://rpc.sepolia.org",
    "https://rpc.holesky.ethpandaops.io",
    "https://goerli.infura.io",
    "https://rpc-mumbai.maticvigil.com",
]


class MainnetRpcError(RuntimeError):
    """Raised when a mainnet RPC URL is detected and blocked."""


def _assert_not_mainnet(url: str) -> None:
    """
    Raise MainnetRpcError if *url* looks like a mainnet endpoint.

    Whitelist takes priority: if the URL starts with any allowed prefix,
    it is accepted. Otherwise any mainnet pattern triggers a hard error.
    """
    normalized = url.strip().rstrip("/")
    for prefix in _ALLOWED_PREFIXES:
        if normalized.lower().startswith(prefix.lower()):
            return  # explicitly allowed
    for pattern in _MAINNET_PATTERNS:
        if pattern.search(normalized):
            raise MainnetRpcError(
                f"Mainnet RPC blocked: {url!r}. "
                "PoC harness only allows localhost / testnet endpoints. "
                "See RULES-OF-ENGAGEMENT.md §2."
            )


# ---------------------------------------------------------------------------
# Anvil harness
# ---------------------------------------------------------------------------


class AnvilHarness:
    """
    Manages a local anvil process for PoC fork testing.

    Parameters
    ----------
    fork_url:
        The RPC URL to fork from. Must be localhost or a whitelisted testnet.
        Mainnet URLs are rejected immediately.
    port:
        Local port for the anvil JSON-RPC server (default 8555 to avoid
        conflicting with a running node on 8545).
    block_number:
        Optional specific block to fork at.
    chain_id:
        Chain ID for the local fork (default 31337).
    """

    def __init__(
        self,
        fork_url: str = "http://127.0.0.1:8545",
        port: int = 8555,
        block_number: int | None = None,
        chain_id: int = 31337,
    ) -> None:
        _assert_not_mainnet(fork_url)  # hard guard — must stay first
        self.fork_url = fork_url
        self.port = port
        self.block_number = block_number
        self.chain_id = chain_id
        self._proc: subprocess.Popen | None = None

    @property
    def rpc_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def anvil_available(self) -> bool:
        return shutil.which("anvil") is not None

    def _build_cmd(self) -> list[str]:
        cmd = [
            "anvil",
            "--fork-url",
            self.fork_url,
            "--port",
            str(self.port),
            "--chain-id",
            str(self.chain_id),
            "--silent",
        ]
        if self.block_number is not None:
            cmd += ["--fork-block-number", str(self.block_number)]
        return cmd

    def start(self) -> None:
        """Start the anvil process. Call stop() when done."""
        if not self.anvil_available:
            raise RuntimeError(
                "anvil not found. Install Foundry: https://getfoundry.sh/. "
                "Root must install Foundry manually (docker/sudo not available here)."
            )
        if self._proc is not None:
            raise RuntimeError("AnvilHarness already started.")
        self._proc = subprocess.Popen(
            self._build_cmd(),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        self._wait_ready()

    def stop(self) -> None:
        """Terminate the anvil process."""
        if self._proc is not None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
            self._proc = None

    def _wait_ready(self, retries: int = 20, delay: float = 0.3) -> None:
        """Poll until anvil is accepting connections."""
        import socket

        for _ in range(retries):
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=1):
                    return
            except OSError:
                time.sleep(delay)
        raise RuntimeError(
            f"anvil did not become ready on port {self.port} after {retries} attempts."
        )

    @contextmanager
    def run(self) -> Generator[str, None, None]:
        """
        Context manager that starts anvil and yields the local RPC URL.

        Example
        -------
            with harness.run() as rpc_url:
                w3 = Web3(Web3.HTTPProvider(rpc_url))
                ...
        """
        self.start()
        try:
            yield self.rpc_url
        finally:
            self.stop()
