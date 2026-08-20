"""
Tracer-GOV — Blockchain Store for dual-write
=============================================
Submits audit proofs to blockchain (Polygon, Ethereum, etc.).

Backend resolution (in order):
  1. WinnexChain from winnex-proof-of-audit (github.com/winnex-ai/winnex-proof-of-audit)
  2. Built-in web3.py implementation (fallback)

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
import os, json, hashlib, logging
from typing import Optional, Dict, Any
from pathlib import Path

logger = logging.getLogger("tracer-gov")

# Try to import WinnexChain from the Winnex stack
_HAS_WINNEX_CHAIN = False
try:
    from src.chain import WinnexChain as _WinnexChain
    _HAS_WINNEX_CHAIN = True
    logger.info("BlockchainStore: using WinnexChain from winnex-proof-of-audit")
except ImportError:
    logger.info("BlockchainStore: WinnexChain not found, using built-in web3.py")


class BlockchainStore:
    """Blockchain store — submits proof batches to smart contract.

    Delegates to WinnexChain if available, otherwise uses raw web3.py.

    Args:
        rpc_url: RPC node URL
        contract_address: Smart contract address
        chain_name: Chain name (polygon, ethereum, avalanche, hedera, polygon-mumbai, sepolia)
        private_key_env: Environment variable holding the private key
    """

    def __init__(self, rpc_url: str = "", contract_address: str = "",
                 chain_name: str = "polygon",
                 private_key_env: str = "WINNEX_TRACER_BLOCKCHAIN_KEY"):
        self.rpc_url = rpc_url
        self.contract_address = contract_address
        self.chain_name = chain_name
        self.private_key_env = private_key_env
        self._chain = None

    def _get_private_key(self) -> str:
        return os.environ.get(self.private_key_env, "")

    def _get_chain(self):
        """Resolve backend — WinnexChain first, then built-in web3."""
        if self._chain is not None:
            return self._chain

        pk = self._get_private_key()
        rpc = self.rpc_url or os.environ.get(
            "WINNEX_TRACER_BLOCKCHAIN_RPC", "")
        addr = self.contract_address or os.environ.get(
            "WINNEX_TRACER_BLOCKCHAIN_CONTRACT", "")

        if _HAS_WINNEX_CHAIN:
            # Use WinnexChain from winnex-proof-of-audit
            try:
                self._chain = _WinnexChain(
                    chain=self.chain_name,
                    contract_address=addr,
                    private_key=pk,
                )
                # Override RPC if explicitly configured
                if rpc and hasattr(self._chain.config, "__setitem__"):
                    self._chain.config["rpc"] = rpc
                elif rpc and isinstance(self._chain.config, dict):
                    self._chain.config["rpc"] = rpc
                return self._chain
            except Exception as e:
                logger.warning(
                    f"WinnexChain init failed ({e}), falling back to web3.py")

        # Fallback: use embedded web3.py (same pattern as WinnexChain)
        self._chain = _BuiltinChain(
            chain_name=self.chain_name,
            rpc_url=rpc,
            contract_address=addr,
            private_key=pk,
        )
        return self._chain

    def submit_batch(self, merkle_root: str, proof_count: int,
                     agency: str = "", source_database: str = "") -> Dict[str, Any]:
        """Submit a batch of proofs to the blockchain.

        Args:
            merkle_root: Merkle root of proof hashes
            proof_count: Number of proofs in the batch
            agency: Requesting agency
            source_database: Source database

        Returns:
            Receipt with tx_hash and block_number
        """
        pk = self._get_private_key()
        if not pk:
            return {
                "store": "blockchain",
                "status": "skipped",
                "reason": f"{self.private_key_env} not configured",
            }

        chain = self._get_chain()
        try:
            return chain.submit_batch(merkle_root, proof_count)
        except AttributeError:
            # _BuiltinChain has same method
            return chain.submit_batch(merkle_root, proof_count)

    def verify(self, proof_hash: str) -> Dict[str, Any]:
        """Verify a proof on-chain."""
        pk = self._get_private_key()
        if not pk:
            return {"verified": False, "reason": "no private key configured"}
        chain = self._get_chain()
        try:
            return chain.verify_on_chain(proof_hash)
        except AttributeError:
            return chain.verify(proof_hash)


class _BuiltinChain:
    """Built-in web3.py chain — fallback when WinnexChain is unavailable."""

    SUPPORTED_CHAINS = {
        "polygon":        {"chain_id": 137,   "rpc": "https://polygon-rpc.com"},
        "ethereum":       {"chain_id": 1,     "rpc": "https://eth-mainnet.g.alchemy.com/v2/"},
        "avalanche":      {"chain_id": 43114, "rpc": "https://api.avax.network/ext/bc/C/rpc"},
        "hedera":         {"chain_id": 295,   "rpc": "https://mainnet.hashio.io/api"},
        "polygon-mumbai": {"chain_id": 80001, "rpc": "https://rpc-mumbai.maticvigil.com"},
        "sepolia":        {"chain_id": 11155111, "rpc": "https://rpc.sepolia.org"},
    }

    def __init__(self, chain_name="polygon", rpc_url="",
                 contract_address="", private_key=""):
        self.chain_name = chain_name
        self.config = self.SUPPORTED_CHAINS.get(chain_name, {})
        self.contract_address = contract_address
        self.private_key = private_key
        self._web3 = None
        self._contract = None
        if rpc_url:
            self.config = {**self.config, "rpc": rpc_url}
        self._connect()

    def _connect(self):
        from web3 import Web3
        rpc = self.config.get("rpc", "")
        if not rpc:
            raise ConnectionError(f"No RPC URL for chain {self.chain_name}")
        self._web3 = Web3(Web3.HTTPProvider(rpc))
        abi_path = (Path(__file__).parent.parent /
                    "config" / "TracerGovRegistry.abi")
        if abi_path.exists() and self.contract_address:
            with open(abi_path) as f:
                abi = json.load(f)
            self._contract = self._web3.eth.contract(
                address=self._web3.to_checksum_address(self.contract_address),
                abi=abi,
            )

    def submit_batch(self, merkle_root: str, proof_count: int) -> Dict[str, Any]:
        acct = self._web3.eth.account.from_key(self.private_key)
        tx = self._contract.functions.submitBatch(
            bytes.fromhex(
                merkle_root[2:] if merkle_root.startswith("0x") else merkle_root
            ),
            proof_count,
            "", "",
        ).build_transaction({
            "from": acct.address,
            "nonce": self._web3.eth.get_transaction_count(acct.address),
            "gas": 500000,
            "gasPrice": self._web3.eth.gas_price,
        })
        signed = acct.sign_transaction(tx)
        tx_hash = self._web3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = self._web3.eth.wait_for_transaction_receipt(tx_hash)
        return {
            "store": "blockchain",
            "chain": self.chain_name,
            "tx_hash": tx_hash.hex(),
            "block_number": receipt["blockNumber"],
            "status": "confirmed" if receipt["status"] == 1 else "failed",
            "proof_count": proof_count,
        }

    def verify(self, proof_hash: str) -> Dict[str, Any]:
        try:
            v = self._contract.functions.isVerified(
                bytes.fromhex(proof_hash)).call()
            return {"verified": v, "chain": self.chain_name}
        except Exception as e:
            return {"verified": False, "error": str(e)}
