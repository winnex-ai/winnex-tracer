"""
Tracer-GOV — Backup File Store for non-blockchain deployments
==============================================================
Append-only JSONL store with local hash chain.
Used as secondary store when blockchain is unavailable.

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
import os, json, hashlib, time
from typing import Optional, List, Dict, Any
from pathlib import Path


class FileStore:
    """Append-only file store with local hash chain.

    Args:
        base_path: Root directory for file storage
        hash_algorithm: Hash algorithm (e.g. sha3_256)
    """

    def __init__(self, base_path: str = "/var/lib/tracer-gov/filestore",
                 hash_algorithm: str = "sha3_256"):
        self.base_path = Path(base_path)
        self.hash_algorithm = hash_algorithm
        self._chain_file = self.base_path / "chain.sha3"
        self._last_hash = b""
        self._load_chain()

    def _load_chain(self):
        if self._chain_file.exists():
            with open(self._chain_file) as f:
                hex_str = f.read().strip()
            self._last_hash = bytes.fromhex(hex_str) if hex_str else b""

    def _hash(self, data: bytes) -> bytes:
        h = hashlib.new(self.hash_algorithm)
        h.update(data)
        return h.digest()

    def append(self, record_id: str, record: dict) -> Dict[str, Any]:
        """Append record with hash chain.

        Args:
            record_id: Unique record identifier
            record: Dict with record data

        Returns:
            Receipt with block hash and path
        """
        timestamp = time.time()
        block = {
            "record_id": record_id,
            "data": record,
            "timestamp": timestamp,
            "prev_hash": self._last_hash.hex(),
        }
        block_bytes = json.dumps(block, sort_keys=True).encode()
        block_hash = self._hash(block_bytes).hex()
        block["block_hash"] = block_hash

        store_file = self.base_path / "store.jsonl"
        store_file.parent.mkdir(parents=True, exist_ok=True)
        with open(store_file, "a") as f:
            f.write(json.dumps(block, ensure_ascii=False) + "\n")
            f.flush()
            os.fsync(f.fileno())

        self._last_hash = bytes.fromhex(block_hash)
        with open(self._chain_file, "w") as f:
            f.write(block_hash)

        return {
            "store": "file",
            "record_id": record_id,
            "block_hash": block_hash,
            "path": str(store_file),
        }

    def get(self, record_id: str) -> Optional[dict]:
        """Get record by ID (O(n) scan)."""
        store_file = self.base_path / "store.jsonl"
        if not store_file.exists():
            return None
        with open(store_file) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    block = json.loads(line)
                    if block.get("record_id") == record_id:
                        return block
                except json.JSONDecodeError:
                    continue
        return None

    def verify_chain(self) -> Dict[str, Any]:
        """Verify integrity of the hash chain."""
        store_file = self.base_path / "store.jsonl"
        if not store_file.exists():
            return {"verified": True, "blocks": 0}

        violations = []
        prev = b""
        blocks = []
        with open(store_file) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    blocks.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

        for i, block in enumerate(blocks):
            if block.get("prev_hash", "") != prev.hex():
                violations.append({
                    "block": i, "reason": "prev_hash_mismatch"
                })
            block_copy = {k: v for k, v in block.items()
                          if k != "block_hash"}
            expected = self._hash(
                json.dumps(block_copy, sort_keys=True).encode()
            ).hex()
            if block.get("block_hash", "") != expected:
                violations.append({
                    "block": i, "reason": "hash_mismatch"
                })
            prev = bytes.fromhex(block.get("block_hash", ""))

        return {
            "verified": len(violations) == 0,
            "blocks": len(blocks),
            "violations": len(violations),
            "violations_detail": violations[:20],
        }
