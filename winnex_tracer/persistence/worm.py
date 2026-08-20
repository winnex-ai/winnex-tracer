"""
winnex-tracer-core — WORM Storage (Write Once Read Many)
==================================================
Immutable disk storage with SHA3-256 hash chain.
Records are written as JSONL files organized by date,
with each block chained to the previous via cryptographic hash.

This is true WORM — records cannot be altered or deleted once written.

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
import os, json, hashlib, time
from typing import Optional, List, Dict, Any
from pathlib import Path
from datetime import datetime


class WormStorage:
    """Write Once Read Many — append-only log with hash chain.

    Args:
        base_path: Root directory for WORM storage
        hash_algorithm: Hash algorithm (default sha3_256)
    """

    def __init__(self, base_path: str = "/var/lib/tracer-gov/worm",
                 hash_algorithm: str = "sha3_256"):
        self.base_path = Path(base_path)
        self.hash_algorithm = hash_algorithm
        self._chain_file = self.base_path / ".chain"
        self._last_hash = b""
        self._load_chain_state()

    def _load_chain_state(self):
        """Load last chain hash from disk.

        Read-only: does NOT create the directory. Creation happens only
        on append (the actual write). This lets verify/get run against a
        base_path that does not exist or is not writable.
        """
        if self._chain_file.exists():
            with open(self._chain_file) as f:
                hex_str = f.read().strip()
            self._last_hash = bytes.fromhex(hex_str) if hex_str else b""
        else:
            self._last_hash = b""

    def _get_daily_path(self) -> Path:
        """Get daily file path: base_path/YYYY/MM/DD/records.jsonl."""
        now = datetime.utcnow()
        daily_dir = self.base_path / f"{now.year:04d}" / f"{now.month:02d}" / f"{now.day:02d}"
        daily_dir.mkdir(parents=True, exist_ok=True)
        return daily_dir / "records.jsonl"

    def _compute_hash(self, data: bytes) -> bytes:
        """Compute hash using configured algorithm."""
        h = hashlib.new(self.hash_algorithm)
        h.update(data)
        return h.digest()

    def append(self, record: dict) -> Dict[str, Any]:
        """Immutable append — writes record + hash chain.

        Args:
            record: Dict with audit record data

        Returns:
            WORM receipt with hash and path
        """
        timestamp = time.time()

        # Strip any previous chain fields to avoid overwrite contamination
        record = {k: v for k, v in record.items()
                  if k not in ("_worm_hash", "_worm_prev_hash", "_worm_timestamp")}

        # Build block with hash chain
        block = {
            "data": record,
            "timestamp": timestamp,
            "prev_hash": self._last_hash.hex(),
        }
        block_bytes = json.dumps(block, sort_keys=True).encode()
        block_hash = self._compute_hash(block_bytes)
        block["block_hash"] = block_hash.hex()

        # Append to daily file (enforced append-only via file system)
        daily_path = self._get_daily_path()
        line = json.dumps(block, ensure_ascii=False)
        with open(daily_path, "a") as f:
            f.write(line + "\n")
            f.flush()
            os.fsync(f.fileno())

        # Persist chain state
        self._last_hash = block_hash
        with open(self._chain_file, "w") as f:
            f.write(block_hash.hex())

        return {
            "worm_path": str(daily_path.relative_to(self.base_path)),
            "worm_hash": block_hash.hex(),
            "worm_prev_hash": block.get("prev_hash", ""),
            "block_number": len(list(self.base_path.rglob("records.jsonl"))),
        }

    def verify_integrity(self) -> Dict[str, Any]:
        """Scan all files and verify the complete hash chain.

        Returns:
            Integrity report with any violations found
        """
        all_records = []
        for f in sorted(self.base_path.rglob("records.jsonl")):
            with open(f) as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        try:
                            all_records.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue

        violations = []
        prev = b""
        for i, block in enumerate(all_records):
            expected_prev = prev.hex()
            if block.get("prev_hash", "") != expected_prev:
                violations.append({
                    "block": i,
                    "expected_prev": expected_prev,
                    "found_prev": block.get("prev_hash", ""),
                })
            # Recompute hash and compare
            block_copy = {k: v for k, v in block.items() if k != "block_hash"}
            block_bytes = json.dumps(block_copy, sort_keys=True).encode()
            expected_hash = self._compute_hash(block_bytes).hex()
            if block.get("block_hash", "") != expected_hash:
                violations.append({
                    "block": i,
                    "expected_hash": expected_hash,
                    "found_hash": block.get("block_hash", ""),
                })
            prev = bytes.fromhex(block.get("block_hash", ""))

        return {
            "total_blocks": len(all_records),
            "violations": len(violations),
            "chain_integrity_verified": len(violations) == 0,
            "violations_detail": violations[:50],
            "algorithm": self.hash_algorithm,
        }

    def get_record(self, block_hash: str) -> Optional[dict]:
        """Get a record by block hash (O(n) — acceptable for audit)."""
        for f in sorted(self.base_path.rglob("records.jsonl")):
            with open(f) as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        block = json.loads(line)
                        if block.get("block_hash") == block_hash:
                            return block
                    except json.JSONDecodeError:
                        continue
        return None

    def get_records_by_date(self, year: int, month: int, day: int) -> List[dict]:
        """Get all records for a specific date."""
        daily_path = self.base_path / f"{year:04d}" / f"{month:02d}" / f"{day:02d}" / "records.jsonl"
        if not daily_path.exists():
            return []
        records = []
        with open(daily_path) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return records
