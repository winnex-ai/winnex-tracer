"""
Tracer-GOV — Self Audit Trail Logger
======================================
Logs who accessed which audit trail, when, and from where.
Required for LGPD (Art. 20) and LAI compliance — the system
must audit its own access patterns.

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
import os, json, hashlib, hmac, uuid
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone


class AuditLogTracker:
    """Self-audit trail — tracks who accessed which audit records.

    Every query to the audit trail itself is logged with
    timestamp, agent identification, and purpose.

    Integrity (SOC 2 CC7.2): each entry carries an HMAC-SHA3-256 over the
    entry content and the previous entry's HMAC, forming a tamper-evident
    hash chain. The HMAC key comes from the environment variable
    ``WINNEX_TRACER_AUDIT_HMAC_KEY`` (never hardcoded). Without the key the
    chain degrades to plain SHA-256 (integrity-checkable, not
    forgery-resistant) — deployers MUST set the key for production.

    Args:
        storage_path: Directory for access log files
    """

    def __init__(self, storage_path: str = ""):
        storage_path = storage_path or os.environ.get(
            "WINNEX_TRACER_AUDIT_LOG_PATH", "/var/lib/tracer-gov/access-log")
        self.storage_path = storage_path
        os.makedirs(storage_path, exist_ok=True)
        self._hmac_key = os.environ.get("WINNEX_TRACER_AUDIT_HMAC_KEY", "").encode()
        self._use_hmac = bool(self._hmac_key)

    def _digest(self, payload: bytes) -> str:
        """Compute HMAC-SHA3-256 (or plain SHA3-256 if no key set)."""
        if self._use_hmac:
            return hmac.new(self._hmac_key, payload, "sha3_256").hexdigest()
        return hashlib.sha3_256(payload).hexdigest()

    def _last_chain(self, log_file: str) -> str:
        """Read the last entry's chain value in the current daily file."""
        if not os.path.exists(log_file):
            return ""
        prev = ""
        with open(log_file) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    prev = json.loads(line).get("_chain", "")
                except json.JSONDecodeError:
                    continue
        return prev

    def log_access(self, audit_id: str, agent: str, agency: str,
                   ip_address: str = "", purpose: str = "") -> str:
        """Log an access to an audit record.

        Args:
            audit_id: The audit record being accessed
            agent: Who is accessing (CPF or login)
            agency: The agent's agency
            ip_address: Source IP address
            purpose: Reason for access

        Returns:
            Access log entry ID
        """
        entry_id = uuid.uuid4().hex[:16]
        entry = {
            "entry_id": entry_id,
            "audit_id": audit_id,
            "agent": agent,
            "agency": agency,
            "ip_address": ip_address,
            "purpose": purpose,
            "accessed_at": datetime.now(timezone.utc).isoformat(),
        }

        # Write to daily log file
        now = datetime.now(timezone.utc)
        log_dir = os.path.join(
            self.storage_path,
            f"{now.year:04d}", f"{now.month:02d}")
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, f"{now.day:02d}.jsonl")

        # Tamper-evident chain: digest(entry + prev_chain)
        prev_chain = self._last_chain(log_file)
        chain_input = json.dumps(entry, sort_keys=True).encode() + b"|" + prev_chain.encode()
        entry["_chain"] = self._digest(chain_input)

        with open(log_file, "a") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            f.flush()
            os.fsync(f.fileno())

        return entry_id

    def verify_chain(self) -> Dict[str, Any]:
        """Verify the tamper-evident chain across all daily files.

        Returns a report with the number of entries and any violations
        (broken chain links). For HMAC mode also indicates whether the key
        was set (forgery-resistant) or not (plain SHA, integrity only).
        """
        violations = []
        total = 0
        prev_chain = ""
        log_dir = self.storage_path
        if os.path.exists(log_dir):
            for year_dir in sorted(os.listdir(log_dir)):
                year_path = os.path.join(log_dir, year_dir)
                if not os.path.isdir(year_path):
                    continue
                for month_dir in sorted(os.listdir(year_path)):
                    month_path = os.path.join(year_path, month_dir)
                    if not os.path.isdir(month_path):
                        continue
                    for day_file in sorted(os.listdir(month_path)):
                        file_path = os.path.join(month_path, day_file)
                        if not file_path.endswith(".jsonl"):
                            continue
                        with open(file_path) as f:
                            for line in f:
                                line = line.strip()
                                if not line:
                                    continue
                                try:
                                    entry = json.loads(line)
                                except json.JSONDecodeError:
                                    continue
                                expected = entry.get("_chain", "")
                                chain_input = json.dumps(
                                    {k: v for k, v in entry.items()
                                     if k != "_chain"},
                                    sort_keys=True).encode() + b"|" + prev_chain.encode()
                                recomputed = self._digest(chain_input)
                                if expected != recomputed:
                                    violations.append({
                                        "entry": entry.get("entry_id", "?"),
                                        "file": str(file_path),
                                    })
                                prev_chain = expected
                                total += 1
        return {
            "entries": total,
            "violations": len(violations),
            "verified": len(violations) == 0,
            "hmac_protected": self._use_hmac,
            "violations_detail": violations[:20],
        }

    def get_access_history(self, audit_id: str) -> List[Dict[str, Any]]:
        """Get all access history for a given audit record.

        Args:
            audit_id: Audit record ID

        Returns:
            List of access entries chronologically
        """
        results = []
        log_dir = self.storage_path
        if not os.path.exists(log_dir):
            return results

        for year_dir in sorted(os.listdir(log_dir)):
            year_path = os.path.join(log_dir, year_dir)
            if not os.path.isdir(year_path):
                continue
            for month_dir in sorted(os.listdir(year_path)):
                month_path = os.path.join(year_path, month_dir)
                if not os.path.isdir(month_path):
                    continue
                for day_file in sorted(os.listdir(month_path)):
                    file_path = os.path.join(month_path, day_file)
                    if not file_path.endswith(".jsonl"):
                        continue
                    with open(file_path) as f:
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                entry = json.loads(line)
                                if entry.get("audit_id") == audit_id:
                                    results.append(entry)
                            except json.JSONDecodeError:
                                continue
        return results

    def get_recent_accesses(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get most recent access entries.

        Args:
            limit: Maximum number of entries

        Returns:
            List of recent access entries
        """
        all_entries = []
        log_dir = self.storage_path
        if not os.path.exists(log_dir):
            return all_entries

        for year_dir in sorted(os.listdir(log_dir), reverse=True):
            year_path = os.path.join(log_dir, year_dir)
            if not os.path.isdir(year_path):
                continue
            for month_dir in sorted(os.listdir(year_path), reverse=True):
                month_path = os.path.join(year_path, month_dir)
                if not os.path.isdir(month_path):
                    continue
                for day_file in sorted(os.listdir(month_path), reverse=True):
                    file_path = os.path.join(month_path, day_file)
                    if not file_path.endswith(".jsonl"):
                        continue
                    with open(file_path) as f:
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                all_entries.append(json.loads(line))
                            except json.JSONDecodeError:
                                continue
                    if len(all_entries) >= limit:
                        break
                if len(all_entries) >= limit:
                    break
            if len(all_entries) >= limit:
                break

        return sorted(all_entries,
                      key=lambda e: e.get("accessed_at", ""),
                      reverse=True)[:limit]
