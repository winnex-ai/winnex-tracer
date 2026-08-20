"""
Tracer-MED — Digital Chain of Custody
======================================
Evidence chain built on the Tracer-GOV WORM storage.

Every clinical triage, result, and proof is written to an immutable WORM
store (append-only, SHA3-256 hash chain, fsync). Tampering is detected —
the foundation for **auditability and accountability** in healthcare.

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
import json, os, logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone

logger = logging.getLogger("tracer-med.evidence")


class EvidenceChain:
    """Chain of custody for clinical triage, backed by WORM storage."""

    def __init__(self, worm=None, evidence_base_path: str = ""):
        if worm is not None:
            self.worm = worm
        else:
            from winnex_tracer.persistence import WormStorage  # shared base
            base = evidence_base_path or os.environ.get(
                "TRACER_MED_EVIDENCE_PATH", "/var/lib/tracer-med/evidence")
            self.worm = WormStorage(base_path=base)
        self._last_receipt: Dict[str, Any] = {}

    def record_triage(self, audit_id: str, context: Dict[str, Any],
                      filter_applied: Dict[str, Any],
                      queries: List[str], bound_violations: int,
                      bound_pairs: int, corpus_size: int,
                      signature: str = "",
                      signature_algorithm: str = "") -> Dict[str, Any]:
        """Record a clinical triage as an evidence-chain event."""
        event = {
            "event_type": "clinical_triage",
            "audit_id": audit_id,
            "context": context,
            "filter_applied": filter_applied,
            "queries": list(queries),
            "bound_violations": bound_violations,
            "bound_pairs": bound_pairs,
            "corpus_size": corpus_size,
            "signature": signature,
            "signature_algorithm": signature_algorithm,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        }
        receipt = self.worm.append(event)
        self._last_receipt = receipt
        logger.info("EvidenceChain: recorded triage %s (block %s)",
                    audit_id, receipt.get("worm_hash", "")[:12])
        return receipt

    def record_document_access(self, audit_id: str, record_id: str,
                               action: str, actor: str = "") -> Dict[str, Any]:
        """Record access to a clinical record (who viewed what, when)."""
        event = {
            "event_type": "record_access",
            "audit_id": audit_id,
            "record_id": record_id,
            "action": action,                 # view / export / modify
            "actor": actor,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        }
        receipt = self.worm.append(event)
        self._last_receipt = receipt
        return receipt

    def verify_chain(self) -> Dict[str, Any]:
        return self.worm.verify_integrity()

    def get_events(self, audit_id: str) -> List[Dict[str, Any]]:
        events = []
        base = self.worm.base_path
        if not base.exists():
            return events
        for f in sorted(base.rglob("records.jsonl")):
            with open(f) as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        block = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    data = block.get("data", {})
                    if data.get("audit_id") == audit_id:
                        events.append({
                            "block_hash": block.get("block_hash", ""),
                            "prev_hash": block.get("prev_hash", ""),
                            **data,
                        })
        return events

    def last_receipt(self) -> Dict[str, Any]:
        return self._last_receipt
