"""
Tracer-JUS — Digital Chain of Custody
======================================
Evidence chain built on the Tracer-GOV WORM storage.

Every legal search, result, and proof is written to an immutable WORM store
(append-only, SHA3-256 hash chain, fsync). Any attempt to alter or delete a
record breaks the chain and is immediately detectable — the foundation for
**admissibility of digital evidence** in a legal proceeding.

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
import json, os, logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone

logger = logging.getLogger("tracer-jus.evidence")


class EvidenceChain:
    """Chain of custody for legal searches, backed by WORM storage.

    Args:
        worm: A Tracer-GOV WormStorage instance (or a path to build one).
        evidence_base_path: Root path for the evidence WORM store.
    """

    def __init__(self, worm=None, evidence_base_path: str = ""):
        if worm is not None:
            self.worm = worm
        else:
            from winnex_tracer.persistence import WormStorage  # shared base
            base = evidence_base_path or os.environ.get(
                "TRACER_JUS_EVIDENCE_PATH", "/var/lib/tracer-jus/evidence")
            self.worm = WormStorage(base_path=base)
        self._last_receipt: Dict[str, Any] = {}

    # ------------------------------------------------------------------
    # Evidence events
    # ------------------------------------------------------------------
    def record_search(self, audit_id: str, case: Dict[str, Any],
                      query_text: str, bound_violations: int,
                      bound_pairs: int, result_indices: List[int],
                      signature: str = "",
                      signature_algorithm: str = "") -> Dict[str, Any]:
        """Record a legal search as an evidence-chain event.

        Returns the WORM receipt (hash chain position + hashes).
        """
        event = {
            "event_type": "legal_search",
            "audit_id": audit_id,
            "case": case,
            "query": query_text,
            "bound_violations": bound_violations,
            "bound_pairs": bound_pairs,
            "result_indices": list(result_indices),
            "signature": signature,
            "signature_algorithm": signature_algorithm,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        }
        receipt = self.worm.append(event)
        self._last_receipt = receipt
        logger.info("EvidenceChain: recorded search %s (block %s)",
                    audit_id, receipt.get("worm_hash", "")[:12])
        return receipt

    def record_document_review(self, audit_id: str, doc_id: int,
                               review_decision: str,
                               reviewer: str = "") -> Dict[str, Any]:
        """Record a document-review decision (e-Discovery coding)."""
        event = {
            "event_type": "document_review",
            "audit_id": audit_id,
            "doc_id": doc_id,
            "review_decision": review_decision,   # relevant/privileged/irrelevant
            "reviewer": reviewer,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        }
        receipt = self.worm.append(event)
        self._last_receipt = receipt
        return receipt

    def record_export(self, audit_id: str, scope: str,
                      exported_by: str = "") -> Dict[str, Any]:
        """Record an evidence export (chain of custody of produced set)."""
        event = {
            "event_type": "evidence_export",
            "audit_id": audit_id,
            "scope": scope,
            "exported_by": exported_by,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        }
        receipt = self.worm.append(event)
        self._last_receipt = receipt
        return receipt

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------
    def verify_chain(self) -> Dict[str, Any]:
        """Verify the integrity of the entire evidence chain."""
        return self.worm.verify_integrity()

    def get_events(self, audit_id: str) -> List[Dict[str, Any]]:
        """Retrieve all evidence-chain events for a given audit_id."""
        # WORM is addressed by block_hash; here we scan for matching audit_id.
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
        """The most recent WORM receipt (for client confirmation)."""
        return self._last_receipt
