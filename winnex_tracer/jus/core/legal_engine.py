"""
Tracer-JUS — Legal Engine
==========================
Orchestrates legal search and e-Discovery, integrating:

  - the Madhava engine (`winnex-madhava`, pip) for soundness-guaranteed
    vector search,
  - the Tracer-GOV audit framework (WORM, signatures, audit log),
  - Tracer-JUS legal metadata, e-Discovery, and the evidence chain.

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
import os, json, logging, time
from typing import Dict, Any, Optional, List

import numpy as np

from winnex_tracer.jus.core.metadata import CaseMetadata, LegalQuery, new_audit_id
from winnex_tracer.jus.core.discovery import DiscoveryEngine, DiscoveryResult
from winnex_tracer.jus.core.evidence import EvidenceChain

logger = logging.getLogger("tracer-jus")


class LegalEngine:
    """Legal search + e-Discovery engine with mathematical proof.

    Args:
        jurisdiction: legal jurisdiction ("global", "br", "us", "eu", ...)
        mode: "public" or "internal" (internal requires credential)
        evidence: an EvidenceChain instance (optional)
        worm_base_path: override for the evidence WORM path
    """

    def __init__(self, jurisdiction: str = "global", mode: str = "public",
                 evidence: Optional[EvidenceChain] = None,
                 worm_base_path: str = ""):
        self.jurisdiction = jurisdiction
        self.mode = mode
        self._evidence = evidence or EvidenceChain(
            evidence_base_path=worm_base_path)
        self._discovery = DiscoveryEngine(evidence=self._evidence)

    # ------------------------------------------------------------------
    # e-Discovery
    # ------------------------------------------------------------------
    def run_discovery(self, corpus: List[str], review_queries: List[str],
                      case: Optional[CaseMetadata] = None,
                      k: int = 10) -> DiscoveryResult:
        """Run e-Discovery triage with soundness guarantee."""
        return self._discovery.run_discovery(
            corpus=corpus, review_queries=review_queries,
            case=case, k=k)

    def discovery_proof_report(self, result: DiscoveryResult) -> Dict[str, Any]:
        """Build the court-ready proof report for a discovery run."""
        return self._discovery.build_proof_report(result)

    # ------------------------------------------------------------------
    # Single audited legal search (thin wrapper over Madhava)
    # ------------------------------------------------------------------
    def search(self, query_text: str, corpus: List[str],
               case: Optional[CaseMetadata] = None,
               k: int = 10) -> Dict[str, Any]:
        """Audited legal search over an in-memory corpus.

        Returns a dict with the proof and evidence receipt. For large
        corpora prefer `run_discovery` (which builds the index once).
        """
        result = self.run_discovery(
            corpus=corpus,
            review_queries=[query_text],
            case=case,
            k=k,
        )
        return result.to_dict()

    # ------------------------------------------------------------------
    # Evidence chain helpers
    # ------------------------------------------------------------------
    def verify_evidence_chain(self) -> Dict[str, Any]:
        """Verify the integrity of the evidence WORM chain."""
        return self._evidence.verify_chain()

    def evidence_events(self, audit_id: str) -> List[Dict[str, Any]]:
        """Retrieve all evidence-chain events for an audit."""
        return self._evidence.get_events(audit_id)
