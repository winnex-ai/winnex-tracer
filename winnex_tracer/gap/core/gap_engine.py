"""
Tracer-GAP — Gap Engine
========================
Orchestrates financial gap identification, integrating:

  - the Madhava engine (`winnex-madhava`, pip) for soundness-guaranteed
    vector search,
  - structured financial metadata filtering (sector, instrument, CIK,
    period, risk category),
  - the SEC EDGAR 10-K loader for real filings,
  - the Tracer-GOV audit framework (WORM, signatures, audit log),
  - Tracer-GAP financial metadata and evidence chain.

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
import os, logging
from typing import Dict, Any, Optional, List

from winnex_tracer.gap.core.metadata import FinancialMetadata, FinancialRecord
from winnex_tracer.gap.core.gap_analysis import GapAnalysisEngine, GapResult, MetadataFilter
from winnex_tracer.gap.core.evidence import EvidenceChain
from winnex_tracer.gap.core.sec_loader import SecLoader

logger = logging.getLogger("tracer-gap")


class GapEngine:
    """Financial gap analysis engine with mathematical proof.

    Args:
        jurisdiction: legal jurisdiction ("global", "br", "us", "eu", ...)
        mode: "public" or "internal"
        evidence: an EvidenceChain (optional)
        worm_base_path: override for the evidence WORM path
    """

    def __init__(self, jurisdiction: str = "global", mode: str = "public",
                 evidence: Optional[EvidenceChain] = None,
                 worm_base_path: str = ""):
        self.jurisdiction = jurisdiction
        self.mode = mode
        self._evidence = evidence or EvidenceChain(
            evidence_base_path=worm_base_path)
        self._gap = GapAnalysisEngine(evidence=self._evidence)
        self.sec = SecLoader()

    # ------------------------------------------------------------------
    # Gap analysis
    # ------------------------------------------------------------------
    def run_gap_analysis(self, corpus: List[FinancialRecord],
                         gap_queries: List[str],
                         context: Optional[FinancialMetadata] = None,
                         filter_by: Optional[MetadataFilter] = None,
                         k: int = 10) -> GapResult:
        """Run gap analysis with soundness guarantee and metadata filters."""
        return self._gap.run_gap_analysis(
            records=corpus, gap_queries=gap_queries,
            context=context, filter_by=filter_by, k=k)

    def gap_proof_report(self, result: GapResult) -> Dict[str, Any]:
        return self._gap.build_proof_report(result)

    # ------------------------------------------------------------------
    # SEC loading helpers
    # ------------------------------------------------------------------
    def load_sec_filings(self, directory: str, limit: int = 0) -> List[FinancialRecord]:
        """Load SEC 10-K filings into financial records."""
        return self.sec.load_dir(directory, limit=limit)

    # ------------------------------------------------------------------
    # Evidence chain helpers
    # ------------------------------------------------------------------
    def verify_evidence_chain(self) -> Dict[str, Any]:
        return self._evidence.verify_chain()

    def evidence_events(self, audit_id: str) -> List[Dict[str, Any]]:
        return self._evidence.get_events(audit_id)
