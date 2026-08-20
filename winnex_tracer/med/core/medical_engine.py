"""
Tracer-MED — Medical Engine
============================
Orchestrates clinical triage, integrating:

  - the Madhava engine (`winnex-madhava`, pip) for soundness-guaranteed
    vector search,
  - a biomedical embedding model (BlueBERT) for medical language,
  - structured metadata filtering (CID-10, document type, date, patient),
  - HL7 FHIR interoperability,
  - the Tracer-GOV audit framework (WORM, signatures, audit log),
  - Tracer-MED clinical metadata and evidence chain.

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
import os, logging
from typing import Dict, Any, Optional, List

from winnex_tracer.med.core.metadata import ClinicalMetadata, ClinicalRecord
from winnex_tracer.med.core.clinical import ClinicalTriageEngine, TriageResult, MetadataFilter
from winnex_tracer.med.core.evidence import EvidenceChain
from winnex_tracer.med.core.fhir import FhirResourceMapper

logger = logging.getLogger("tracer-med")


class MedicalEngine:
    """Clinical triage engine with mathematical proof.

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
        self._triage = ClinicalTriageEngine(evidence=self._evidence)
        self.fhir = FhirResourceMapper()

    # ------------------------------------------------------------------
    # Clinical triage
    # ------------------------------------------------------------------
    def run_triage(self, corpus: List[ClinicalRecord],
                   clinical_queries: List[str],
                   context: Optional[ClinicalMetadata] = None,
                   filter_by: Optional[MetadataFilter] = None,
                   k: int = 10) -> TriageResult:
        """Run clinical triage with soundness guarantee and metadata filters."""
        return self._triage.run_triage(
            records=corpus, clinical_queries=clinical_queries,
            context=context, filter_by=filter_by, k=k)

    def triage_proof_report(self, result: TriageResult) -> Dict[str, Any]:
        return self._triage.build_proof_report(result)

    # ------------------------------------------------------------------
    # FHIR helpers
    # ------------------------------------------------------------------
    def ingest_fhir_resources(self, resources: List[Dict[str, Any]]) -> List[ClinicalRecord]:
        """Map FHIR resources to clinical records for triage."""
        records = []
        for r in resources:
            rec = self.fhir.map_resource(r)
            if rec is not None:
                records.append(rec)
        return records

    def to_fhir_bundle(self, records: List[ClinicalRecord]) -> Dict[str, Any]:
        return self.fhir.build_bundle(records)

    # ------------------------------------------------------------------
    # Evidence chain helpers
    # ------------------------------------------------------------------
    def verify_evidence_chain(self) -> Dict[str, Any]:
        return self._evidence.verify_chain()

    def evidence_events(self, audit_id: str) -> List[Dict[str, Any]]:
        return self._evidence.get_events(audit_id)
