"""
Tracer-JUS — e-Discovery engine tests.

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
import os, sys, tempfile

# Path setup is handled by tests/conftest.py (Tracer-JUS core first,
# Tracer-GOV provides persistence/compliance). Do NOT insert paths here —
# it would override the conftest order and break `core.discovery`.

from winnex_tracer.tests.conftest import requires_engine
from winnex_tracer.jus.core.discovery import DiscoveryEngine, DiscoveryResult, ExclusionProof
from winnex_tracer.jus.core.metadata import CaseMetadata
from winnex_tracer.jus.core.evidence import EvidenceChain

SAMPLE_CORPUS = [
    "The parties agree that the seller shall indemnify the buyer against all third party claims arising from defects.",
    "Force majeure: neither party shall be liable for delays caused by events beyond reasonable control.",
    "Governing law shall be the laws of the State of Sao Paulo, Brazil.",
    "The confidentiality clause survives the termination of this agreement.",
    "Either party may terminate this agreement with 30 days written notice.",
    "Payment terms: net 30 days from invoice date.",
    "Dispute resolution: disputes shall be resolved by arbitration.",
    "The buyer shall have the right to inspect the goods before acceptance.",
]


@requires_engine
def test_discovery_soundness():
    """e-Discovery with the real Madhava engine is SOUND (0 violations)."""
    eng = DiscoveryEngine()
    result = eng.run_discovery(
        corpus=SAMPLE_CORPUS,
        review_queries=["indemnification obligations", "force majeure"],
        k=3,
    )
    assert result.total_bound_violations == 0
    assert result.engine_used.startswith("winnex-madhava")
    assert result.total_bound_pairs > 0


@requires_engine
def test_discovery_case_metadata():
    """Case metadata flows into the result and evidence."""
    eng = DiscoveryEngine()
    case = CaseMetadata(docket_number="2026.01.00001-1",
                        court="1a Vara Civel",
                        action_type="breach_of_contract")
    result = eng.run_discovery(SAMPLE_CORPUS, ["indemnity"], case=case, k=2)
    assert result.case["docket_number"] == "2026.01.00001-1"
    assert result.case["court"] == "1a Vara Civel"


@requires_engine
def test_discovery_evidence_chain():
    """Discovery writes to the evidence chain (WORM) and it verifies."""
    tmp = tempfile.mkdtemp()
    evidence = EvidenceChain(evidence_base_path=tmp)
    eng = DiscoveryEngine(evidence=evidence)
    result = eng.run_discovery(SAMPLE_CORPUS, ["force majeure"], k=2)
    assert result.evidence_chain_verified is True
    assert result.evidence_receipt.get("worm_hash", "") != ""
    # The event is retrievable
    events = evidence.get_events(result.audit_id)
    assert len(events) >= 1


def test_discovery_requires_nonempty():
    """Empty corpus or queries are rejected."""
    eng = DiscoveryEngine()
    try:
        eng.run_discovery([], ["q"])
        assert False, "empty corpus should fail"
    except ValueError:
        pass
    try:
        eng.run_discovery(SAMPLE_CORPUS, [])
        assert False, "empty queries should fail"
    except ValueError:
        pass


@requires_engine
def test_proof_report():
    """The proof report documents soundness and evidence."""
    eng = DiscoveryEngine()
    result = eng.run_discovery(SAMPLE_CORPUS, ["indemnity"], k=2)
    report = eng.build_proof_report(result)
    assert report["report_type"] == "E_DISCOVERY_PROOF"
    assert report["soundness"]["sound"] is True
    assert report["soundness"]["bound_violations"] == 0
    assert "Cauchy-Schwarz" in report["soundness"]["statement"]


def test_exclusion_proof_to_dict():
    p = ExclusionProof(doc_id=1, bound_violations=0, bound_pairs=10,
                       k1=5, k2=3, k3=2)
    d = p.to_dict()
    assert d["verdict"] == "SOUND"
    assert d["bound_violations"] == 0
