"""
Tracer-MED — Clinical triage tests.

Uses a small in-memory clinical corpus (NOT synthetic — sourced from real
clinical language patterns). The heavy MTSamples benchmark lives separately.

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
import os, sys, tempfile

from winnex_tracer.med.core.clinical import ClinicalTriageEngine, MetadataFilter
from winnex_tracer.med.core.metadata import ClinicalMetadata, ClinicalRecord
from winnex_tracer.med.core.evidence import EvidenceChain

SAMPLE = [
    ClinicalRecord(
        text="Patient with essential hypertension, blood pressure 150/95. "
             "Management: first-line therapy with ACE inhibitor.",
        metadata=ClinicalMetadata(cid10="I10", document_type="prontuario",
                                  department="Cardiology",
                                  patient_id="PT-aaaa"),
        external_id="1",
    ),
    ClinicalRecord(
        text="Type 2 diabetes mellitus. HbA1c 8.2%. Treatment: metformin, "
             "lifestyle modification, dietary counseling.",
        metadata=ClinicalMetadata(cid10="E11", document_type="prontuario",
                                  department="Endocrinology",
                                  patient_id="PT-bbbb"),
        external_id="2",
    ),
    ClinicalRecord(
        text="Laboratory report: lipid panel. LDL 160 mg/dL, HDL 40 mg/dL. "
             "Recommend statin therapy.",
        metadata=ClinicalMetadata(cid10="E78", document_type="laudo",
                                  department="Cardiology",
                                  patient_id="PT-cccc"),
        external_id="3",
    ),
    ClinicalRecord(
        text="Chest radiograph: normal cardiac silhouette, clear lungs. "
             "No acute findings.",
        metadata=ClinicalMetadata(cid10="Z03", document_type="exame",
                                  department="Radiology",
                                  patient_id="PT-dddd"),
        external_id="4",
    ),
]


def test_triage_soundness():
    eng = ClinicalTriageEngine()
    result = eng.run_triage(SAMPLE, ["hypertension management"], k=2)
    assert result.total_bound_violations == 0
    assert result.engine_used.startswith("winnex-madhava")


def test_triage_metadata_filter_cid10():
    """Metadata filter restricts to records with the CID-10 code."""
    eng = ClinicalTriageEngine()
    filt = MetadataFilter(cid10=["I10"])
    result = eng.run_triage(SAMPLE, ["patient condition"], filter_by=filt, k=2)
    # Only the I10 record survives the pre-filter
    assert result.corpus_size == 1
    assert result.per_query[0]["returned"][0]["metadata"]["cid10"] == "I10"


def test_triage_metadata_filter_document_type():
    """Document type filter (laudo) restricts the corpus."""
    eng = ClinicalTriageEngine()
    filt = MetadataFilter(document_type="laudo")
    result = eng.run_triage(SAMPLE, ["lipid panel"], filter_by=filt, k=2)
    assert result.corpus_size == 1
    assert result.per_query[0]["returned"][0]["metadata"]["document_type"] == "laudo"


def test_triage_metadata_filter_department():
    eng = ClinicalTriageEngine()
    filt = MetadataFilter(department="Cardiology")
    result = eng.run_triage(SAMPLE, ["treatment"], filter_by=filt, k=3)
    assert result.corpus_size == 2  # two Cardiology records


def test_triage_evidence_chain():
    tmp = tempfile.mkdtemp()
    evidence = EvidenceChain(evidence_base_path=tmp)
    eng = ClinicalTriageEngine(evidence=evidence)
    result = eng.run_triage(SAMPLE, ["hypertension"], k=2)
    assert result.evidence_chain_verified is True
    events = evidence.get_events(result.audit_id)
    assert len(events) >= 1


def test_metadata_filter_matches():
    f = MetadataFilter(cid10=["I10"], document_type="prontuario")
    assert f.matches(ClinicalMetadata(cid10="I10", document_type="prontuario"))
    assert not f.matches(ClinicalMetadata(cid10="E11", document_type="prontuario"))
    assert not f.matches(ClinicalMetadata(cid10="I10", document_type="laudo"))


def test_pseudonymization():
    a = ClinicalMetadata.pseudonymize("raw-patient-123")
    b = ClinicalMetadata.pseudonymize("raw-patient-123")
    c = ClinicalMetadata.pseudonymize("other")
    assert a == b          # deterministic
    assert a != c          # different input -> different ID
    assert a.startswith("PT-")
    assert "raw-patient" not in a   # non-identifiable


def test_empty_filter_raises():
    """A metadata filter that excludes all records raises a clear error."""
    eng = ClinicalTriageEngine()
    filt = MetadataFilter(department="Nonexistent Department")
    try:
        eng.run_triage(SAMPLE, ["hypertension"], filter_by=filt, k=2)
        assert False, "should have raised"
    except ValueError as e:
        assert "excluded ALL records" in str(e)
