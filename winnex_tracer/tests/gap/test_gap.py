"""
Tracer-GAP — Gap analysis engine tests.

Uses in-memory financial document snippets (real financial language) for
fast tests; the SEC 10-K benchmark lives separately.

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
import os, sys, tempfile

from winnex_tracer.gap.core.gap_analysis import GapAnalysisEngine, MetadataFilter
from winnex_tracer.gap.core.metadata import FinancialMetadata, FinancialRecord
from winnex_tracer.gap.core.evidence import EvidenceChain

SAMPLE = [
    FinancialRecord(
        text="Risk factor: the company has significant exposure to interest "
             "rate fluctuations that are not hedged.",
        metadata=FinancialMetadata(sector="Finance", instrument_type="10-K",
                                   company="Acme Bank", period="FY2021",
                                   risk_category="market_risk"),
        external_id="1",
    ),
    FinancialRecord(
        text="MD&A: the company's liquidity position remains strong, with "
             "access to committed credit facilities.",
        metadata=FinancialMetadata(sector="Finance", instrument_type="10-K",
                                   company="Acme Bank", period="FY2021",
                                   risk_category="liquidity"),
        external_id="2",
    ),
    FinancialRecord(
        text="Risk factor: currency translation exposure from operations in "
             "emerging markets may affect results.",
        metadata=FinancialMetadata(sector="Manufacturing", instrument_type="10-K",
                                   company="Global Corp", period="FY2020",
                                   risk_category="currency"),
        external_id="3",
    ),
    FinancialRecord(
        text="Insurance policy: coverage for cyber incidents, data breaches, "
             "and business interruption.",
        metadata=FinancialMetadata(sector="Insurance", instrument_type="policy",
                                   company="InsureCo", period="FY2022",
                                   risk_category="cyber"),
        external_id="4",
    ),
]


def test_gap_analysis_soundness():
    eng = GapAnalysisEngine()
    result = eng.run_gap_analysis(SAMPLE, ["unhedged interest rate exposure"], k=2)
    assert result.total_bound_violations == 0
    assert result.engine_used.startswith("winnex-madhava")


def test_gap_metadata_filter_sector():
    """Filter by sector restricts the corpus."""
    eng = GapAnalysisEngine()
    filt = MetadataFilter(sector="Finance")
    result = eng.run_gap_analysis(SAMPLE, ["exposure"], filter_by=filt, k=2)
    assert result.corpus_size == 2  # two Finance records
    for r in result.per_query[0]["returned"]:
        assert r["sector"] == "Finance"


def test_gap_metadata_filter_period():
    eng = GapAnalysisEngine()
    filt = MetadataFilter(period="FY2021")
    result = eng.run_gap_analysis(SAMPLE, ["risk"], filter_by=filt, k=2)
    assert result.corpus_size == 2


def test_gap_metadata_filter_risk_category():
    eng = GapAnalysisEngine()
    filt = MetadataFilter(risk_category="cyber")
    result = eng.run_gap_analysis(SAMPLE, ["coverage"], filter_by=filt, k=2)
    assert result.corpus_size == 1
    assert result.per_query[0]["returned"][0]["sector"] == "Insurance"


def test_gap_evidence_chain():
    tmp = tempfile.mkdtemp()
    evidence = EvidenceChain(evidence_base_path=tmp)
    eng = GapAnalysisEngine(evidence=evidence)
    result = eng.run_gap_analysis(SAMPLE, ["interest rate"], k=2)
    assert result.evidence_chain_verified is True
    events = evidence.get_events(result.audit_id)
    assert len(events) >= 1


def test_empty_filter_raises():
    eng = GapAnalysisEngine()
    filt = MetadataFilter(sector="Nonexistent")
    try:
        eng.run_gap_analysis(SAMPLE, ["risk"], filter_by=filt, k=2)
        assert False, "should have raised"
    except ValueError as e:
        assert "excluded ALL records" in str(e)


def test_metadata_filter_matches():
    f = MetadataFilter(sector="Finance", instrument_type="10-K")
    assert f.matches(FinancialMetadata(sector="Finance", instrument_type="10-K"))
    assert not f.matches(FinancialMetadata(sector="Insurance", instrument_type="10-K"))
    assert not f.matches(FinancialMetadata(sector="Finance", instrument_type="policy"))
