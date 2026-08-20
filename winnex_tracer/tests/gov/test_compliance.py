"""
Tracer-GOV — Compliance report tests.

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from winnex_tracer.gov.compliance import LgpdReport, LaiReport, MarcoLegalReport, EuAiActReport
from winnex_tracer.gov.reports import TcuReport, CguReport, ControladoriaReport


DUMMY_RECORD = {
    "metadata": {
        "requesting_agency": "TCU",
        "cpf": "000.000.000-00",
        "role": "Auditor",
        "source_database": "SIAFI",
        "sensitivity": "restricted",
        "purpose": "Expenditure audit",
        "timestamp": "2026-07-18T12:00:00+00:00",
    },
    "result": {"indices": [1, 2, 3], "scores": [0.95, 0.90, 0.85]},
    "audit": [{"doc_id": 42, "true_cosine": 0.5, "upper_bound": 0.3,
               "threshold": 0.7, "excluded": True, "stage": "stage1"}],
    "total_excluded": 997,
    "violations_64d": 0,
    "violations_128d": 0,
    "query_hash": "a1b2c3d4e5f6a7b8",
    "signature": "abcd1234",
    "signature_algorithm": "Ed25519",
    "worm_path": "2026/07/18/records.jsonl",
    "worm_hash": "0xdeadbeef",
    "blockchain_tx": "0xcafe1234",
    "total_documents": 1000,
}


def test_lgpd_report():
    r = LgpdReport.generate(DUMMY_RECORD)
    assert "LGPD" in r["report_type"]
    assert "self-assessment" in r["assessment"]["classification"]
    assert len(r["explanations"]) > 0
    text = LgpdReport.to_text(r)
    assert "LGPD" in text


def test_lai_report():
    r = LaiReport.generate(DUMMY_RECORD)
    assert "LAI" in r["report_type"]
    assert "self-assessment" in r["assessment"]["classification"]
    text = LaiReport.to_text(r)
    assert "LAI" in text or "12527" in text


def test_marco_legal_report():
    r = MarcoLegalReport.generate(DUMMY_RECORD)
    assert "MARCO_LEGAL" in r["report_type"]
    assert "not certified" in r["assessment"]


def test_eu_ai_act_report():
    r = EuAiActReport.generate(DUMMY_RECORD)
    assert "EU_AI_ACT" in r["report_type"]
    assert "not a compliance certification" in r["disclaimer"]
    assert "preliminary" in r["overall_mapping"]


def test_tcu_report():
    r = TcuReport.generate(DUMMY_RECORD)
    assert r["report_type"] == "TCU_ACCOUNTABILITY"
    assert "not a regulatory filing" in r["disclaimer"]
    text = TcuReport.to_text(r)
    assert "TCU" in text


def test_cgu_report():
    r = CguReport.generate(DUMMY_RECORD)
    assert r["report_type"] == "CGU_TRANSPARENCY"
    assert "not certified" in r["assessment"]
    text = CguReport.to_text(r)
    assert "CGU" in text


def test_controladoria_report():
    r = ControladoriaReport.generate(DUMMY_RECORD)
    assert r["report_type"] == "CONTROLADORIA_OVERSIGHT"
    assert "not certified" in r["assessment"]
    assert len(r["regulations_mapped"]) == 3


if __name__ == "__main__":
    test_lgpd_report(); print("[OK] test_lgpd_report")
    test_lai_report(); print("[OK] test_lai_report")
    test_marco_legal_report(); print("[OK] test_marco_legal_report")
    test_eu_ai_act_report(); print("[OK] test_eu_ai_act_report")
    test_tcu_report(); print("[OK] test_tcu_report")
    test_cgu_report(); print("[OK] test_cgu_report")
    test_controladoria_report(); print("[OK] test_controladoria_report")
    print("\n[ALL COMPLIANCE TESTS PASSED]")
