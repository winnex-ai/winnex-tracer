"""
Tracer-GAP — API tests.

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
import os, sys, tempfile

import pytest
from fastapi.testclient import TestClient

from winnex_tracer.gap.api.server import app

CORPUS = [
    {"text": "Risk factor: the company has significant exposure to interest "
             "rate fluctuations that are not hedged.",
     "metadata": {"sector": "Finance", "instrument_type": "10-K",
                  "company": "Acme Bank", "period": "FY2021",
                  "risk_category": "market_risk"},
     "external_id": "1"},
    {"text": "MD&A: the company's liquidity position remains strong.",
     "metadata": {"sector": "Finance", "instrument_type": "10-K",
                  "company": "Acme Bank", "period": "FY2021",
                  "risk_category": "liquidity"},
     "external_id": "2"},
]

PAYLOAD = {
    "corpus": CORPUS,
    "gap_queries": ["unhedged interest rate exposure"],
    "context": {"sector": "Finance", "instrument_type": "10-K", "period": "FY2021"},
    "k": 2,
}


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("TRACER_GAP_EVIDENCE_PATH", tempfile.mkdtemp())
    import winnex_tracer.gap.api.server as s
    s._engine = None
    return TestClient(app)


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.headers.get("x-content-type-options") == "nosniff"


def test_gaps_run(client):
    r = client.post("/v1/gaps/run", json=PAYLOAD)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total_bound_violations"] == 0
    assert body["audit_id"] != ""


def test_gaps_proof(client):
    r = client.post("/v1/gaps/run", json=PAYLOAD)
    aid = r.json()["audit_id"]
    r = client.get(f"/v1/gaps/{aid}/proof")
    assert r.status_code == 200
    assert r.json()["soundness"]["sound"] is True


def test_gaps_report(client):
    r = client.post("/v1/gaps/run", json=PAYLOAD)
    aid = r.json()["audit_id"]
    r = client.get(f"/v1/gaps/{aid}/report")
    assert r.status_code == 200
    body = r.json()
    assert body["report_type"] == "TRACER_GAP_FINANCIAL_COMPLIANCE"
    assert "SOX" in body["regulatory_mapping"]
    assert "SEC" in body["regulatory_mapping"]


def test_gaps_evidence(client):
    r = client.post("/v1/gaps/run", json=PAYLOAD)
    aid = r.json()["audit_id"]
    r = client.get(f"/v1/gaps/{aid}/evidence")
    assert r.status_code == 200
    assert len(r.json()["events"]) >= 1


def test_gaps_missing_404(client):
    r = client.get("/v1/gaps/nonexistent/proof")
    assert r.status_code == 404


def test_gaps_empty_422(client):
    r = client.post("/v1/gaps/run", json={"corpus": [], "gap_queries": ["q"]})
    assert r.status_code == 422


def test_sec_load_invalid_dir(client):
    r = client.post("/v1/sec/load", json={"directory": "/nonexistent"})
    assert r.status_code == 422


def test_security_header(client):
    r = client.get("/health")
    assert r.headers.get("x-frame-options") == "DENY"
