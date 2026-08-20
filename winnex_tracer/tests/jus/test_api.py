"""
Tracer-JUS — API tests.

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
import os, sys, tempfile

# Path setup is handled by tests/conftest.py. Do NOT insert paths here.

import pytest
from fastapi.testclient import TestClient

from winnex_tracer.jus.api.server import app

CORPUS = [
    "The parties agree that the seller shall indemnify the buyer against all third party claims.",
    "Force majeure: neither party shall be liable for delays caused by events beyond reasonable control.",
    "Governing law shall be the laws of the State of Sao Paulo, Brazil.",
    "The confidentiality clause survives the termination of this agreement.",
]

PAYLOAD = {
    "corpus": CORPUS,
    "review_queries": ["indemnification obligations", "force majeure"],
    "case": {"docket_number": "2026.01.00001-1", "court": "1a Vara Civel",
             "action_type": "breach_of_contract", "purpose": "e-discovery"},
    "k": 2,
}


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("TRACER_JUS_EVIDENCE_PATH", tempfile.mkdtemp())
    # Reset engine cache
    import winnex_tracer.jus.api.server as s
    s._engine = None
    return TestClient(app)


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    # Security headers
    assert r.headers.get("x-content-type-options") == "nosniff"
    assert r.headers.get("x-frame-options") == "DENY"


def test_readiness(client):
    r = client.get("/v1/health/readiness")
    assert r.status_code == 200
    assert r.json()["status"] == "ready"


def test_discovery_run(client):
    r = client.post("/v1/discovery/run", json=PAYLOAD)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total_bound_violations"] == 0
    assert body["evidence_chain_verified"] is True
    assert body["audit_id"] != ""


def test_discovery_proof(client):
    r = client.post("/v1/discovery/run", json=PAYLOAD)
    aid = r.json()["audit_id"]
    r = client.get(f"/v1/discovery/{aid}/proof")
    assert r.status_code == 200
    assert r.json()["soundness"]["sound"] is True


def test_discovery_report(client):
    r = client.post("/v1/discovery/run", json=PAYLOAD)
    aid = r.json()["audit_id"]
    r = client.get(f"/v1/discovery/{aid}/report")
    assert r.status_code == 200
    assert r.json()["report_type"] == "TRACER_JUS_LEGAL_COMPLIANCE"


def test_discovery_evidence(client):
    r = client.post("/v1/discovery/run", json=PAYLOAD)
    aid = r.json()["audit_id"]
    r = client.get(f"/v1/discovery/{aid}/evidence")
    assert r.status_code == 200
    assert len(r.json()["events"]) >= 1


def test_discovery_missing_404(client):
    r = client.get("/v1/discovery/nonexistent/proof")
    assert r.status_code == 404


def test_discovery_empty_422(client):
    r = client.post("/v1/discovery/run", json={"corpus": [], "review_queries": ["q"]})
    assert r.status_code == 422


def test_audit_log_requires_api_key(client, monkeypatch):
    """Sensitive endpoints require an API key when configured."""
    monkeypatch.setenv("WINNEX_TRACER_API_KEY", "test-key")
    r = client.get("/v1/discovery/some/proof")  # wrong key -> 401
    assert r.status_code == 401
