"""
Tracer-GOV — API security tests.

Covers the security gaps identified in GOVERNMENT_READINESS_REVIEW:
  GAP 1 — internal mode requires a REAL credential (constant-time).
  GAP 2 — compliance endpoints read the REAL WORM record.
  GAP 5 — audit-log endpoints require an API key.

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
import os, sys, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

import numpy as np
from winnex_tracer.tests.conftest import requires_engine
import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(monkeypatch):
    """API client with WORM + internal credential configured."""
    tmp = tempfile.mkdtemp()
    monkeypatch.setenv("WINNEX_TRACER_WORM_PATH", tmp)
    monkeypatch.setenv("WINNEX_TRACER_AUDIT_LOG_PATH", tmp)
    monkeypatch.setenv("WINNEX_TRACER_INTERNAL_CREDENTIAL", "server-secret")
    monkeypatch.setenv("WORM_SIGNING_PRIVATE_KEY_HEX", "00" * 32)
    # Fresh engine cache per test
    from winnex_tracer.gov.api import server
    server.reset_engines()
    return TestClient(server.app)


def _build_and_search(client, mode="public", credential="", vectors=None):
    """Helper: build an index and run a search; returns the response."""
    rng = np.random.RandomState(42)
    if vectors is None:
        vectors = rng.randn(200, 64).astype(np.float32)
        vectors /= np.linalg.norm(vectors, axis=1, keepdims=True)
    rb = client.post("/v1/tracer/build", json={
        "vectors": vectors.tolist(), "jurisdiction": "br-gv", "mode": mode,
        "internal_credential": credential,
    })
    assert rb.status_code == 200, rb.text
    rs = client.post("/v1/tracer/search", json={
        "query": vectors[0].tolist(),
        "requesting_agency": "TCU", "cpf": "000.000.000-00",
        "role": "Auditor", "source_database": "SIAFI",
        "sensitivity": "public", "purpose": "test",
        "jurisdiction": "br-gv", "mode": mode, "k": 5,
        "internal_credential": credential,
    })
    return rs


def test_internal_mode_wrong_credential_401(client):
    """GAP 1: internal mode with a wrong credential is rejected (401)."""
    rng = np.random.RandomState(42)
    v = rng.randn(100, 64).astype(np.float32)
    v /= np.linalg.norm(v, axis=1, keepdims=True)
    client.post("/v1/tracer/build", json={
        "vectors": v.tolist(), "jurisdiction": "br-gv", "mode": "internal",
        "internal_credential": "wrong-secret",
    })
    r = client.post("/v1/tracer/search", json={
        "query": v[0].tolist(),
        "requesting_agency": "TCU", "cpf": "000", "role": "Auditor",
        "source_database": "SIAFI", "sensitivity": "public", "purpose": "t",
        "jurisdiction": "br-gv", "mode": "internal", "k": 5,
        "internal_credential": "wrong-secret",
    })
    assert r.status_code == 401, r.text


@requires_engine
def test_internal_mode_correct_credential_ok(client):
    """GAP 1: internal mode with the CORRECT credential succeeds."""
    r = _build_and_search(client, mode="internal", credential="server-secret")
    assert r.status_code == 200, r.text
    assert r.json()["mode"] == "internal"


def test_internal_mode_missing_server_config_503(client, monkeypatch):
    """GAP 1: if the server has no credential set, internal mode is 503."""
    monkeypatch.delenv("WINNEX_TRACER_INTERNAL_CREDENTIAL")
    rng = np.random.RandomState(42)
    v = rng.randn(50, 64).astype(np.float32)
    v /= np.linalg.norm(v, axis=1, keepdims=True)
    r = client.post("/v1/tracer/build", json={
        "vectors": v.tolist(), "jurisdiction": "br-gv", "mode": "internal",
        "internal_credential": "anything",
    })
    assert r.status_code == 503, r.text


@requires_engine
def test_compliance_endpoint_reads_real_record(client):
    """GAP 2: compliance endpoints use the REAL WORM record."""
    rng = np.random.RandomState(42)
    v = rng.randn(200, 64).astype(np.float32)
    v /= np.linalg.norm(v, axis=1, keepdims=True)
    rs = _build_and_search(client, vectors=v)
    assert rs.status_code == 200, rs.text
    audit_id = rs.json()["audit_id"]

    # TCU report must reflect the real audit (violations field present).
    r = client.get(f"/v1/compliance/tcu/{audit_id}")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["report_type"] == "TCU_ACCOUNTABILITY"
    assert "bound_violations" in body["mathematical_proof"]

    # LGPD report must be non-empty (real explanations).
    r = client.get(f"/v1/compliance/lgpd/{audit_id}")
    assert r.status_code == 200, r.text
    body = r.json()
    assert "automated_decision" in body


def test_compliance_endpoint_missing_audit_404(client):
    """GAP 2: unknown audit_id returns 404 (not a dummy report)."""
    r = client.get("/v1/compliance/tcu/does-not-exist")
    assert r.status_code == 404, r.text


def test_audit_log_requires_api_key(client):
    """GAP 5: audit-log endpoint requires an API key when configured."""
    # No API key configured -> 503 (fail-closed).
    r = client.get("/v1/audit-log/some-audit")
    assert r.status_code == 503, r.text


def test_audit_log_with_valid_api_key(client, monkeypatch):
    """GAP 5: with an API key, the audit-log endpoint works."""
    monkeypatch.setenv("WINNEX_TRACER_API_KEY", "test-api-key")
    # Re-import module to pick up env (functions read env at call time, so
    # the already-imported module is fine).
    r = client.get("/v1/audit-log/some-audit",
                   headers={"X-API-Key": "test-api-key"})
    assert r.status_code == 200, r.text
    assert "accesses" in r.json()


def test_audit_log_wrong_api_key_401(client, monkeypatch):
    """GAP 5: wrong API key is rejected with 401."""
    monkeypatch.setenv("WINNEX_TRACER_API_KEY", "test-api-key")
    r = client.get("/v1/audit-log/some-audit",
                   headers={"X-API-Key": "wrong-key"})
    assert r.status_code == 401, r.text


def test_security_headers_present(client):
    """Security headers are present on responses."""
    r = client.get("/health")
    assert r.headers.get("x-content-type-options") == "nosniff"
    assert r.headers.get("x-frame-options") == "DENY"


def test_pgstore_rejects_invalid_table_name():
    """GAP 4: PgStore rejects table names that could enable SQL injection."""
    from persistence import PgStore
    # Valid
    PgStore(table_name="tracer_gov_audits")
    PgStore(table_name="audits2")
    # Invalid — would break out of the identifier
    for bad in ["audits; DROP TABLE x; --", 'audits" OR 1=1--',
                "AUDITS", "audits-table"]:
        try:
            PgStore(table_name=bad)
            assert False, f"should have rejected {bad!r}"
        except ValueError:
            pass
