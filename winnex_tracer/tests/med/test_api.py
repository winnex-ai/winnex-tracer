"""
Tracer-MED — API tests.

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
import os, sys, tempfile

from winnex_tracer.tests.conftest import requires_engine
import pytest
from fastapi.testclient import TestClient

from winnex_tracer.med.api.server import app

CORPUS = [
    {"text": "Patient with essential hypertension, blood pressure 150/95. "
             "Management: first-line therapy with ACE inhibitor.",
     "metadata": {"cid10": "I10", "document_type": "prontuario",
                  "department": "Cardiology", "patient_id": "PT-aaaa"},
     "external_id": "1"},
    {"text": "Type 2 diabetes mellitus. HbA1c 8.2%. Treatment: metformin.",
     "metadata": {"cid10": "E11", "document_type": "prontuario",
                  "department": "Endocrinology", "patient_id": "PT-bbbb"},
     "external_id": "2"},
]

PAYLOAD = {
    "corpus": CORPUS,
    "clinical_queries": ["hypertension management"],
    "context": {"department": "Cardiology", "purpose": "clinical_triage"},
    "k": 2,
}


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("TRACER_MED_EVIDENCE_PATH", tempfile.mkdtemp())
    import winnex_tracer.med.api.server as s
    s._engine = None
    return TestClient(app)


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.headers.get("x-content-type-options") == "nosniff"


@requires_engine
def test_triage_run(client):
    r = client.post("/v1/triage/run", json=PAYLOAD)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total_bound_violations"] == 0
    assert body["audit_id"] != ""


@requires_engine
def test_triage_proof(client):
    r = client.post("/v1/triage/run", json=PAYLOAD)
    aid = r.json()["audit_id"]
    r = client.get(f"/v1/triage/{aid}/proof")
    assert r.status_code == 200
    assert r.json()["soundness"]["sound"] is True


@requires_engine
def test_triage_report(client):
    r = client.post("/v1/triage/run", json=PAYLOAD)
    aid = r.json()["audit_id"]
    r = client.get(f"/v1/triage/{aid}/report")
    assert r.status_code == 200
    assert r.json()["report_type"] == "TRACER_MED_HEALTH_COMPLIANCE"
    assert "LGPD" in r.json()["compliance_mapping"]
    assert "HIPAA" in r.json()["compliance_mapping"]


@requires_engine
def test_triage_evidence(client):
    r = client.post("/v1/triage/run", json=PAYLOAD)
    aid = r.json()["audit_id"]
    r = client.get(f"/v1/triage/{aid}/evidence")
    assert r.status_code == 200
    assert len(r.json()["events"]) >= 1


def test_triage_missing_404(client):
    r = client.get("/v1/triage/nonexistent/proof")
    assert r.status_code == 404


def test_triage_empty_422(client):
    r = client.post("/v1/triage/run",
                    json={"corpus": [], "clinical_queries": ["q"]})
    assert r.status_code == 422


def test_fhir_ingest(client):
    resource = {
        "resourceType": "Condition",
        "id": "cond-1",
        "code": {"coding": [{"system": "http://hl7.org/fhir/sid/icd-10",
                             "code": "I10",
                             "display": "Essential hypertension"}]},
        "subject": {"reference": "Patient/12345"},
        "text": {"div": "<div>Patient with essential hypertension.</div>"},
    }
    r = client.post("/v1/fhir/ingest", json={"resources": [resource]})
    assert r.status_code == 200
    assert r.json()["ingested"] == 1
    rec = r.json()["records"][0]
    assert rec["metadata"]["cid10"] == "I10"
    assert rec["metadata"]["patient_id"].startswith("PT-")


def test_security_header(client):
    r = client.get("/health")
    assert r.headers.get("x-frame-options") == "DENY"
