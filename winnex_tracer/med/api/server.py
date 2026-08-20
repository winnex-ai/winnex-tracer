"""
Tracer-MED — FastAPI Server
============================
REST API for clinical triage and research with mathematical proof.

Endpoints:
  POST /v1/triage/run            — clinical triage with proof + filters
  GET  /v1/triage/{id}           — triage evidence events
  GET  /v1/triage/{id}/proof     — mathematical proof report
  GET  /v1/triage/{id}/report    — healthcare compliance report
  GET  /v1/triage/{id}/evidence  — evidence chain (custody)
  POST /v1/fhir/ingest           — ingest FHIR resources as clinical records

  GET  /health                   — liveness
  GET  /v1/health/readiness      — readiness (engine, evidence, FHIR)

Security (inherited from Tracer-GOV): API key, security headers.

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
import os, sys, logging, time, hmac
from typing import Dict, Any, List
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
import uvicorn

# Path setup: Tracer-MED first (its own `core`), then Tracer-GOV
# (provides `persistence`/`compliance`).
_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_TRACER_GOV = os.environ.get("TRACER_GOV_PATH",
                             os.path.abspath(os.path.join(_REPO, "..", "tracer-gov")))
for _p in (_TRACER_GOV, _REPO):
    if os.path.isdir(_p) and _p not in sys.path:
        sys.path.insert(0, _p)

logger = logging.getLogger("tracer-med.api")

from winnex_tracer.med.core import MedicalEngine, ClinicalMetadata, ClinicalRecord
from winnex_tracer.med.core.clinical import MetadataFilter

app = FastAPI(
    title="Tracer-MED API",
    version="0.1.0",
    description="Clinical triage and research with mathematical proof.",
    contact={"name": "Winnex AI", "email": "licensing@winnex.ai"},
    license_info={
        "name": "Business Source License 1.1",
        "url": "https://github.com/winnex-ai/tracer-gov",
    },
)


# ---------------------------------------------------------------------------
# Security middleware
# ---------------------------------------------------------------------------
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    )
    if os.environ.get("TRACER_MED_HSTS", "1") == "1":
        response.headers.setdefault(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains; preload",
        )
    return response


def _constant_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def _require_optional_api_key(request: Request):
    expected = os.environ.get("WINNEX_TRACER_API_KEY", "")
    if not expected:
        return
    provided = request.headers.get("X-API-Key", "")
    if not provided or not _constant_time_eq(provided, expected):
        raise HTTPException(401, "Invalid or missing API key.")


_engine = None


def _get_engine() -> MedicalEngine:
    global _engine
    if _engine is None:
        _engine = MedicalEngine(jurisdiction="global", mode="public")
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------
class RecordIn(BaseModel):
    text: str
    metadata: Dict[str, Any] = {}
    external_id: str = ""


class TriageRequest(BaseModel):
    corpus: List[RecordIn]
    clinical_queries: List[str]
    context: Dict[str, Any] = {}
    filter: Dict[str, Any] = {}
    k: int = 10


class FhirIngestRequest(BaseModel):
    resources: List[Dict[str, Any]]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.get("/")
def root():
    return {
        "service": "Tracer-MED — Clinical Triage with Mathematical Proof",
        "version": "0.1.0",
        "endpoints": [
            "POST /v1/triage/run",
            "GET  /v1/triage/{id}/proof",
            "GET  /v1/triage/{id}/report",
            "GET  /v1/triage/{id}/evidence",
            "POST /v1/fhir/ingest",
        ],
        "contact": "licensing@winnex.ai",
    }


@app.get("/health")
def health():
    return {"status": "ok", "service": "tracer-med", "version": "0.1.0"}


@app.get("/v1/health/readiness")
def readiness():
    checks = {}
    try:
        eng = _get_engine()
        checks["engine"] = {"ok": True, "jurisdiction": eng.jurisdiction}
    except Exception as e:
        checks["engine"] = {"ok": False, "error": str(e)}
    try:
        v = _get_engine().verify_evidence_chain()
        checks["evidence_chain"] = {
            "ok": v.get("chain_integrity_verified", False),
            "blocks": v.get("total_blocks", 0),
        }
    except Exception as e:
        checks["evidence_chain"] = {"ok": False, "error": str(e)}
    all_ok = all(c.get("ok") for c in checks.values())
    return {"status": "ready" if all_ok else "degraded", "checks": checks}


@app.post("/v1/triage/run")
def triage_run(request: Request, req: TriageRequest):
    """Run clinical triage with soundness guarantee and metadata filters."""
    _require_optional_api_key(request)
    engine = _get_engine()
    if not req.corpus or not req.clinical_queries:
        raise HTTPException(422, "corpus and clinical_queries must be non-empty")

    records = [
        ClinicalRecord(
            text=r.text,
            metadata=ClinicalMetadata.from_dict(r.metadata) if r.metadata
            else ClinicalMetadata(),
            external_id=r.external_id,
        )
        for r in req.corpus
    ]
    context = ClinicalMetadata.from_dict(req.context) if req.context else None
    filt = MetadataFilter(**req.filter) if req.filter else None

    try:
        result = engine.run_triage(
            corpus=records,
            clinical_queries=req.clinical_queries,
            context=context,
            filter_by=filt,
            k=req.k,
        )
    except Exception as e:
        raise HTTPException(500, f"Triage failed: {e}")
    return result.to_dict()


@app.get("/v1/triage/{audit_id}")
def triage_get(request: Request, audit_id: str):
    _require_optional_api_key(request)
    events = _get_engine().evidence_events(audit_id)
    if not events:
        raise HTTPException(404, f"Triage {audit_id} not found")
    return {"audit_id": audit_id, "events": events}


@app.get("/v1/triage/{audit_id}/proof")
def triage_proof(request: Request, audit_id: str):
    _require_optional_api_key(request)
    engine = _get_engine()
    events = engine.evidence_events(audit_id)
    if not events:
        raise HTTPException(404, f"Triage {audit_id} not found")
    event = events[0]
    sound = event.get("bound_violations", 0) == 0
    return {
        "report_type": "CLINICAL_TRIAGE_PROOF",
        "audit_id": audit_id,
        "soundness": {
            "bound_violations": event.get("bound_violations", 0),
            "bound_pairs": event.get("bound_pairs", 0),
            "sound": sound,
        },
        "evidence_chain": {
            "verified": engine.verify_evidence_chain().get(
                "chain_integrity_verified", False),
            "block_hash": event.get("block_hash", ""),
        },
        "disclaimer": "Proof of exclusion, not of relevance or diagnosis.",
    }


@app.get("/v1/triage/{audit_id}/report")
def triage_report(request: Request, audit_id: str):
    _require_optional_api_key(request)
    engine = _get_engine()
    events = engine.evidence_events(audit_id)
    if not events:
        raise HTTPException(404, f"Triage {audit_id} not found")
    from winnex_tracer.med.compliance import MedicalComplianceReport
    event = events[0]
    sound = event.get("bound_violations", 0) == 0
    report = MedicalComplianceReport.generate({
        "corpus_size": event.get("corpus_size", 0),
        "num_queries": len(event.get("queries", [])),
        "k": 10,
        "engine_used": event.get("engine", "winnex-madhava"),
        "filter_applied": event.get("filter_applied", {}),
        "soundness": {
            "bound_violations": event.get("bound_violations", 0),
            "bound_pairs": event.get("bound_pairs", 0),
            "sound": sound,
            "statement": ("No excluded record could be in the relevant top-K."
                          if sound else "BOUND VIOLATION"),
        },
        "evidence_chain": {
            "verified": engine.verify_evidence_chain().get(
                "chain_integrity_verified", False),
            "receipt": {"worm_hash": event.get("block_hash", "")},
        },
        "context": event.get("context", {}),
    })
    return report


@app.get("/v1/triage/{audit_id}/evidence")
def triage_evidence(request: Request, audit_id: str):
    _require_optional_api_key(request)
    engine = _get_engine()
    events = engine.evidence_events(audit_id)
    if not events:
        raise HTTPException(404, f"Triage {audit_id} not found")
    return {
        "audit_id": audit_id,
        "chain_verified": engine.verify_evidence_chain().get(
            "chain_integrity_verified", False),
        "events": events,
    }


@app.post("/v1/fhir/ingest")
def fhir_ingest(request: Request, req: FhirIngestRequest):
    """Ingest FHIR resources as clinical records (for triage)."""
    _require_optional_api_key(request)
    engine = _get_engine()
    records = engine.ingest_fhir_resources(req.resources)
    return {"ingested": len(records), "records": [r.to_dict() for r in records]}


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8460))
    uvicorn.run("api.server:app", host="0.0.0.0", port=port)
