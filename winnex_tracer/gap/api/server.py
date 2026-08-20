"""
Tracer-GAP — FastAPI Server
============================
REST API for financial gap identification with mathematical proof.

Endpoints:
  POST /v1/gaps/run            — gap analysis with proof + filters
  GET  /v1/gaps/{id}           — gap evidence events
  GET  /v1/gaps/{id}/proof     — mathematical proof report
  GET  /v1/gaps/{id}/report    — financial compliance report
  GET  /v1/gaps/{id}/evidence  — evidence chain (custody)
  POST /v1/sec/load            — load SEC 10-K filings into the corpus

  GET  /health                 — liveness
  GET  /v1/health/readiness    — readiness (engine, evidence, SEC loader)

Security (inherited from Tracer-GOV): API key, security headers.

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
import os, sys, logging, time, hmac
from typing import Dict, Any, List
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
import uvicorn

# Path setup: Tracer-GAP first (its own `core`), then Tracer-GOV
# (provides `persistence`/`compliance`).
_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_TRACER_GOV = os.environ.get("TRACER_GOV_PATH",
                             os.path.abspath(os.path.join(_REPO, "..", "tracer-gov")))
for _p in (_TRACER_GOV, _REPO):
    if os.path.isdir(_p) and _p not in sys.path:
        sys.path.insert(0, _p)

logger = logging.getLogger("tracer-gap.api")

from winnex_tracer.gap.core import GapEngine, FinancialMetadata, FinancialRecord
from winnex_tracer.gap.core.gap_analysis import MetadataFilter

app = FastAPI(
    title="Tracer-GAP API",
    version="0.1.0",
    description="Financial gap identification with mathematical proof.",
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
    if os.environ.get("TRACER_GAP_HSTS", "1") == "1":
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


def _get_engine() -> GapEngine:
    global _engine
    if _engine is None:
        _engine = GapEngine(jurisdiction="global", mode="public")
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------
class FinancialRecordIn(BaseModel):
    text: str
    metadata: Dict[str, Any] = {}
    external_id: str = ""


class GapRequest(BaseModel):
    corpus: List[FinancialRecordIn]
    gap_queries: List[str]
    context: Dict[str, Any] = {}
    filter: Dict[str, Any] = {}
    k: int = 10


class SecLoadRequest(BaseModel):
    directory: str
    limit: int = 0


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.get("/")
def root():
    return {
        "service": "Tracer-GAP — Financial Gap Identification with Proof",
        "version": "0.1.0",
        "endpoints": [
            "POST /v1/gaps/run",
            "GET  /v1/gaps/{id}/proof",
            "GET  /v1/gaps/{id}/report",
            "GET  /v1/gaps/{id}/evidence",
            "POST /v1/sec/load",
        ],
        "contact": "licensing@winnex.ai",
    }


@app.get("/health")
def health():
    return {"status": "ok", "service": "tracer-gap", "version": "0.1.0"}


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


@app.post("/v1/gaps/run")
def gaps_run(request: Request, req: GapRequest):
    """Run financial gap analysis with soundness guarantee and filters."""
    _require_optional_api_key(request)
    engine = _get_engine()
    if not req.corpus or not req.gap_queries:
        raise HTTPException(422, "corpus and gap_queries must be non-empty")

    records = [
        FinancialRecord(
            text=r.text,
            metadata=FinancialMetadata.from_dict(r.metadata) if r.metadata
            else FinancialMetadata(),
            external_id=r.external_id,
        )
        for r in req.corpus
    ]
    context = FinancialMetadata.from_dict(req.context) if req.context else None
    filt = MetadataFilter(**req.filter) if req.filter else None

    try:
        result = engine.run_gap_analysis(
            corpus=records,
            gap_queries=req.gap_queries,
            context=context,
            filter_by=filt,
            k=req.k,
        )
    except Exception as e:
        raise HTTPException(500, f"Gap analysis failed: {e}")
    return result.to_dict()


@app.get("/v1/gaps/{audit_id}")
def gaps_get(request: Request, audit_id: str):
    _require_optional_api_key(request)
    events = _get_engine().evidence_events(audit_id)
    if not events:
        raise HTTPException(404, f"Gap analysis {audit_id} not found")
    return {"audit_id": audit_id, "events": events}


@app.get("/v1/gaps/{audit_id}/proof")
def gaps_proof(request: Request, audit_id: str):
    _require_optional_api_key(request)
    engine = _get_engine()
    events = engine.evidence_events(audit_id)
    if not events:
        raise HTTPException(404, f"Gap analysis {audit_id} not found")
    event = events[0]
    sound = event.get("bound_violations", 0) == 0
    return {
        "report_type": "GAP_ANALYSIS_PROOF",
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
        "disclaimer": "Proof of exclusion, not of relevance or investment advice.",
    }


@app.get("/v1/gaps/{audit_id}/report")
def gaps_report(request: Request, audit_id: str):
    _require_optional_api_key(request)
    engine = _get_engine()
    events = engine.evidence_events(audit_id)
    if not events:
        raise HTTPException(404, f"Gap analysis {audit_id} not found")
    from winnex_tracer.gap.compliance import FinancialComplianceReport
    event = events[0]
    sound = event.get("bound_violations", 0) == 0
    report = FinancialComplianceReport.generate({
        "corpus_size": event.get("corpus_size", 0),
        "num_queries": len(event.get("queries", [])),
        "k": 10,
        "engine_used": "winnex-madhava",
        "filter_applied": event.get("filter_applied", {}),
        "soundness": {
            "bound_violations": event.get("bound_violations", 0),
            "bound_pairs": event.get("bound_pairs", 0),
            "sound": sound,
            "statement": ("No excluded document could be in the relevant top-K."
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


@app.get("/v1/gaps/{audit_id}/evidence")
def gaps_evidence(request: Request, audit_id: str):
    _require_optional_api_key(request)
    engine = _get_engine()
    events = engine.evidence_events(audit_id)
    if not events:
        raise HTTPException(404, f"Gap analysis {audit_id} not found")
    return {
        "audit_id": audit_id,
        "chain_verified": engine.verify_evidence_chain().get(
            "chain_integrity_verified", False),
        "events": events,
    }


@app.post("/v1/sec/load")
def sec_load(request: Request, req: SecLoadRequest):
    """Load SEC 10-K filings from a directory (for gap analysis corpus)."""
    _require_optional_api_key(request)
    engine = _get_engine()
    if not os.path.isdir(req.directory):
        raise HTTPException(422, f"directory {req.directory} not found")
    records = engine.load_sec_filings(req.directory, limit=req.limit)
    return {"loaded": len(records),
            "records": [r.to_dict() for r in records[:10]]}


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8470))
    uvicorn.run("api.server:app", host="0.0.0.0", port=port)
