"""
Tracer-JUS — FastAPI Server
============================
REST API for legal e-Discovery and research with mathematical proof.

Endpoints:
  POST /v1/discovery/run           — run e-Discovery triage with proof
  GET  /v1/discovery/{id}          — discovery evidence events
  GET  /v1/discovery/{id}/proof    — mathematical proof report
  GET  /v1/discovery/{id}/report   — legal compliance report
  GET  /v1/discovery/{id}/evidence — evidence chain (custody)

  GET  /health                     — liveness
  GET  /v1/health/readiness        — readiness (engine, evidence, jurisdiction)

Security (inherited from Tracer-GOV):
  - API key via X-API-Key header (WINNEX_TRACER_API_KEY), constant-time.
  - Security headers on every response.

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
import os, sys, json, logging, time, hmac
from typing import Dict, Any, List
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
import uvicorn

# Make tracer-gov importable when running from a checkout (no-op when the
# package is installed as a dependency).
# NOTE: the Tracer-JUS repo root MUST come FIRST so `core` resolves to
# Tracer-JUS's own `core`, while `persistence`/`compliance` resolve to
# Tracer-GOV's.
_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_TRACER_GOV = os.environ.get("TRACER_GOV_PATH",
                             os.path.abspath(os.path.join(_REPO, "..", "tracer-gov")))
# Insert Tracer-GOV FIRST (so its `persistence`/`compliance` are found),
# then Tracer-JUS repo LAST (so it lands at position 0 and `core` resolves
# to Tracer-JUS's own core).
for _p in (_TRACER_GOV, _REPO):
    if os.path.isdir(_p) and _p not in sys.path:
        sys.path.insert(0, _p)

logger = logging.getLogger("tracer-jus.api")

from winnex_tracer.jus.core import LegalEngine, CaseMetadata

app = FastAPI(
    title="Tracer-JUS API",
    version="0.1.0",
    description="Legal e-Discovery and research with mathematical proof.",
    contact={"name": "Winnex AI", "email": "licensing@winnex.ai"},
    license_info={
        "name": "Business Source License 1.1",
        "url": "https://github.com/winnex-ai/tracer-gov",
    },
)


# ---------------------------------------------------------------------------
# Security middleware (inherited pattern from Tracer-GOV)
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
    if os.environ.get("TRACER_JUS_HSTS", "1") == "1":
        response.headers.setdefault(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains; preload",
        )
    return response


def _constant_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def _require_api_key(request: Request):
    expected = os.environ.get("WINNEX_TRACER_API_KEY", "")
    if not expected:
        raise HTTPException(
            503, "API authentication not configured "
                 "(WINNEX_TRACER_API_KEY not set).")
    provided = request.headers.get("X-API-Key", "")
    if not provided or not _constant_time_eq(provided, expected):
        raise HTTPException(401, "Invalid or missing API key.")


def _require_optional_api_key(request: Request):
    expected = os.environ.get("WINNEX_TRACER_API_KEY", "")
    if not expected:
        return
    provided = request.headers.get("X-API-Key", "")
    if not provided or not _constant_time_eq(provided, expected):
        raise HTTPException(401, "Invalid or missing API key.")


# Engine cache (one LegalEngine per process)
_engine = None


def _get_engine() -> LegalEngine:
    global _engine
    if _engine is None:
        _engine = LegalEngine(jurisdiction="global", mode="public")
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------
class DiscoveryRequest(BaseModel):
    corpus: List[str]
    review_queries: List[str]
    case: Dict[str, Any] = {}
    k: int = 10


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.get("/")
def root():
    return {
        "service": "Tracer-JUS — Legal e-Discovery with Mathematical Proof",
        "version": "0.1.0",
        "endpoints": [
            "POST /v1/discovery/run",
            "GET  /v1/discovery/{id}/proof",
            "GET  /v1/discovery/{id}/report",
            "GET  /v1/discovery/{id}/evidence",
        ],
        "contact": "licensing@winnex.ai",
    }


@app.get("/health")
def health():
    return {"status": "ok", "service": "tracer-jus", "version": "0.1.0"}


@app.get("/v1/health/readiness")
def readiness():
    """Readiness: engine constructible, evidence WORM writable."""
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


@app.post("/v1/discovery/run")
def discovery_run(request: Request, req: DiscoveryRequest):
    """Run e-Discovery triage with soundness guarantee.

    Requires API key if configured. Returns the audited result with the
    mathematical proof and evidence chain receipt.
    """
    _require_optional_api_key(request)
    engine = _get_engine()
    case = CaseMetadata.from_dict(req.case) if req.case else CaseMetadata()
    if not req.corpus or not req.review_queries:
        raise HTTPException(422, "corpus and review_queries must be non-empty")
    try:
        result = engine.run_discovery(
            corpus=req.corpus,
            review_queries=req.review_queries,
            case=case,
            k=req.k,
        )
    except Exception as e:
        raise HTTPException(500, f"Discovery failed: {e}")
    return result.to_dict()


@app.get("/v1/discovery/{audit_id}")
def discovery_get(request: Request, audit_id: str):
    """Retrieve a discovery result's evidence events."""
    _require_optional_api_key(request)
    engine = _get_engine()
    events = engine.evidence_events(audit_id)
    if not events:
        raise HTTPException(404, f"Discovery {audit_id} not found")
    return {"audit_id": audit_id, "events": events}


@app.get("/v1/discovery/{audit_id}/proof")
def discovery_proof(request: Request, audit_id: str):
    """Mathematical proof report for a discovery run."""
    _require_optional_api_key(request)
    engine = _get_engine()
    events = engine.evidence_events(audit_id)
    if not events:
        raise HTTPException(404, f"Discovery {audit_id} not found")
    event = events[0]
    sound = event.get("bound_violations", 0) == 0
    return {
        "report_type": "E_DISCOVERY_PROOF",
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
        "disclaimer": "Proof of exclusion, not of relevance.",
    }


@app.get("/v1/discovery/{audit_id}/report")
def discovery_report(request: Request, audit_id: str):
    """Legal compliance report for a discovery run."""
    _require_optional_api_key(request)
    engine = _get_engine()
    events = engine.evidence_events(audit_id)
    if not events:
        raise HTTPException(404, f"Discovery {audit_id} not found")
    from winnex_tracer.jus.compliance import LegalComplianceReport
    event = events[0]
    sound = event.get("bound_violations", 0) == 0
    report = LegalComplianceReport.generate({
        "corpus_size": event.get("bound_pairs", 0),
        "num_queries": 1,
        "k": 10,
        "engine_used": "winnex-madhava",
        "soundness": {
            "bound_violations": event.get("bound_violations", 0),
            "bound_pairs": event.get("bound_pairs", 0),
            "sound": sound,
            "statement": ("No excluded doc could be in the relevant top-K."
                          if sound else "BOUND VIOLATION"),
        },
        "evidence_chain": {
            "verified": engine.verify_evidence_chain().get(
                "chain_integrity_verified", False),
            "receipt": {"worm_hash": event.get("block_hash", "")},
        },
        "case": event.get("case", {}),
    })
    return report


@app.get("/v1/discovery/{audit_id}/evidence")
def discovery_evidence(request: Request, audit_id: str):
    """Full evidence chain (custody) for a discovery run."""
    _require_optional_api_key(request)
    engine = _get_engine()
    events = engine.evidence_events(audit_id)
    if not events:
        raise HTTPException(404, f"Discovery {audit_id} not found")
    return {
        "audit_id": audit_id,
        "chain_verified": engine.verify_evidence_chain().get(
            "chain_integrity_verified", False),
        "events": events,
    }


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8450))
    uvicorn.run("api.server:app", host="0.0.0.0", port=port)
