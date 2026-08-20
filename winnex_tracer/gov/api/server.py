"""
Tracer-GOV — FastAPI Server (Global)
=====================================
REST API for government audit with mathematical proof — multi-jurisdiction.

Endpoints:
  GET    /v1/jurisdictions            — List supported jurisdictions
  POST   /v1/tracer/search            — Audited search (jurisdiction + mode)
  GET    /v1/tracer/audit/{id}         — Get audit record
  GET    /v1/tracer/audit/{id}/proof   — Mathematical proof JSON

  POST   /v1/tracer/verify            — Verify hash chain integrity
  GET    /v1/tracer/stats             — Query statistics

  GET    /v1/compliance/lgpd/{id}     — LGPD Art. 20 report (br-gv)
  GET    /v1/compliance/lai/{id}      — LAI report (br-gv)
  GET    /v1/compliance/tcu/{id}      — TCU report (br-gv)
  GET    /v1/compliance/cgu/{id}      — CGU report (br-gv)
  GET    /v1/compliance/gdpr/{id}     — GDPR Art. 22 report (eu-gv)
  GET    /v1/compliance/foia/{id}     — FOIA report (us-gv)

  GET    /v1/worm/verify              — Full WORM integrity check
  GET    /v1/audit-log/{audit_id}     — Who accessed this audit trail

Jurisdictions: br-gv, us-gv, eu-gv, pt-gv, es-gv, fr-gv, de-gv, it-gv, global.
Mode: "public" (open data) or "internal" (government-adopted, requires credential).

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
import os, sys, json, logging, time, hmac
from typing import Optional, Dict, Any, List
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

logger = logging.getLogger("tracer-gov.api")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from winnex_tracer.gov.core import TracerEngine, Config, GovMetadata


# ---------------------------------------------------------------------------
# Authentication helpers (SOC 2 CC6.1 / CC6.2)
#
# The API supports two auth models, both configured via env vars:
#   1. API key (header "X-API-Key") — for all endpoints when
#      WINNEX_TRACER_API_KEY is set.
#   2. Internal credential — for mode="internal" searches, compared
#      constant-time against WINNEX_TRACER_INTERNAL_CREDENTIAL.
#
# The audit-log endpoints are always protected (they reveal who accessed
# what) and REQUIRE an API key.
# ---------------------------------------------------------------------------
def _constant_time_eq(a: str, b: str) -> bool:
    """Constant-time string comparison (resistant to timing attacks)."""
    return hmac.compare_digest(a.encode(), b.encode())


def _server_internal_credential() -> str:
    return os.environ.get("WINNEX_TRACER_INTERNAL_CREDENTIAL", "")


def _server_api_key() -> str:
    return os.environ.get("WINNEX_TRACER_API_KEY", "")


def _require_internal_credential(provided: str):
    """Validate an internal-mode credential, raising 401 on mismatch.

    Requires the server to have WINNEX_TRACER_INTERNAL_CREDENTIAL set;
    otherwise internal mode is refused (fail-closed).
    """
    expected = _server_internal_credential()
    if not expected:
        raise HTTPException(
            503, "Internal mode not configured on server "
                 "(WINNEX_TRACER_INTERNAL_CREDENTIAL not set).")
    if not provided or not _constant_time_eq(provided, expected):
        raise HTTPException(401, "Invalid internal credential.")


def _require_api_key(request: Request):
    """Require a valid API key for the request, raising 401 otherwise."""
    expected = _server_api_key()
    if not expected:
        raise HTTPException(
            503, "API authentication not configured on server "
                 "(WINNEX_TRACER_API_KEY not set).")
    provided = request.headers.get("X-API-Key", "")
    if not provided or not _constant_time_eq(provided, expected):
        raise HTTPException(401, "Invalid or missing API key.")


def _require_optional_api_key(request: Request):
    """Enforce API key when configured; allow anonymous otherwise."""
    expected = _server_api_key()
    if not expected:
        return  # anonymous mode (public data)
    provided = request.headers.get("X-API-Key", "")
    if not provided or not _constant_time_eq(provided, expected):
        raise HTTPException(401, "Invalid or missing API key.")

app = FastAPI(
    title="Tracer-GOV API",
    version="2.0.0",
    contact={"name": "Winnex AI", "email": "licensing@winnex.ai"},
    license_info={
        "name": "Business Source License 1.1",
        "url": "https://www.apache.org/licenses/LICENSE-2.0",
    },
)

# ---------------------------------------------------------------------------
# Security headers middleware (SOC 2 CC7.1 / OWASP ASVS hardening)
# Each response carries explicit security headers; deployers can layer
# additional HSTS via the reverse proxy.
# ---------------------------------------------------------------------------
@app.middleware("http")
async def security_headers(request: Request, call_next):
    import starlette.responses as _sr
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    )
    response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
    if os.environ.get("WINNEX_TRACER_HSTS", "1") == "1":
        response.headers.setdefault(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains; preload",
        )
    return response


# ---------------------------------------------------------------------------
# Request audit logging (SOC 2 CC7.2 / CC7.3): log each request with
# outcome. Deployers route this logger to a SIEM / central log store.
# ---------------------------------------------------------------------------
@app.middleware("http")
async def request_audit_log(request: Request, call_next):
    t0 = time.time()
    try:
        response = await call_next(request)
        status = response.status_code
    except Exception:
        status = 500
        raise
    finally:
        logger.info(
            "AUDIT %s %s %s %.1fms src=%s",
            request.method,
            request.url.path,
            status,
            (time.time() - t0) * 1000,
            request.client.host if request.client else "unknown",
        )
    return response

# Engine cache per jurisdiction+mode
_engines: Dict[str, TracerEngine] = {}


def _engine_key(jurisdiction: str, mode: str) -> str:
    return f"{jurisdiction}:{mode}"


def get_engine(jurisdiction: str = "global", mode: str = "public",
               state: str = "", internal_credential: str = "") -> TracerEngine:
    """Get a cached engine for a jurisdiction+mode combination.

    Base configuration is loaded from WINNEX_TRACER_* env vars so that
    deployers can set WORM paths, PG connection strings, etc. without
    editing code; the per-request jurisdiction/mode/state override it.
    """
    key = _engine_key(jurisdiction, mode)
    if key not in _engines:
        cfg = Config.from_env()
        cfg.jurisdiction = jurisdiction
        cfg.mode = mode
        cfg.state = state
        cfg.internal_credential = internal_credential
        _engines[key] = TracerEngine(cfg)
    return _engines[key]


def reset_engines():
    """Clear the engine cache (for tests / config reloads)."""
    _engines.clear()


# --- Request models ---

class SearchRequest(BaseModel):
    query: List[float]
    # Jurisdiction & mode — the metadata contract is REGIONALIZED:
    # the caller sends a `metadata` dict whose keys follow the ACTIVE
    # jurisdiction (e.g. br-gv → orgao_requisitante/cpf/funcao/...;
    # us-gv/eu-gv/global → requesting_agency/operator_id/role/...).
    # The engine validates against the jurisdiction's required_fields.
    #
    # The fixed fields below remain for BACKWARD compatibility (the Liferay
    # bridge and older clients send them); when `metadata` is provided it
    # takes precedence.
    metadata: Dict[str, Any] = {}
    requesting_agency: str = ""
    cpf: str = ""
    operator_id: str = ""
    role: str = ""
    source_database: str = ""
    sensitivity: str = "public"
    purpose: str = ""
    k: int = 10
    jurisdiction: str = "global"
    mode: str = "public"
    state: str = ""
    internal_credential: str = ""


class AuditQuery(BaseModel):
    audit_id: str


class VerifyRequest(BaseModel):
    audit_id: str


# --- Routes ---

@app.get("/")
def root():
    return {
        "service": "Tracer-GOV — Government Audit with Mathematical Proof (Global)",
        "version": "2.0.0",
        "jurisdictions": list_jurisdictions_codes(),
        "compliance": ["LGPD_Art20", "LAI_12527", "MarcoLegal_Gov_Digital",
                       "EU_AI_Act", "GDPR", "FOIA", "TCU", "CGU"],
        "contact": "licensing@winnex.ai",
    }


@app.get("/health")
def health():
    """Liveness check (SOC 2 CC7.1 / A1.1 monitoring).

    Returns 200 when the API process is up. Lightweight — no heavy work.
    """
    return {"status": "ok", "service": "tracer-gov", "version": "2.0.0"}


@app.get("/v1/health/readiness")
def readiness():
    """Readiness check (SOC 2 CC7.1 / CC7.3).

    Reports whether each core dependency is in a ready state:
      - engine: has a built Madhava index for any jurisdiction
      - worm:   WORM store is writable / chain verifiable
      - jurisdictions: registry loaded
    Useful for load balancers, SIEM, and auditor evidence.
    """
    from winnex_tracer.gov.core.jurisdiction import reload_jurisdictions, list_jurisdictions
    from winnex_tracer.persistence import WormStorage

    checks = {}

    # Jurisdictions registry
    try:
        reload_jurisdictions()
        codes = list_jurisdictions()
        checks["jurisdictions"] = {"ok": True, "count": len(codes)}
    except Exception as e:
        checks["jurisdictions"] = {"ok": False, "error": str(e)}

    # Engine built state (any cached engine with an index)
    built = sum(1 for e in _engines.values() if getattr(e, "_N", 0) > 0)
    checks["engine"] = {"ok": built > 0, "built_engines": built}

    # WORM integrity (best-effort — verify chain if data exists)
    try:
        worm = WormStorage(base_path=get_engine().config.worm_base_path)
        if worm.base_path.exists():
            integrity = worm.verify_integrity()
            checks["worm"] = {
                "ok": integrity["chain_integrity_verified"],
                "blocks": integrity["total_blocks"],
                "violations": integrity["violations"],
            }
        else:
            checks["worm"] = {"ok": True, "blocks": 0,
                              "note": "no data yet (append-only store empty)"}
    except Exception as e:
        checks["worm"] = {"ok": False, "error": str(e)}

    all_ok = all(c.get("ok") for c in checks.values())
    return {"status": "ready" if all_ok else "degraded",
            "checks": checks}


@app.get("/v1/jurisdictions")
def jurisdictions():
    """List all supported jurisdictions."""
    from winnex_tracer.gov.core.jurisdiction import reload_jurisdictions, list_jurisdictions
    reload_jurisdictions()
    out = []
    for code in list_jurisdictions():
        from winnex_tracer.gov.core.jurisdiction import get_jurisdiction
        j = get_jurisdiction(code)
        out.append({
            "code": j.code,
            "name": j.name,
            "language": j.language,
            "parent": j.parent,
            "description": j.description,
        })
    return {"jurisdictions": out, "total": len(out)}


def list_jurisdictions_codes():
    try:
        from winnex_tracer.gov.core.jurisdiction import list_jurisdictions
        return list_jurisdictions()
    except Exception:
        return []


class BuildRequest(BaseModel):
    vectors: List[List[float]]
    jurisdiction: str = "global"
    mode: str = "public"
    state: str = ""
    internal_credential: str = ""


@app.post("/v1/tracer/build")
def build(req: BuildRequest):
    """Build the Madhava index for a jurisdiction+mode engine.

    Required before any search against that jurisdiction/mode.
    """
    import numpy as np
    mode = (req.mode or "public").lower()
    if mode == "internal":
        _require_internal_credential(req.internal_credential or "")
    engine = get_engine(
        jurisdiction=req.jurisdiction or "global",
        mode=mode,
        state=req.state or "",
        internal_credential=req.internal_credential or "",
    )
    if not req.vectors or len(req.vectors[0]) == 0:
        raise HTTPException(422, "vectors must be a non-empty matrix")
    vectors = np.array(req.vectors, dtype=np.float32)
    engine.build(vectors)
    return {
        "status": "built",
        "jurisdiction": engine.jurisdiction_code,
        "mode": engine.config.mode,
        "N": engine._N,
        "dim": int(vectors.shape[1]),
        "engine": engine._resolve_backend(),
    }


def _require_built(engine):
    """Raise a clear error if the engine has no index built."""
    if getattr(engine, "_N", 0) == 0 and not hasattr(engine, "_vectors"):
        raise HTTPException(
            409,
            "No index built. Call POST /v1/tracer/build first "
            "(or preload vectors for this jurisdiction/mode).",
        )


@app.post("/v1/tracer/search")
def search(req: SearchRequest):
    """Audited search with government compliance metadata.

    jurisdiction: br-gv | us-gv | eu-gv | pt-gv | es-gv | fr-gv | de-gv |
                  it-gv | global
    mode: "public" (open data) or "internal" (government-adopted;
          requires internal_credential).

    The index must be built first via POST /v1/tracer/build.
    """
    import numpy as np
    # Resolve engine for the requested jurisdiction + mode
    mode = (req.mode or "public").lower()
    if mode == "internal":
        # Real authentication: constant-time comparison against the
        # server-side credential. Fail-closed if not configured.
        _require_internal_credential(req.internal_credential or "")
    engine = get_engine(
        jurisdiction=req.jurisdiction or "global",
        mode=mode,
        state=req.state or "",
        internal_credential=req.internal_credential or "",
    )
    _require_built(engine)

    # Build government metadata — REGIONALIZED (global/multilanguage).
    # 1. If the caller sends a `metadata` dict, its keys follow the ACTIVE
    #    jurisdiction (br-gv → orgao_requisitante/cpf/funcao/...;
    #    us-gv/eu-gv/global → requesting_agency/operator_id/role/...).
    # 2. Backward-compat: fixed fields are folded in (only the non-empty).
    # 3. Drop empty values so the jurisdiction's required_fields validation
    #    behaves as expected (unknown fields are ignored).
    metadata_data = dict(req.metadata or {})
    fixed = {
        "requesting_agency": req.requesting_agency,
        "cpf": req.cpf,
        "operator_id": req.operator_id,
        "role": req.role,
        "source_database": req.source_database,
        "sensitivity": req.sensitivity,
        "purpose": req.purpose,
    }
    for k, v in fixed.items():
        if v and k not in metadata_data:
            metadata_data[k] = v
    metadata_data = {k: v for k, v in metadata_data.items() if v}

    # Validate against the ACTIVE jurisdiction's required_fields (localized).
    # The engine maps generic fields to the regional names first, so a
    # client sending English field names to a Portuguese jurisdiction works.
    metadata_data = engine._map_metadata_fields(metadata_data)
    missing = engine.validate_metadata(metadata_data)
    if missing:
        raise HTTPException(
            422,
            f"Missing required metadata for jurisdiction "
            f"'{req.jurisdiction or 'global'}': {missing}",
        )

    query = np.array(req.query, dtype=np.float32)
    metadata = GovMetadata(data=metadata_data, jurisdiction=req.jurisdiction or "global")
    result = engine.search_with_audit(query, metadata, k=req.k)

    # Persist to WORM (append-only + hash chain) so that
    # GET /v1/tracer/audit/{id} and /proof return real data.
    try:
        from winnex_tracer.persistence import WormStorage
        worm = WormStorage(base_path=engine.config.worm_base_path)

        def _native(v):
            # Convert numpy scalars to native Python types so that
            # json.dumps (WORM serialization) never fails.
            if isinstance(v, (list, tuple)):
                return [_native(x) for x in v]
            if isinstance(v, dict):
                return {k: _native(x) for k, x in v.items()}
            return v.item() if hasattr(v, "item") else v

        if result.commitment is not None:
            # --- PRODUCTION (1.9.2+): the signed lightweight commitment.
            # The motor returned a ~500-byte AuditCommitment already signed
            # with Ed25519 by winnex-tracer-core. The WORM stores the SIGNED
            # commitment UNCHANGED (signature stays valid) + a _ctx block with
            # the government metadata. verify_record operates on `commitment`.
            record = {
                "commitment": result.commitment,   # the signed payload (intact)
                "_ctx": {
                    "jurisdiction": result.jurisdiction,
                    "mode": result.mode,
                    "state": result.state,
                    "language": result.language,
                    "metadata": metadata.to_dict(),
                    "result": {
                        "indices": _native(result.indices),
                        "scores": [round(float(s), 6) for s in result.scores],
                        "bound_violations": int(result.violations_64d),
                        "bound_pairs": int(result.bound_pairs),
                        "total_excluded": int(result.total_excluded),
                        "engine_used": result.engine_used,
                        "latency_ms": round(result.latency_ms, 3),
                    },
                    "audit": [
                        {
                            "doc_id": r.doc_id,
                            "upper_bound": float(r.upper_bound),
                            "threshold": float(r.threshold),
                            "excluded": bool(r.excluded),
                            "verdict": r.verdict,
                        }
                        for r in result.audit
                    ],
                },
            }
        else:
            # Legacy path (< 1.9.2 or non-madhava backend): full record.
            record = {
                "audit_id": metadata.audit_id,
                "jurisdiction": result.jurisdiction,
                "mode": result.mode,
                "state": result.state,
                "language": result.language,
                "metadata": metadata.to_dict(),
                "result": {
                    "indices": _native(result.indices),
                    "scores": [round(float(s), 6) for s in result.scores],
                },
                "audit": [
                    {
                        "doc_id": r.doc_id,
                        "true_cosine": float(r.true_cosine),
                        "upper_bound": float(r.upper_bound),
                        "threshold": float(r.threshold),
                        "excluded": bool(r.excluded),
                        "verdict": r.verdict,
                    }
                    for r in result.audit
                ],
                "signature": result.signature,
                "signature_algorithm": result.signature_algorithm,
                "total_excluded": result.total_excluded,
                "violations_64d": result.violations_64d,
                "violations_128d": result.violations_128d,
                "latency_ms": round(result.latency_ms, 3),
                "engine_used": result.engine_used,
            }
        receipt = worm.append(record)
    except Exception as e:  # persistence must never fail the search
        logger.warning("Tracer-GOV API: WORM persist failed: %s", e)
        receipt = {}

    return {
        "audit_id": metadata.audit_id,
        "jurisdiction": result.jurisdiction,
        "mode": result.mode,
        "state": result.state,
        "language": result.language,
        "indices": result.indices,
        "scores": result.scores,
        "total_excluded": result.total_excluded,
        "latency_ms": round(result.latency_ms, 3),
        "violations_64d": result.violations_64d,
        "violations_128d": result.violations_128d,
        "worm": {
            "block_hash": receipt.get("worm_hash", ""),
            "path": receipt.get("worm_path", ""),
        },
    }


def _resolve_worm_path(audit_id: str) -> str:
    """Resolve a WORM record by its stored audit_id.

    Tracer-GOV persists each audit block with the audit_id inside the
    block data (see the persistence layer). The WORM store is addressed
    by block_hash, so we scan for the block whose data.audit_id matches.
    Returns the block (record) or raises 404.
    """
    from winnex_tracer.persistence import WormStorage
    worm = WormStorage(base_path=get_engine().config.worm_base_path)
    if not worm.base_path.exists():
        raise HTTPException(404, f"Audit {audit_id} not found (no WORM data)")
    for f in sorted(worm.base_path.rglob("records.jsonl")):
        with open(f) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    block = json.loads(line)
                except json.JSONDecodeError:
                    continue
                data = block.get("data", {})
                if data.get("audit_id") == audit_id:
                    return block
    raise HTTPException(404, f"Audit {audit_id} not found in WORM storage")


def _worm_record(audit_id: str) -> dict:
    """Fetch the stored audit record (data payload) for an audit_id.

    Returns the record dict or raises 404. Used by compliance endpoints so
    reports reflect the REAL audited search, not a placeholder.
    """
    block = _resolve_worm_path(audit_id)
    data = block.get("data", {})
    data.setdefault("worm_path", block.get("path", ""))
    data.setdefault("worm_hash", block.get("block_hash", ""))
    data.setdefault("query_hash", audit_id)
    return data


@app.get("/v1/tracer/audit/{audit_id}")
def get_audit(audit_id: str):
    """Get audit record details from WORM storage."""
    block = _resolve_worm_path(audit_id)
    data = block.get("data", {})
    return {
        "audit_id": audit_id,
        "metadata": data.get("metadata", data),
        "result": data.get("result", {}),
        "signature": data.get("signature", ""),
        "signature_algorithm": data.get("signature_algorithm", ""),
        "total_excluded": data.get("total_excluded", 0),
        "violations_64d": data.get("violations_64d", 0),
        "violations_128d": data.get("violations_128d", 0),
        "worm": {
            "path": block.get("path", ""),
            "block_hash": block.get("block_hash", ""),
            "prev_hash": block.get("prev_hash", ""),
            "timestamp": block.get("timestamp", ""),
        },
        "retrieved_from": "WORM storage",
    }


@app.get("/v1/tracer/audit/{audit_id}/proof")
def get_proof(audit_id: str):
    """Get mathematical proof for an audit from WORM storage."""
    block = _resolve_worm_path(audit_id)
    data = block.get("data", {})
    audit_records = data.get("audit", [])
    return {
        "audit_id": audit_id,
        "algorithm": "Cauchy-Schwarz + QR-JL (Madhava)",
        "bound_violations": {
            "64d": data.get("violations_64d", 0),
            "128d": data.get("violations_128d", 0),
        },
        "total_excluded": data.get("total_excluded", 0),
        "exclusion_count": sum(
            1 for r in audit_records if r.get("excluded")),
        "survived_count": sum(
            1 for r in audit_records if not r.get("excluded")),
        "explanations": [
            {
                "doc_id": r.get("doc_id"),
                "true_cosine": r.get("true_cosine"),
                "upper_bound": r.get("upper_bound"),
                "threshold": r.get("threshold"),
                "excluded": r.get("excluded"),
                "verdict": r.get("verdict", ""),
            }
            for r in audit_records[:500]
        ],
        "worm": {
            "block_hash": block.get("block_hash", ""),
            "prev_hash": block.get("prev_hash", ""),
        },
        "proof_available": True,
    }


@app.post("/v1/tracer/verify")
def verify_audit(req: VerifyRequest):
    """Verify integrity of an audit record (WORM hash chain + record)."""
    from winnex_tracer.persistence import WormStorage
    worm = WormStorage(base_path=get_engine().config.worm_base_path)
    integrity = worm.verify_integrity()
    block = _resolve_worm_path(req.audit_id)
    return {
        "audit_id": req.audit_id,
        "record_found": True,
        "worm_integrity": "verified" if integrity["chain_integrity_verified"] else "FAILED",
        "worm_total_blocks": integrity["total_blocks"],
        "worm_violations": integrity["violations"],
        "block_hash": block.get("block_hash", ""),
        "blockchain_verified": "not_configured",
        "note": "Blockchain verification requires a configured chain/RPC.",
    }


@app.get("/v1/tracer/stats")
def stats():
    """Query statistics."""
    return {
        "service": "Tracer-GOV",
        "note": "Statistics available via PostgreSQL count queries",
    }


@app.get("/v1/compliance/lgpd/{audit_id}")
def lgpd_report(request: Request, audit_id: str, jurisdiction: str = "br-gv"):
    """LGPD Art. 20 compliance report (Brazil — br-gv).

    Reads the REAL audit record from WORM storage; returns 404 if the
    audit does not exist. Requires API key if configured.
    """
    _require_optional_api_key(request)
    from winnex_tracer.gov.compliance import LgpdReport
    record = _worm_record(audit_id)
    if jurisdiction and record.get("metadata", {}).get("jurisdiction") is None:
        record.setdefault("metadata", {})["jurisdiction"] = jurisdiction
    return LgpdReport.generate(record)


@app.get("/v1/compliance/gdpr/{audit_id}")
def gdpr_report(request: Request, audit_id: str, jurisdiction: str = "eu-gv"):
    """GDPR Art. 22 compliance report (European Union — eu-gv).

    Reads the REAL audit record from WORM storage.
    Requires API key if configured.
    """
    _require_optional_api_key(request)
    from winnex_tracer.gov.compliance.localized import generate_localized_report
    record = _worm_record(audit_id)
    return generate_localized_report(jurisdiction, record)


@app.get("/v1/compliance/foia/{audit_id}")
def foia_report(request: Request, audit_id: str, jurisdiction: str = "us-gv"):
    """FOIA compliance report (United States — us-gv).

    Reads the REAL audit record from WORM storage.
    Requires API key if configured.
    """
    _require_optional_api_key(request)
    from winnex_tracer.gov.compliance.localized import generate_localized_report
    record = _worm_record(audit_id)
    return generate_localized_report(jurisdiction, record)


@app.get("/v1/compliance/lai/{audit_id}")
def lai_report(request: Request, audit_id: str):
    """LAI compliance report — reads the REAL audit record from WORM.
    Requires API key if configured.
    """
    _require_optional_api_key(request)
    from winnex_tracer.gov.compliance import LaiReport
    return LaiReport.generate(_worm_record(audit_id))


@app.get("/v1/compliance/tcu/{audit_id}")
def tcu_report(request: Request, audit_id: str):
    """TCU accountability report — reads the REAL audit record from WORM.
    Requires API key if configured.
    """
    _require_optional_api_key(request)
    from winnex_tracer.gov.reports import TcuReport
    return TcuReport.generate(_worm_record(audit_id))


@app.get("/v1/compliance/cgu/{audit_id}")
def cgu_report(request: Request, audit_id: str):
    """CGU transparency report — reads the REAL audit record from WORM.
    Requires API key if configured.
    """
    _require_optional_api_key(request)
    from winnex_tracer.gov.reports import CguReport
    return CguReport.generate(_worm_record(audit_id))


@app.get("/v1/worm/verify")
def worm_verify():
    """Full WORM integrity verification."""
    from winnex_tracer.persistence import WormStorage
    config = get_engine().config
    worm = WormStorage(
        base_path=config.worm_base_path)
    return worm.verify_integrity()


@app.get("/v1/audit-log/{audit_id}")
def audit_log(request: Request, audit_id: str):
    """Who accessed this audit trail.

    PROTECTED: reveals who accessed what (sensitive) — requires a valid
    API key (X-API-Key header) against WINNEX_TRACER_API_KEY.
    """
    _require_api_key(request)
    from winnex_tracer.gov.core import AuditLogTracker
    tracker = AuditLogTracker()
    return {"audit_id": audit_id,
            "accesses": tracker.get_access_history(audit_id)}


# ---------------------------------------------------------------------------
# Risk Intelligence endpoints
# ---------------------------------------------------------------------------

@app.get("/v1/risk/analyze")
def risk_analyze():
    """Risk displacement analysis -- EXPERIMENTAL. See kaggle/BENCHMARK_RESULTS.md.
    Current benchmark shows this method does NOT outperform cosine similarity."""
    from winnex_tracer.gov.risk import RiskEngine, RiskConfig
    from winnex_tracer.gov.risk.sample_dimensions import SAMPLE_EXPOSURES, SAMPLE_OUTCOMES
    cfg = RiskConfig.from_env()
    engine = RiskEngine(cfg)
    engine.add_exposures_from_dict(SAMPLE_EXPOSURES)
    engine.add_outcomes_from_dict(SAMPLE_OUTCOMES)
    result = engine.analyze()
    return {
        "summary": result.to_dict(),
        "significant_displacements": [d.to_dict() for d in result.significant_displacements],
        "causal_chains": [c.to_dict() for c in result.causal_chains],
        "alerts": [a.to_dict() for a in result.alerts],
    }


@app.get("/v1/risk/pair")
def risk_pair(exposure_id: str = Query(...), outcome_id: str = Query(...)):
    """Analyze a single exposure-outcome pair. EXPERIMENTAL."""
    from winnex_tracer.gov.risk import RiskEngine, RiskConfig
    from winnex_tracer.gov.risk.sample_dimensions import SAMPLE_EXPOSURES, SAMPLE_OUTCOMES
    cfg = RiskConfig.from_env()
    engine = RiskEngine(cfg)
    engine.add_exposures_from_dict(SAMPLE_EXPOSURES)
    engine.add_outcomes_from_dict(SAMPLE_OUTCOMES)
    try:
        return engine.analyze_pair(exposure_id, outcome_id)
    except KeyError as e:
        raise HTTPException(404, str(e))


@app.get("/v1/risk/alerts")
def risk_alerts(severity: Optional[str] = Query(None)):
    """Get risk alerts. EXPERIMENTAL -- currently disabled pending benchmark review."""
    from winnex_tracer.gov.risk import RiskEngine, RiskConfig
    from winnex_tracer.gov.risk.sample_dimensions import SAMPLE_EXPOSURES, SAMPLE_OUTCOMES
    cfg = RiskConfig.from_env()
    engine = RiskEngine(cfg)
    engine.add_exposures_from_dict(SAMPLE_EXPOSURES)
    engine.add_outcomes_from_dict(SAMPLE_OUTCOMES)
    result = engine.analyze()
    alerts = [a.to_dict() for a in result.alerts]
    if severity:
        alerts = [a for a in alerts if a["severity"] == severity]
    return {"alerts": alerts, "total": len(alerts)}


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8443))
    uvicorn.run("api.server:app", host="0.0.0.0", port=port)
