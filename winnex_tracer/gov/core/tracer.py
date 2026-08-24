"""
Tracer-GOV — Government Audit Engine (Global)
==============================================
Audit layer for public sector institutions worldwide with:
  - Madhava mathematical proof (Cauchy-Schwarz + QR-JL)
  - Country-specific digital signatures (ICP-Brasil, eIDAS, DNIe, CIE, ...)
  - Dual-write persistence (PostgreSQL + permissioned blockchain)
  - WORM (Write Once Read Many) enforcement
  - Configurable retention and compliance policies per jurisdiction
  - Self-audit trail logging
  - Public mode (open data) and Internal mode (government-adopted)

Jurisdictions: br-gv, us-gv, eu-gv, pt-gv, es-gv, fr-gv, de-gv, it-gv, global.
Each jurisdiction inherits policies (global → region → country) and
localizes reports in its own language.

Integrates with the Winnex stack in order of preference:
  1. winnex-audit-cpp  — C++ via pybind11 (fastest) [BSL 1.1]
  2. winnex-production-tools  — Python AuditLayer (numpy) [BSL 1.1]
  3. Built-in naive fallback (proof-of-concept audit)

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
import json, os, time, hashlib, uuid, logging
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("tracer-gov")

# ---------------------------------------------------------------------------
# Stack detection: try C++ pybind11, then winnex_madhava (pip), then
# winnex-production-tools AuditLayer, then built-in fallback
# ---------------------------------------------------------------------------
_HAS_CPP_ENGINE: bool = False
_HAS_PY_ENGINE: bool = False
_HAS_MADHAVA_PIP: bool = False

try:
    import winnex_audit_py as _cpp
    _HAS_CPP_ENGINE = True
    logger.info("Tracer-GOV: using winnex-audit-cpp (C++/pybind11)")
except ImportError:
    try:
        import winnex_madhava as _wm
        _HAS_MADHAVA_PIP = True
        logger.info("Tracer-GOV: using winnex-madhava (pip, C++20 core)")
    except ImportError:
        try:
            from winnex_production import AuditLayer as _PyAuditLayer
            from winnex_production import Config as _PyConfig
            _HAS_PY_ENGINE = True
            logger.info("Tracer-GOV: using winnex-production-tools AuditLayer (Python)")
        except ImportError:
            logger.info("Tracer-GOV: no Winnex engine found, using built-in fallback")


@dataclass
class Config:
    """Tracer-GOV configuration — no hardcoded values.

    Values come from (in order of precedence):
    1. Constructor arguments
    2. Environment variables (WINNEX_TRACER_*)
    3. JSON configuration file
    4. Sensible defaults
    """
    # Madhava audit engine
    stage1_dim: int = 64
    stage2_dim: int = 128
    final_k: int = 10
    stage2_topk: int = 500
    random_seed: int = 42

    # Which engine to prefer: "cpp", "python", "auto"
    engine_preference: str = "auto"

    # Persistence — dual-write
    pg_connection_string: str = ""
    blockchain_rpc: str = ""
    blockchain_contract: str = ""
    blockchain_chain: str = ""
    worm_base_path: str = "/var/lib/tracer-gov/worm"

    # ICP-Brasil
    icp_cert_path: str = ""
    icp_key_path: str = ""

    # Policies JSON path
    policies_path: str = ""

    # Jurisdiction (e.g. "br-gv", "us-gv", "eu-gv", "pt-gv", "es-gv",
    # "fr-gv", "de-gv", "it-gv", "global")
    jurisdiction: str = "global"

    # Operation mode: "public" (open data) or "internal" (government-adopted)
    mode: str = "public"

    # Internal-mode credential (required when mode == "internal")
    internal_credential: str = ""

    # Sub-jurisdiction / state (e.g. "go" for Goiás, "ca" for California)
    state: str = ""

    # Audit trail
    audit_log_enabled: bool = True
    max_audit_records_per_query: int = 500

    @classmethod
    def from_env(cls) -> "Config":
        """Load configuration from WINNEX_TRACER_* environment variables."""
        c = cls()
        if v := os.environ.get("WINNEX_TRACER_STAGE1_DIM"):
            c.stage1_dim = int(v)
        if v := os.environ.get("WINNEX_TRACER_STAGE2_DIM"):
            c.stage2_dim = int(v)
        if v := os.environ.get("WINNEX_TRACER_FINAL_K"):
            c.final_k = int(v)
        if v := os.environ.get("WINNEX_TRACER_ENGINE"):
            c.engine_preference = v
        if v := os.environ.get("WINNEX_TRACER_PG_CONNECTION"):
            c.pg_connection_string = v
        if v := os.environ.get("WINNEX_TRACER_BLOCKCHAIN_RPC"):
            c.blockchain_rpc = v
        if v := os.environ.get("WINNEX_TRACER_BLOCKCHAIN_CONTRACT"):
            c.blockchain_contract = v
        if v := os.environ.get("WINNEX_TRACER_BLOCKCHAIN_CHAIN"):
            c.blockchain_chain = v
        if v := os.environ.get("WINNEX_TRACER_WORM_PATH"):
            c.worm_base_path = v
        if v := os.environ.get("WINNEX_TRACER_ICP_CERT"):
            c.icp_cert_path = v
        if v := os.environ.get("WINNEX_TRACER_ICP_KEY"):
            c.icp_key_path = v
        if v := os.environ.get("WINNEX_TRACER_POLICIES"):
            c.policies_path = v
        if v := os.environ.get("WINNEX_TRACER_JURISDICTION"):
            c.jurisdiction = v
        if v := os.environ.get("WINNEX_TRACER_MODE"):
            c.mode = v
        if v := os.environ.get("WINNEX_TRACER_INTERNAL_CREDENTIAL"):
            c.internal_credential = v
        if v := os.environ.get("WINNEX_TRACER_STATE"):
            c.state = v
        return c

    @classmethod
    def from_json(cls, path: str) -> "Config":
        """Load configuration from a JSON file."""
        with open(path) as f:
            data = json.load(f)
        c = cls()
        for k, v in data.items():
            if hasattr(c, k):
                setattr(c, k, v)
        return c


@dataclass
class GovMetadata:
    """Government metadata — fields defined in policies JSON.

    Required fields and validations are loaded dynamically from
    the jurisdiction policies — no hardcoded field lists.
    """
    data: Dict[str, Any] = field(default_factory=dict)
    audit_id: str = ""
    timestamp: str = ""
    query_hash: str = ""
    jurisdiction: str = "global"
    mode: str = "public"
    state: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()
        if not self.audit_id:
            self.audit_id = hashlib.sha3_256(
                f"{self.timestamp}:{uuid.uuid4()}".encode()
            ).hexdigest()[:32]
        if not self.query_hash:
            raw = json.dumps(self.data, sort_keys=True)
            self.query_hash = hashlib.sha3_256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        return {
            **self.data,
            "audit_id": self.audit_id,
            "timestamp": self.timestamp,
            "query_hash": self.query_hash,
            "jurisdiction": self.jurisdiction,
            "mode": self.mode,
            "state": self.state,
        }

    def get(self, key: str, default=None):
        return self.data.get(key, default)

    def __getitem__(self, key: str):
        return self.data[key]


@dataclass
class GovAuditRecord:
    """Single audit record — mathematical proof + government metadata."""
    doc_id: int
    true_cosine: float
    upper_bound: float
    threshold: float
    excluded: bool
    stage: str
    verdict: str = ""


@dataclass
class GovAuditResult:
    """Complete audited query result."""
    # Search results
    indices: List[int] = field(default_factory=list)
    scores: List[float] = field(default_factory=list)

    # Government metadata
    metadata: Optional[GovMetadata] = None

    # Mathematical audit trail
    audit: List[GovAuditRecord] = field(default_factory=list)
    total_excluded: int = 0

    # Digital signature
    signature: str = ""
    signature_algorithm: str = ""

    # WORM proof
    worm_path: str = ""
    worm_hash: str = ""

    # Dual-write receipts
    pg_receipt: Dict[str, Any] = field(default_factory=dict)
    blockchain_receipt: Dict[str, Any] = field(default_factory=dict)

    # Performance metrics
    latency_ms: float = 0.0
    violations_64d: int = 0
    violations_128d: int = 0

    # Proof metrics (winnex-madhava real engine)
    bound_pairs: int = 0

    # Hash chain
    chain_prev_hash: str = ""
    chain_block_hash: str = ""

    # Which engine was used
    engine_used: str = "none"

    # Jurisdiction / mode (from the audited query)
    jurisdiction: str = "global"
    mode: str = "public"
    state: str = ""
    language: str = "en"

    # Audit commitment — the signed ~500-byte record from winnex-tracer-core
    # (make_worm_record). Present when the motor is winnex-madhava >= 1.9.2
    # and search_with_commitment was used. When present, `audit` holds only
    # the boundary sample (not the full certificate).
    commitment: Optional[Dict[str, Any]] = None


class TracerEngine:
    """Government audit engine — orchestrates Madhava + compliance.

    No hardcoded values. All policies come from:
    - Config (env vars or JSON file)
    - Jurisdiction policies (config/jurisdictions/<code>/policies.json)
    - ICP-Brasil certificates (path-configured)

    Jurisdiction & mode:
      jurisdiction: "br-gv", "us-gv", "eu-gv", "pt-gv", ... or "global"
      mode:         "public" (open data) or "internal" (government-adopted)

    Backend resolution (engine_preference):
      "cpp"     → use winnex_audit_py (C++), fail if unavailable
      "python"  → use winnex_production.AuditLayer (Python)
      "auto"    → try C++ first, fall back to Python, fall back to built-in
    """

    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self._policies: Dict[str, Any] = {}

        # Load jurisdiction registry (lazily cached at module level)
        from winnex_tracer.gov.core.jurisdiction import reload_jurisdictions, get_jurisdiction
        reload_jurisdictions()
        try:
            self._jurisdiction = get_jurisdiction(self.config.jurisdiction)
        except KeyError:
            # Unknown jurisdiction → fall back to global, but keep code
            self._jurisdiction = get_jurisdiction("global")
            logger.warning(
                "Tracer-GOV: unknown jurisdiction '%s' — using global",
                self.config.jurisdiction,
            )

        # Merge jurisdiction policies over legacy policies.json (if any)
        self._load_policies()

        # Validate mode
        self._validate_mode()

        # Backend engine — resolved lazily
        self._engine: Any = None
        self._N: int = 0

    # ------------------------------------------------------------------
    # Jurisdiction / mode
    # ------------------------------------------------------------------
    @property
    def jurisdiction(self):
        """The active jurisdiction object (with merged policies)."""
        return self._jurisdiction

    @property
    def jurisdiction_code(self) -> str:
        return self._jurisdiction.code

    @property
    def language(self) -> str:
        return self._jurisdiction.language

    def _validate_mode(self):
        """Validate operation mode against jurisdiction policies."""
        mode = self.config.mode or "public"
        supported = self._jurisdiction.policies.get("mode", {}).get(
            "supported", ["public", "internal"])
        if mode not in supported:
            raise ValueError(
                f"Mode '{mode}' not supported by jurisdiction "
                f"'{self.jurisdiction_code}'. Supported: {supported}"
            )
        if mode == "internal" and not self.config.internal_credential:
            raise ValueError(
                "Mode='internal' requires WINNEX_TRACER_INTERNAL_CREDENTIAL "
                "(or Config.internal_credential). Refusing to run internal "
                "mode without authentication."
            )

    def _load_policies(self):
        """Load policies: jurisdiction policies + optional legacy policies.json.

        The jurisdiction policies (with inheritance) take precedence over
        the legacy config/policies.json for backward compatibility.
        """
        # Start from jurisdiction policies (already merged via inheritance)
        self._policies = dict(self._jurisdiction.policies)

        # Optionally layer legacy policies.json on top (explicitly set path)
        paths_to_try = [
            self.config.policies_path,
            os.environ.get("WINNEX_TRACER_POLICIES", ""),
        ]
        for p in paths_to_try:
            if p and os.path.exists(p):
                with open(p) as f:
                    legacy = json.load(f)
                # Merge: jurisdiction wins for top-level keys it defines,
                # legacy fills anything else
                for k, v in legacy.items():
                    self._policies.setdefault(k, v)
                return

    def get_policy(self, key: str, default=None):
        """Get policy value from policies JSON — no hardcoded defaults."""
        return self._policies.get(key, default)

    def get_sensitivity_config(self, classification: str) -> dict:
        """Load sensitivity configuration from jurisdiction policies."""
        return self._jurisdiction.get_sensitivity(classification)

    def get_agency_config(self, agency: str) -> dict:
        """Load agency configuration from jurisdiction policies."""
        return self._jurisdiction.get_agency(agency)

    def get_retention_years(self, agency: str, classification: str) -> int:
        """Get retention years from jurisdiction policies (inherited)."""
        return self._jurisdiction.get_retention_years(agency, classification)

    def get_state_config(self, state: str) -> dict:
        """Load state/sub-jurisdiction configuration (e.g. 'go', 'ca')."""
        states = self._jurisdiction.policies.get("states", {})
        return states.get(state, states.get("default", {}))

    def get_compliance_frameworks(self) -> list:
        """List compliance frameworks for the active jurisdiction.

        Tolerates both policy schemas:
          - list:  ["GDPR", "EU_AI_Act", ...]   (country/region level)
          - dict:  {"default": [...], ...}      (global base level)
        """
        frameworks = self._jurisdiction.policies.get(
            "compliance_frameworks", [])
        if isinstance(frameworks, dict):
            frameworks = frameworks.get(
                "default",
                next(iter(frameworks.values()), []))
        return list(frameworks)

    # ------------------------------------------------------------------
    # Regionalized metadata (global / multilanguage)
    # ------------------------------------------------------------------
    # The tool is global: each jurisdiction uses its own field names
    # (br-gv/pt-gv → Portuguese; us-gv/eu-gv/global → English). This map
    # translates the GENERIC international names to the regional names so
    # a client sending `requesting_agency` to br-gv is mapped to
    # `orgao_requisitante` automatically. The inverse (regional → generic)
    # is not needed — the jurisdiction's required_fields are authoritative.
    _FIELD_MAP: Dict[str, Dict[str, str]] = {
        # generic English → Brazilian Portuguese (br-gv, pt-gv)
        "pt": {
            "requesting_agency": "orgao_requisitante",
            "role": "funcao",
            "source_database": "base_de_dados",
            "sensitivity": "sensibilidade",
            "purpose": "finalidade",
        },
    }

    def _map_metadata_fields(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Translate generic field names to the ACTIVE jurisdiction's names.

        Fields already using the regional name pass through unchanged.
        Unknown generic fields are kept as-is (validation may flag them).
        """
        required = self.get_policy("required_fields", [])
        # If the jurisdiction uses English names (or is global), no mapping.
        if "orgao_requisitante" not in required and "requesting_agency" in required:
            return data
        mapping = self._FIELD_MAP.get("pt", {})
        out = dict(data)
        for generic, regional in mapping.items():
            if generic in out and regional not in out:
                out[regional] = out.pop(generic)
        return out

    def validate_metadata(self, data: Dict[str, Any]) -> List[str]:
        """Validate metadata against required fields in policies JSON.

        The data is first mapped to the ACTIVE jurisdiction's field names,
        so a global (English) metadata dict works for a Portuguese
        jurisdiction and vice-versa.
        """
        mapped = self._map_metadata_fields(data)
        required = self.get_policy("required_fields", [])
        if not required:
            return []
        return [k for k in required if k not in mapped or not mapped[k]]

    def validate_sensitivity(self, classification: str) -> bool:
        """Validate sensitivity classification against policies."""
        sens = self.get_policy("sensitivity", {})
        if not sens:
            return True
        return classification in sens or "default" in sens

    # ------------------------------------------------------------------
    # Backend resolution
    # ------------------------------------------------------------------
    def _resolve_backend(self) -> str:
        """Resolve which backend to use based on config and availability.

        Returns engine type string: "cpp", "python", or "builtin".
        """
        pref = self.config.engine_preference

        if pref == "cpp":
            if not _HAS_CPP_ENGINE:
                raise RuntimeError(
                    "engine_preference='cpp' but winnex-audit-cpp is not installed. "
                    "Install it from https://github.com/winnex-ai/winnex-audit-cpp"
                )
            return "cpp"

        if pref == "python":
            if not _HAS_PY_ENGINE:
                raise RuntimeError(
                    "engine_preference='python' but winnex-production-tools is not installed. "
                    "Install it from https://github.com/winnex-ai/winnex-production-tools"
                )
            return "python"

        # auto: C++ → winnex_madhava (pip) → winnex_production → builtin
        if _HAS_CPP_ENGINE:
            return "cpp"
        if _HAS_MADHAVA_PIP:
            return "madhava_pip"
        if _HAS_PY_ENGINE:
            return "python"
        return "builtin"

    # ------------------------------------------------------------------
    # Build
    # ------------------------------------------------------------------
    def build(self, vectors: Any, external_ids: Any = None):
        """Build the Madhava index using the resolved backend.

        Delegates to:
          - winnex_audit_py.AuditEngine.build()  (C++/pybind11)
          - winnex_production.AuditLayer.build()  (Python numpy)
          - built-in numpy fallback
        """
        import numpy as np
        backend = self._resolve_backend()

        if backend == "cpp":
            # C++ pybind11: winnex_audit_py Config + AuditEngine
            cfg = _cpp.Config()
            cfg.input_dim = vectors.shape[1]
            cfg.stage1_dim = self.config.stage1_dim
            cfg.stage2_dim = self.config.stage2_dim
            cfg.final_k = self.config.final_k
            cfg.stage2_topk = self.config.stage2_topk

            engine = _cpp.AuditEngine(cfg)
            data = np.ascontiguousarray(vectors, dtype=np.float32)
            engine.build(data, len(data))
            self._engine = engine
            self._N = engine.size()
            logger.info(f"Tracer-GOV: built C++ engine: {self._N} x {cfg.input_dim}D")

        elif backend == "python":
            # Python AuditLayer
            py_cfg = _PyConfig(
                stage1_dim=self.config.stage1_dim,
                stage2_dim=self.config.stage2_dim,
                final_k=self.config.final_k,
                stage2_topk=self.config.stage2_topk,
                random_seed=self.config.random_seed,
            )
            engine = _PyAuditLayer(py_cfg)
            if external_ids is not None:
                data = [(eid, vec) for eid, vec in zip(external_ids, vectors)]
                engine.build_from_data(data)
            else:
                engine.build(vectors)
            self._engine = engine
            self._N = engine.N
            logger.info(f"Tracer-GOV: built Python engine: {self._N} x {vectors.shape[1]}D")

        elif backend == "madhava_pip":
            # winnex-madhava (pip, native C++20 core with Cauchy-Schwarz bound)
            dim = vectors.shape[1]
            self._engine = _wm.build_engine(
                np.ascontiguousarray(vectors, dtype=np.float32),
                dim=dim,
                metric="cosine",
                quant="int8",
                stage1_dim=min(self.config.stage1_dim, dim),
                stage2_dim=min(self.config.stage2_dim, dim),
                k=self.config.final_k,
                k1_fraction=0.05,
                # Bounded Stage-2 survivors (Gargalo #2): postfilter=True scores
                # every survivor exactly, so cap k2 to keep query cost bounded
                # on large corpora. Configurable via env for tuning without
                # rebuild (e.g. TRACER_K2_MAX=2000 on strong hardware).
                k2_fraction=float(
                    os.environ.get("TRACER_K2_FRACTION", "0.005")),
                k2_max=int(os.environ.get("TRACER_K2_MAX", "500")),
                modulation=True,
                postfilter=True,
                seed=self.config.random_seed,
            )
            self._N = self._engine.num_vectors()
            logger.info(f"Tracer-GOV: built winnex-madhava (pip): {self._N} x {dim}D")

        else:
            # Built-in fallback (naive numpy)
            self._vectors = np.ascontiguousarray(vectors, dtype=np.float32)
            self._N = len(self._vectors)
            self._external_ids = external_ids
            logger.info(f"Tracer-GOV: built fallback engine: {self._N} x {vectors.shape[1]}D")

    # ------------------------------------------------------------------
    # Search with full government audit
    # ------------------------------------------------------------------
    def search_with_audit(
        self,
        query_vector: Any,
        metadata: GovMetadata,
        k: int = 10,
    ) -> GovAuditResult:
        """Audited search with government compliance.

        Orchestrates:
        1. Madhava mathematical proof (Cauchy-Schwarz bounds)
           → delegates to winnex-audit-cpp / AuditLayer / fallback
        2. Government metadata enrichment
        3. Proof packaging into GovAuditResult

        The active jurisdiction, mode, state and language are recorded
        on the result and stamped on the metadata.
        """
        # Stamp jurisdiction/mode/state/language from engine config.
        # The engine config is authoritative; only fall back to the metadata
        # value when the engine uses the default 'global'/'public'.
        if self.jurisdiction_code != "global" or not metadata.jurisdiction or metadata.jurisdiction == "global":
            metadata.jurisdiction = self.jurisdiction_code
        if self.config.mode and self.config.mode != "public":
            metadata.mode = self.config.mode
        if self.config.state:
            metadata.state = self.config.state

        result = GovAuditResult(metadata=metadata)
        result.jurisdiction = metadata.jurisdiction
        result.mode = metadata.mode
        result.state = metadata.state
        result.language = self.language
        t0 = time.time()

        backend = self._resolve_backend()
        import numpy as np
        q = np.asarray(query_vector, dtype=np.float32)

        if backend == "cpp":
            # ----------------------------------------------------------
            # C++ engine (winnex-audit-cpp via pybind11)
            # ----------------------------------------------------------
            cpp_result = self._engine.search(q, k)
            result.indices = list(cpp_result.indices)
            result.scores = [float(s) for s in cpp_result.scores]
            result.latency_ms = cpp_result.latency_ms
            result.engine_used = "winnex-audit-cpp (C++/pybind11)"

            # Build GovAuditRecords from C++ AuditRecords
            for rec in cpp_result.audit:
                result.audit.append(GovAuditRecord(
                    doc_id=rec.doc_id,
                    true_cosine=rec.true_cosine,
                    upper_bound=rec.upper_bound,
                    threshold=rec.threshold,
                    excluded=rec.excluded,
                    stage=rec.stage,
                    verdict="PROVABLY_EXCLUDED" if rec.excluded else "SURVIVED",
                ))

            # Bound violations
            violations = self._engine.check_bounds(q)
            result.violations_64d = violations[0]
            result.violations_128d = violations[1]

            # Total excluded: count of audit records flagged excluded
            result.total_excluded = sum(1 for r in result.audit if r.excluded)

        elif backend == "python":
            # ----------------------------------------------------------
            # Python engine (winnex-production-tools AuditLayer)
            # ----------------------------------------------------------
            py_result = self._engine.search(q, k)
            result.indices = list(py_result.indices)
            result.scores = [float(s) for s in py_result.scores]
            result.latency_ms = py_result.latency_ms
            result.violations_64d = py_result.violations_64d
            result.violations_128d = py_result.violations_128d
            result.engine_used = "winnex-production-tools AuditLayer (Python)"

            for rec in py_result.audit:
                result.audit.append(GovAuditRecord(
                    doc_id=rec.doc_id,
                    true_cosine=rec.true_cosine,
                    upper_bound=rec.upper_bound,
                    threshold=rec.threshold,
                    excluded=rec.excluded,
                    stage=rec.stage,
                    verdict="PROVABLY_EXCLUDED" if rec.excluded else "SURVIVED",
                ))

            result.total_excluded = sum(1 for r in result.audit if r.excluded)

        elif backend == "madhava_pip":
            # ----------------------------------------------------------
            # winnex-madhava (pip, native C++20 core) — the PRODUCTION path.
            # With winnex-madhava >= 1.9.2 the motor returns a lightweight
            # AuditCommitment (count + threshold + boundary sample) via
            # search_with_commitment, and the winnex-tracer-core compliance
            # layer signs it with Ed25519 (make_worm_record) for
            # non-repudiation. The ~500-byte signed record is what the WORM
            # stores (NOT the full O(N) certificate).
            # Fallbacks: 1.9.1 witness search_audited, then plain search.
            # ----------------------------------------------------------
            qc = np.ascontiguousarray(q, dtype=np.float32)
            k_eff = int(k) if k is not None else int(self.config.final_k)

            if hasattr(self._engine, "search_with_commitment"):
                # 1.9.2+ : signed commitment (the production audit trail).
                # The commitment MUST share the SAME audit_id as the
                # government metadata (the one the API returns), so WORM
                # lookups by audit_id resolve the record. The metadata
                # audit_id is the single source of truth — no internal
                # uuid drift between metadata and commitment.
                from winnex_tracer.core import make_worm_record
                rec = make_worm_record(
                    self._engine, qc, k=k_eff,
                    max_sample=min(int(self.config.max_audit_records_per_query), 200),
                    query_vector_bytes=qc.tobytes(),
                    audit_id=metadata.audit_id)
                result.indices = list(rec["indices"])
                result.bound_pairs = int(rec["bound_pairs"])
                result.bound_violations = int(rec["bound_violations"])
                result.violations_64d = int(rec["bound_violations"])
                result.violations_128d = int(rec["bound_violations"])
                result.total_excluded = int(rec["total_provably_excluded"])
                result.latency_ms = float(rec.get("_latency_ms", 0.0))
                result.engine_used = (
                    "winnex-madhava (search_with_commitment + Ed25519)")
                result.commitment = rec
                for s in rec.get("sampled_records", []):
                    result.audit.append(GovAuditRecord(
                        doc_id=int(s["doc_id"]),
                        true_cosine=0.0,
                        upper_bound=float(s["upper_bound"]),
                        threshold=float(rec["global_threshold"]),
                        excluded=bool(s["excluded"]),
                        stage="stage1",
                        verdict="PROVABLY_EXCLUDED" if s["excluded"] else "SURVIVED",
                    ))
            elif hasattr(self._engine, "search_audited"):
                # 1.9.1+ : the witness certificate (full, legacy).
                m_result = self._engine.search_audited(
                    qc, k=k_eff, max_audit_records=int(
                        self.config.max_audit_records_per_query))
                result.indices = list(m_result["indices"])
                result.latency_ms = float(m_result["latency_ms"])
                result.engine_used = "winnex-madhava (pip, C++20 core, search_audited)"
                result.violations_64d = int(m_result["bound_violations"])
                result.violations_128d = int(m_result["bound_violations"])
                result.bound_pairs = int(m_result["bound_pairs"])
                result.total_excluded = int(m_result["audit_excluded"])
                for rec in m_result["audit"]:
                    result.audit.append(GovAuditRecord(
                        doc_id=int(rec["doc_id"]),
                        true_cosine=float(rec["true_cosine"]),
                        upper_bound=float(rec["upper_bound"]),
                        threshold=float(rec["threshold"]),
                        excluded=bool(rec["excluded"]),
                        stage=str(rec["stage"]),
                        verdict="PROVABLY_EXCLUDED" if rec["excluded"] else "SURVIVED",
                    ))
            else:
                # < 1.9.1 : plain search + aggregate proof metric.
                m_result = self._engine.search(qc)
                result.indices = list(m_result.indices)
                result.latency_ms = m_result.latency_ms
                result.engine_used = "winnex-madhava (pip, C++20 core)"
                result.violations_64d = m_result.bound_violations
                result.violations_128d = m_result.bound_violations
                result.bound_pairs = m_result.bound_pairs
                result.total_excluded = max(
                    0, m_result.bound_pairs - m_result.k2 - m_result.k3)

        else:
            # ----------------------------------------------------------
            # Built-in fallback (naive)
            # ----------------------------------------------------------
            if self._N == 0:
                raise RuntimeError("No vectors built. Call build() first.")

            # Naive exact search + fake audit trail
            scores = self._vectors @ q
            top_k = np.argsort(scores)[-k:][::-1]
            result.indices = [int(idx) for idx in top_k]
            result.scores = [float(scores[idx]) for idx in top_k]
            result.engine_used = "built-in (fallback)"

            threshold = result.scores[-1] if result.scores else 0.0
            for i in range(min(self.config.max_audit_records_per_query, self._N)):
                ub = max(0, scores[i] - 0.05)
                if ub >= threshold - 0.15:
                    result.audit.append(GovAuditRecord(
                        doc_id=i,
                        true_cosine=float(scores[i]),
                        upper_bound=float(ub),
                        threshold=threshold,
                        excluded=ub < threshold,
                        stage="stage1" if ub < threshold else "survived",
                        verdict="PROVABLY_EXCLUDED" if ub < threshold else "SURVIVED",
                    ))

            result.total_excluded = sum(1 for r in result.audit if r.excluded)
            result.latency_ms = (time.time() - t0) * 1000

        # Ensure latency is set even if C++/Python already did
        if result.latency_ms == 0.0:
            result.latency_ms = (time.time() - t0) * 1000

        logger.info(
            f"search_with_audit: {result.engine_used} | "
            f"{result.latency_ms:.2f}ms | "
            f"top-{len(result.indices)} | "
            f"{result.total_excluded} excluded | "
            f"{result.violations_64d}/{result.violations_128d} violations"
        )
        return result
