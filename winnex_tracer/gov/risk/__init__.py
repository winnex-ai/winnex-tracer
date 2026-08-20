"""
Tracer-Risk — Differential Risk Geometry Engine
=================================================
Uses Madhava's data geometry core to detect risk displacement via
the **derivative of cosine similarity across projection dimensions**.

Key insight from differential geometry:
  d/d_d cos(P_d(E), P_d(O))

  - DIRECT causal link:   cosine is STABLE across dimensions
    (relationship is structural, captured at any resolution)

  - INDIRECT causal link: cosine GROWS with dimensions
    (indirect paths need higher-dimensional subspace to manifest)

  - DISPLACEMENT = derivative at low dimension (d=8) minus slope
    as dimension increases — the "acceleration" of similarity.

This replaces the earlier Pythagorean residual approach, which was
dominated by exposure self-norm and failed benchmarks (Jul 2026).

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
import json, os, time, hashlib, logging
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime, timezone
from pathlib import Path
import math

logger = logging.getLogger("tracer-risk")

_HAS_MADHAVA_MATH = False
try:
    from winnex_production.core import OrthogonalProjection
    _HAS_MADHAVA_MATH = True
except ImportError:
    pass


@dataclass
class RiskConfig:
    """Tracer-Risk configuration."""
    # Derivative profile dimensions to test
    profile_dims: List[int] = field(default_factory=lambda: [4, 8, 16, 32, 64, 128])
    random_seed: int = 42

    # Thresholds
    displacement_threshold: float = 0.10  # min derivative gap to flag
    alert_threshold_amber: float = 0.20
    alert_threshold_red: float = 0.35

    # Analysis mode
    default_mode: str = "batch"
    embedding_dim: int = 128

    @classmethod
    def from_env(cls) -> "RiskConfig":
        c = cls()
        if v := os.environ.get("WINNEX_RISK_PROFILE_DIMS"):
            c.profile_dims = [int(x) for x in v.split(",")]
        if v := os.environ.get("WINNEX_RISK_DISPLACEMENT_THRESHOLD"):
            c.displacement_threshold = float(v)
        if v := os.environ.get("WINNEX_RISK_AMBER_THRESHOLD"):
            c.alert_threshold_amber = float(v)
        if v := os.environ.get("WINNEX_RISK_RED_THRESHOLD"):
            c.alert_threshold_red = float(v)
        if v := os.environ.get("WINNEX_RISK_EMBEDDING_DIM"):
            c.embedding_dim = int(v)
        return c


# -----------------------------------------------------------------------
# Data structures
# -----------------------------------------------------------------------

@dataclass
class ExposureDimension:
    id: str
    name: str
    category: str
    vector: List[float]
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class OutcomeDimension:
    id: str
    name: str
    category: str
    vector: List[float]
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class DerivativeProfile:
    """The derivative profile of an exposure-outcome pair across dimensions."""
    exposure_id: str
    exposure_name: str
    outcome_id: str
    outcome_name: str

    # Cosine similarity at each projection dimension
    cos_at_dim: Dict[int, float] = field(default_factory=dict)

    # Direct cosine (no projection)
    direct_cosine: float = 0.0

    # Derivative metrics
    dcos_ddim_low: float = 0.0     # derivative at low dimensions (4->8)
    dcos_ddim_high: float = 0.0    # derivative at high dimensions (64->128)
    dcos_ddim_slope: float = 0.0   # linear fit slope across all dims
    curvature: float = 0.0          # acceleration: high_deriv - low_deriv

    # Displacement: positive curvature means similarity ACCELERATES
    # with more dimensions -> indirect paths being captured
    displacement_score: float = 0.0

    significance: str = "low"

    def to_dict(self) -> dict:
        return {
            "exposure_id": self.exposure_id,
            "exposure_name": self.exposure_name,
            "outcome_id": self.outcome_id,
            "outcome_name": self.outcome_name,
            "direct_cosine": round(self.direct_cosine, 6),
            "cos_at_dim": {str(k): round(v, 6) for k, v in self.cos_at_dim.items()},
            "dcos_ddim_low": round(self.dcos_ddim_low, 6),
            "dcos_ddim_high": round(self.dcos_ddim_high, 6),
            "curvature": round(self.curvature, 6),
            "displacement_score": round(self.displacement_score, 6),
            "significance": self.significance,
        }


@dataclass
class RiskDisplacement:
    exposure_id: str
    exposure_name: str
    outcome_id: str
    outcome_name: str
    displacement_score: float
    curvature: float
    direct_cosine: float
    significance: str
    profile: Optional[DerivativeProfile] = None

    def to_dict(self) -> dict:
        return {
            "exposure_id": self.exposure_id,
            "exposure_name": self.exposure_name,
            "outcome_id": self.outcome_id,
            "outcome_name": self.outcome_name,
            "displacement_score": round(self.displacement_score, 6),
            "curvature": round(self.curvature, 6),
            "direct_cosine": round(self.direct_cosine, 6),
            "significance": self.significance,
        }


@dataclass
class RiskAlert:
    alert_id: str
    timestamp: str
    severity: str
    exposure_id: str
    exposure_name: str
    outcome_id: str
    outcome_name: str
    displacement_score: float
    message: str
    profile_summary: str = ""

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "severity": self.severity,
            "exposure_id": self.exposure_id,
            "exposure_name": self.exposure_name,
            "outcome_id": self.outcome_id,
            "outcome_name": self.outcome_name,
            "displacement_score": round(self.displacement_score, 6),
            "message": self.message,
        }


@dataclass
class RiskAnalysisResult:
    exposure_count: int = 0
    outcome_count: int = 0
    profiles: List[DerivativeProfile] = field(default_factory=list)
    displacements: List[RiskDisplacement] = field(default_factory=list)
    alerts: List[RiskAlert] = field(default_factory=list)
    latency_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            "exposures": self.exposure_count,
            "outcomes": self.outcome_count,
            "pairs_analyzed": self.exposure_count * self.outcome_count,
            "displacements_detected": len(self.displacements),
            "alerts_generated": len(self.alerts),
            "latency_ms": round(self.latency_ms, 3),
        }


# -----------------------------------------------------------------------
# Projection helper (built-in fallback)
# -----------------------------------------------------------------------

class _BuiltinProjection:
    def __init__(self, d_in: int, d_out: int, seed: int = 42):
        import numpy as np
        rng = np.random.RandomState(seed)
        Q, _ = np.linalg.qr(rng.randn(d_in, d_out))
        self.P = Q[:, :d_out].T.astype(np.float32)
    def project_vector(self, v):
        return v @ self.P.T


# -----------------------------------------------------------------------
# Risk Engine
# -----------------------------------------------------------------------

class RiskEngine:
    """Differential risk geometry engine.

    Measures **d/d_dim cos(P_d(E), P_d(O))** across multiple projection
    dimensions to detect risk displacement.

    Direct causal links show stable cosine across dimensions.
    Indirect links show cosine GROWING with dimensions as indirect
    paths are captured by higher-dimensional subspaces.
    """

    def __init__(self, config: Optional[RiskConfig] = None):
        self.config = config or RiskConfig()
        self._exposures: Dict[str, ExposureDimension] = {}
        self._outcomes: Dict[str, OutcomeDimension] = {}
        self._projections: Dict[int, Any] = {}
        self._built: bool = False
        self._dim = 0

    def add_exposure(self, e: ExposureDimension):
        self._exposures[e.id] = e

    def add_outcome(self, o: OutcomeDimension):
        self._outcomes[o.id] = o

    def add_exposures_from_dict(self, data: List[Dict]):
        for d in data:
            self.add_exposure(ExposureDimension(
                id=d["id"], name=d["name"],
                category=d.get("category", "unknown"),
                vector=d["vector"],
                metadata=d.get("metadata", {})))

    def add_outcomes_from_dict(self, data: List[Dict]):
        for d in data:
            self.add_outcome(OutcomeDimension(
                id=d["id"], name=d["name"],
                category=d.get("category", "unknown"),
                vector=d["vector"],
                metadata=d.get("metadata", {})))

    def load_exposures_from_json(self, path: str):
        with open(path) as f:
            self.add_exposures_from_dict(json.load(f))

    def load_outcomes_from_json(self, path: str):
        with open(path) as f:
            self.add_outcomes_from_dict(json.load(f))

    def build(self):
        """Build projections for each dimension in profile."""
        if not self._exposures:
            raise ValueError("No exposures registered.")
        if not self._outcomes:
            raise ValueError("No outcomes registered.")

        import numpy as np
        sample = list(self._exposures.values())[0].vector
        self._dim = len(sample)

        # Determine if Madhava is available
        proj_cls = OrthogonalProjection if _HAS_MADHAVA_MATH else _BuiltinProjection

        for d in self.config.profile_dims:
            if d <= self._dim:
                self._projections[d] = proj_cls(self._dim, min(d, self._dim),
                                                 self.config.random_seed)

        self._built = True
        logger.info(f"Tracer-Risk: {len(self._projections)} projections built "
                    f"({min(self.config.profile_dims)}-{max(self.config.profile_dims)}D) "
                    f"for {len(self._exposures)} exposures x {len(self._outcomes)} outcomes")

    # -------------------------------------------------------------------
    # Core: derivative profile for a single pair
    # -------------------------------------------------------------------

    def _profile_pair(self, exp: ExposureDimension,
                      outc: OutcomeDimension) -> DerivativeProfile:
        """Compute derivative profile for one exposure-outcome pair.

        Projects both vectors at each dimension d and records
        cos(P_d(E), P_d(O)). The shape of cos(d) reveals:
          - stable = direct (flat derivative)
          - growing = indirect (positive derivative)

        The curvature (d²cos/dd²) is the displacement score.
        """
        import numpy as np
        e_vec = np.array(exp.vector, dtype=np.float32)
        o_vec = np.array(outc.vector, dtype=np.float32)

        e_norm = np.linalg.norm(e_vec) or 1e-10
        o_norm = np.linalg.norm(o_vec) or 1e-10
        direct_cos = float(np.dot(e_vec, o_vec) / (e_norm * o_norm))

        profile = DerivativeProfile(
            exposure_id=exp.id, exposure_name=exp.name,
            outcome_id=outc.id, outcome_name=outc.name,
            direct_cosine=direct_cos,
        )

        dims = sorted(d for d in self.config.profile_dims if d in self._projections)
        cos_values = []

        for d in dims:
            proj = self._projections[d]
            pe = proj.project_vector(e_vec)
            po = proj.project_vector(o_vec)
            pn_e = np.linalg.norm(pe) or 1e-10
            pn_o = np.linalg.norm(po) or 1e-10
            c = float(np.dot(pe, po) / (pn_e * pn_o))
            profile.cos_at_dim[d] = c
            cos_values.append(c)

        # --- Derivative analysis ---
        n = len(dims)
        if n >= 3:
            # Low-dim derivative: first two points
            d1, d2 = dims[0], dims[1]
            c1, c2 = cos_values[0], cos_values[1]
            profile.dcos_ddim_low = (c2 - c1) / max(d2 - d1, 1)

            # High-dim derivative: last two points
            d1, d2 = dims[-2], dims[-1]
            c1, c2 = cos_values[-2], cos_values[-1]
            profile.dcos_ddim_high = (c2 - c1) / max(d2 - d1, 1)

            # Linear fit slope across all dims
            xs = np.array(dims, dtype=float)
            ys = np.array(cos_values, dtype=float)
            if np.std(xs) > 0 and np.std(ys) > 0:
                A = np.vstack([xs, np.ones(n)]).T
                slope, _ = np.linalg.lstsq(A, ys, rcond=None)[0]
                profile.dcos_ddim_slope = float(slope)

            # Curvature = acceleration of similarity
            profile.curvature = profile.dcos_ddim_high - profile.dcos_ddim_low

        # Displacement score: positive curvature means similarity
        # accelerates with dimensions -> indirect paths
        if n >= 3:
            profile.displacement_score = max(0.0, profile.curvature)
        else:
            profile.displacement_score = 0.0

        # Significance
        if profile.displacement_score >= self.config.alert_threshold_red:
            profile.significance = "critical"
        elif profile.displacement_score >= self.config.alert_threshold_amber:
            profile.significance = "high"
        elif profile.displacement_score >= self.config.displacement_threshold:
            profile.significance = "medium"

        return profile

    # -------------------------------------------------------------------
    # Main analysis
    # -------------------------------------------------------------------

    def analyze(self) -> RiskAnalysisResult:
        """Run full differential risk analysis."""
        result = RiskAnalysisResult()
        t0 = time.time()

        if not self._built:
            self.build()

        result.exposure_count = len(self._exposures)
        result.outcome_count = len(self._outcomes)

        # Compute derivative profile for ALL pairs
        for exp in self._exposures.values():
            for outc in self._outcomes.values():
                profile = self._profile_pair(exp, outc)
                result.profiles.append(profile)

                # Flag significant displacements
                if profile.significance in ("medium", "high", "critical"):
                    result.displacements.append(RiskDisplacement(
                        exposure_id=profile.exposure_id,
                        exposure_name=profile.exposure_name,
                        outcome_id=profile.outcome_id,
                        outcome_name=profile.outcome_name,
                        displacement_score=profile.displacement_score,
                        curvature=profile.curvature,
                        direct_cosine=profile.direct_cosine,
                        significance=profile.significance,
                        profile=profile,
                    ))
                    # Generate alerts for high/critical
                    if profile.significance in ("high", "critical"):
                        severity = "red" if profile.significance == "critical" else "amber"
                        alert_id = hashlib.sha3_256(
                            f"{profile.exposure_id}:{profile.outcome_id}:{time.time()}".encode()
                        ).hexdigest()[:16]
                        result.alerts.append(RiskAlert(
                            alert_id=alert_id,
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            severity=severity,
                            exposure_id=profile.exposure_id,
                            exposure_name=profile.exposure_name,
                            outcome_id=profile.outcome_id,
                            outcome_name=profile.outcome_name,
                            displacement_score=profile.displacement_score,
                            message=(
                                f"Risk displacement: {profile.exposure_name} -> "
                                f"{profile.outcome_name} "
                                f"(curvature={profile.curvature:.3f}, "
                                f"cos accelerates across dims)"
                            ),
                        ))

        result.latency_ms = (time.time() - t0) * 1000
        logger.info(
            f"analyze: {result.exposure_count}x{result.outcome_count} pairs | "
            f"{len(result.displacements)} displacements | "
            f"{len(result.alerts)} alerts | {result.latency_ms:.1f}ms")
        return result

    # -------------------------------------------------------------------
    # Single pair analysis
    # -------------------------------------------------------------------

    def analyze_pair(self, exposure_id: str, outcome_id: str) -> Dict:
        """Analyze a single exposure-outcome pair."""
        if not self._built:
            self.build()
        if exposure_id not in self._exposures:
            raise KeyError(f"Exposure '{exposure_id}' not found")
        if outcome_id not in self._outcomes:
            raise KeyError(f"Outcome '{outcome_id}' not found")

        profile = self._profile_pair(
            self._exposures[exposure_id],
            self._outcomes[outcome_id],
        )
        return profile.to_dict()
