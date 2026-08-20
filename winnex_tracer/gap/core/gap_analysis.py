"""
Tracer-GAP — Gap Identification with Mathematical Proof
========================================================
Financial gap analysis with a **soundness guarantee** — every excluded
document is backed by a Cauchy-Schwarz bound proving it could not be in the
top-K.

Gap identification: given a set of financial documents (risk factors,
MD&A, disclosures, policies) and gap queries (unhedged exposure, compliance
gap, market risk), Tracer-GAP finds the relevant gaps with proof that none
was missed, and structured metadata filters (sector, instrument type,
period, CIK, risk category).

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
import os, json, logging, time, hashlib
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from datetime import datetime, timezone

import numpy as np

from winnex_tracer.gap.core.metadata import FinancialMetadata, FinancialRecord, new_audit_id
from winnex_tracer.gap.core.evidence import EvidenceChain

logger = logging.getLogger("tracer-gap.gap")


@dataclass
class MetadataFilter:
    """Structured financial metadata filter."""
    sector: str = ""
    instrument_type: str = ""
    cik: str = ""
    company: str = ""
    period: str = ""
    risk_category: str = ""

    def matches(self, meta: FinancialMetadata) -> bool:
        if self.sector and meta.sector != self.sector:
            return False
        if self.instrument_type and meta.instrument_type != self.instrument_type:
            return False
        if self.cik and meta.cik != self.cik:
            return False
        if self.company and meta.company != self.company:
            return False
        if self.period and meta.period != self.period:
            return False
        if self.risk_category and meta.risk_category != self.risk_category:
            return False
        return True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sector": self.sector,
            "instrument_type": self.instrument_type,
            "cik": self.cik,
            "company": self.company,
            "period": self.period,
            "risk_category": self.risk_category,
        }


@dataclass
class GapResult:
    """Result of a gap-analysis run."""
    audit_id: str = ""
    context: Dict[str, Any] = field(default_factory=dict)
    corpus_size: int = 0
    num_queries: int = 0
    k: int = 10
    total_bound_violations: int = 0
    total_bound_pairs: int = 0
    engine_used: str = ""
    latency_ms: float = 0.0
    evidence_chain_verified: bool = False
    evidence_receipt: Dict[str, Any] = field(default_factory=dict)
    per_query: List[Dict[str, Any]] = field(default_factory=list)
    filter_applied: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "audit_id": self.audit_id,
            "context": self.context,
            "corpus_size": self.corpus_size,
            "num_queries": self.num_queries,
            "k": self.k,
            "total_bound_violations": self.total_bound_violations,
            "total_bound_pairs": self.total_bound_pairs,
            "engine_used": self.engine_used,
            "latency_ms": round(self.latency_ms, 3),
            "evidence_chain_verified": self.evidence_chain_verified,
            "evidence_receipt": self.evidence_receipt,
            "per_query": self.per_query,
            "filter_applied": self.filter_applied,
        }


class GapAnalysisEngine:
    """Financial gap analysis with soundness guarantee and metadata filters."""

    def __init__(self,
                 embedding_model: str = "distiluse-base-multilingual-cased-v2",
                 stage1_dim: int = 64, stage2_dim: int = 128,
                 k: int = 10, evidence=None):
        self.embedding_model = embedding_model
        self.stage1_dim = stage1_dim
        self.stage2_dim = stage2_dim
        self.k = k
        self._evidence = evidence or EvidenceChain()
        self._model = None

    # ------------------------------------------------------------------
    # Embedding
    # ------------------------------------------------------------------
    def _embed(self, texts: List[str]) -> np.ndarray:
        """Embed texts (multilingual, financial language)."""
        try:
            from sentence_transformers import SentenceTransformer
            if self._model is None:
                self._model = SentenceTransformer(self.embedding_model,
                                                  device="cpu")
            vecs = self._model.encode(
                texts, normalize_embeddings=True, show_progress_bar=False)
            return np.ascontiguousarray(vecs, dtype=np.float32)
        except (ImportError, OSError) as e:
            logger.warning("Embedding model unavailable (%s) — hash fallback.",
                           e)
            return self._hash_embed(texts)

    @staticmethod
    def _hash_embed(texts: List[str], dim: int = 384) -> np.ndarray:
        """Deterministic hash-based embedding fallback (demo only)."""
        out = np.zeros((len(texts), dim), dtype=np.float32)
        for i, t in enumerate(texts):
            h = hashlib.sha3_256(t.encode()).digest()
            rng = np.random.RandomState(int.from_bytes(h[:8], "big"))
            out[i] = rng.randn(dim).astype(np.float32)
        norms = np.linalg.norm(out, axis=1, keepdims=True)
        out /= (norms + 1e-9)
        return np.ascontiguousarray(out, dtype=np.float32)

    # ------------------------------------------------------------------
    # Gap analysis run
    # ------------------------------------------------------------------
    def run_gap_analysis(self, records: List[FinancialRecord],
                         gap_queries: List[str],
                         context: Optional[FinancialMetadata] = None,
                         filter_by: Optional[MetadataFilter] = None,
                         k: Optional[int] = None) -> GapResult:
        """Run gap analysis over financial documents with proof.

        Args:
            records: financial records (text + structured metadata)
            gap_queries: the gap questions to search (unhedged exposure, ...)
            context: the analysis context (sector, period, instrument)
            filter_by: structured metadata filter
            k: results per query
        """
        t0 = time.time()
        if not records:
            raise ValueError("records must not be empty")
        if not gap_queries:
            raise ValueError("gap_queries must not be empty")

        k = k or self.k
        audit_id = new_audit_id()
        context_dict = context.to_dict() if context else FinancialMetadata().to_dict()
        filter_dict = filter_by.to_dict() if filter_by else {}

        # 1. Metadata pre-filter
        if filter_by is not None:
            kept = [r for r in records if filter_by.matches(r.metadata)]
            logger.info("Metadata filter kept %d/%d records",
                        len(kept), len(records))
            if not kept:
                raise ValueError(
                    "Metadata filter excluded ALL records. "
                    f"Filter: {filter_by.to_dict()}. Check values against "
                    "corpus metadata (e.g. sector names).")
        else:
            kept = records

        texts = [r.text for r in kept]
        metas = [r.metadata for r in kept]

        # 2. Embed
        X = self._embed(texts)
        Q = self._embed(gap_queries)

        # 3. Build Madhava engine (real, with bound proof)
        try:
            import winnex_madhava as wm
            engine = wm.build_engine(
                np.ascontiguousarray(X, dtype=np.float32),
                dim=X.shape[1], metric="cosine", quant="int8",
                stage1_dim=min(self.stage1_dim, X.shape[1]),
                stage2_dim=min(self.stage2_dim, X.shape[1]),
                k=k, k1_fraction=0.05, modulation=True, postfilter=True,
            )
            engine_used = "winnex-madhava (pip, C++20)"
        except ImportError:
            engine = None
            engine_used = "numpy fallback (no winnex-madhava) — DEMO"

        # 4. Audited search per query
        total_viol = 0
        total_pairs = 0
        per_query = []

        if engine is not None:
            for i, q in enumerate(gap_queries):
                qv = np.ascontiguousarray(Q[i], dtype=np.float32)
                r = engine.search(qv)
                total_viol += r.bound_violations
                total_pairs += r.bound_pairs
                returned = []
                for idx in r.indices:
                    rec = kept[idx]
                    returned.append({
                        "index": int(idx),
                        "external_id": rec.external_id,
                        "company": rec.metadata.company,
                        "sector": rec.metadata.sector,
                        "period": rec.metadata.period,
                        "text_preview": rec.text[:120],
                    })
                per_query.append({
                    "query": q,
                    "indices": list(r.indices),
                    "returned": returned,
                    "bound_violations": r.bound_violations,
                    "bound_pairs": r.bound_pairs,
                    "latency_ms": round(r.latency_ms, 3),
                })
        else:
            for i, q in enumerate(gap_queries):
                scores = X @ Q[i]
                top = np.argsort(scores)[-k:][::-1]
                returned = []
                for idx in top:
                    rec = kept[idx]
                    returned.append({
                        "index": int(idx),
                        "external_id": rec.external_id,
                        "company": rec.metadata.company,
                        "sector": rec.metadata.sector,
                        "period": rec.metadata.period,
                        "text_preview": rec.text[:120],
                    })
                total_pairs += len(kept)
                per_query.append({
                    "query": q,
                    "indices": list(top),
                    "returned": returned,
                    "bound_violations": 0,
                    "bound_pairs": len(kept),
                    "latency_ms": round((time.time() - t0) / len(gap_queries) * 1000, 3),
                })

        # 5. Record in evidence chain
        receipt = {}
        chain_ok = False
        if self._evidence is not None:
            try:
                receipt = self._evidence.record_gap_analysis(
                    audit_id=audit_id,
                    context=context_dict,
                    filter_applied=filter_dict,
                    queries=gap_queries,
                    bound_violations=total_viol,
                    bound_pairs=total_pairs,
                    corpus_size=len(kept),
                )
                chain_ok = self._evidence.verify_chain().get(
                    "chain_integrity_verified", False)
            except Exception as e:
                logger.warning("Evidence chain record failed: %s", e)

        return GapResult(
            audit_id=audit_id,
            context=context_dict,
            corpus_size=len(kept),
            num_queries=len(gap_queries),
            k=k,
            total_bound_violations=total_viol,
            total_bound_pairs=total_pairs,
            engine_used=engine_used,
            latency_ms=(time.time() - t0) * 1000,
            evidence_chain_verified=chain_ok,
            evidence_receipt=receipt,
            per_query=per_query,
            filter_applied=filter_dict,
        )

    # ------------------------------------------------------------------
    # Proof report
    # ------------------------------------------------------------------
    def build_proof_report(self, result: GapResult) -> Dict[str, Any]:
        """Generate a proof report (for a risk officer or auditor)."""
        sound = result.total_bound_violations == 0
        return {
            "report_type": "GAP_ANALYSIS_PROOF",
            "audit_id": result.audit_id,
            "context": result.context,
            "corpus_size": result.corpus_size,
            "num_queries": result.num_queries,
            "k": result.k,
            "filter_applied": result.filter_applied,
            "soundness": {
                "bound_violations": result.total_bound_violations,
                "bound_pairs": result.total_bound_pairs,
                "sound": sound,
                "statement": (
                    "No financial document excluded by the bound could have "
                    "been in the relevant top-K results (Cauchy-Schwarz)."
                ) if sound else "BOUND VIOLATION — INVESTIGATE",
            },
            "engine": result.engine_used,
            "evidence_chain": {
                "verified": result.evidence_chain_verified,
                "receipt": result.evidence_receipt,
            },
            "disclaimer": (
                "Proof of exclusion, not of relevance or investment advice. "
                "Self-assessment — not a certification."
            ),
        }
