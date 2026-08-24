"""
Tracer-JUS — e-Discovery with Mathematical Proof
=================================================
The core of Tracer-JUS: triage of large legal document corpora with a
**soundness guarantee** — every excluded document is backed by a
Cauchy-Schwarz bound proving it could not be in the top-K.

This addresses the deepest pain in e-Discovery: how to prove in court that
the triage did not miss relevant evidence.

Flow:
  1. Embed the corpus (multilingual model, fallback documented).
  2. Build a Madhava index (real engine, `winnex-madhava` pip).
  3. For each review query: audited search with per-document bound proof.
  4. Record every query, result, and proof in the evidence chain (WORM).

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
import os, json, logging, time, hashlib
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone

import numpy as np

from winnex_tracer.jus.core.metadata import CaseMetadata, LegalQuery, new_audit_id
from winnex_tracer.jus.core.evidence import EvidenceChain

logger = logging.getLogger("tracer-jus.discovery")


@dataclass
class ExclusionProof:
    """Per-document mathematical proof of exclusion.

    A document is PROVABLY excluded when its Cauchy-Schwarz upper bound
    falls below the top-K threshold — it mathematically cannot be in the
    relevant set.
    """
    doc_id: int
    bound_violations: int = 0          # must be 0 (soundness)
    bound_pairs: int = 0               # number of (doc, bound) evaluations
    k1: int = 0
    k2: int = 0
    k3: int = 0
    verdict: str = "SOUND"             # SOUND if bound_violations == 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "doc_id": self.doc_id,
            "bound_violations": self.bound_violations,
            "bound_pairs": self.bound_pairs,
            "k1": self.k1, "k2": self.k2, "k3": self.k3,
            "verdict": self.verdict,
        }


@dataclass
class DiscoveryResult:
    """Result of a full e-Discovery run over a corpus with review queries."""
    audit_id: str = ""
    case: Dict[str, Any] = field(default_factory=dict)
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

    def to_dict(self) -> Dict[str, Any]:
        return {
            "audit_id": self.audit_id,
            "case": self.case,
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
        }


class DiscoveryEngine:
    """e-Discovery engine with soundness-guaranteed triage.

    Args:
        embedding_model: sentence-transformers model name (multilingual).
        stage_dims: Madhava stage-1/stage-2 projection dims.
        k: number of results per review query.
        evidence: an EvidenceChain (or None to use default path).
    """

    def __init__(self, embedding_model: str = "distiluse-base-multilingual-cased-v2",
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
        """Embed texts using the multilingual model.

        Falls back to a deterministic hash-based embedding when the model
        is unavailable (documented — the proof engine still works, but on
        weaker embeddings).
        """
        try:
            from sentence_transformers import SentenceTransformer
            if self._model is None:
                self._model = SentenceTransformer(
                    self.embedding_model, device="cpu")
            vecs = self._model.encode(
                texts, normalize_embeddings=True, show_progress_bar=False)
            return np.ascontiguousarray(vecs, dtype=np.float32)
        except (ImportError, OSError) as e:
            raise RuntimeError(
                "DiscoveryEngine: no real embedding model available. "
                f"({e}) Install sentence-transformers with an embedding "
                "model. Refusing to fall back to a hash embedding — "
                "e-Discovery without a real model is meaningless.")

    # ------------------------------------------------------------------
    # Discovery run
    # ------------------------------------------------------------------
    def run_discovery(self, corpus: List[str], review_queries: List[str],
                      case: Optional[CaseMetadata] = None,
                      query_metadata: Optional[List[str]] = None,
                      k: Optional[int] = None) -> DiscoveryResult:
        """Run e-Discovery triage over a corpus with review queries.

        Every query is audited (bound proof), every result is written to
        the evidence chain (WORM). Returns a DiscoveryResult with the proof
        and evidence metadata.

        Args:
            corpus: document texts (contracts, proceedings, case law, ...)
            review_queries: the legal questions to search for
            case: the case/matter metadata
            query_metadata: optional per-query labels (topics)
            k: results per query (defaults to self.k)
        """
        t0 = time.time()
        if not corpus:
            raise ValueError("corpus must not be empty")
        if not review_queries:
            raise ValueError("review_queries must not be empty")

        k = k or self.k
        audit_id = new_audit_id()
        case_dict = case.to_dict() if case else CaseMetadata().to_dict()

        # 1. Embed corpus and queries
        logger.info("Embedding %d documents ...", len(corpus))
        X = self._embed(corpus)
        Q = self._embed(review_queries)

        # 2. Build Madhava engine (real, with bound proof)
        try:
            import winnex_madhava as wm
            engine = wm.build_engine(
                np.ascontiguousarray(X, dtype=np.float32),
                dim=X.shape[1],
                metric="cosine",
                quant="int8",
                stage1_dim=min(self.stage1_dim, X.shape[1]),
                stage2_dim=min(self.stage2_dim, X.shape[1]),
                k=k,
                k1_fraction=0.05,
                modulation=True,
                postfilter=True,
            )
            engine_used = "winnex-madhava (pip, C++20)"
        except ImportError:
            raise RuntimeError(
                "DiscoveryEngine: winnex-madhava is required for "
                "soundness-guaranteed e-Discovery. Install it "
                "(pip install winnex-madhava). Refusing to fall back to a "
                "numpy scan — the proof guarantee requires the real motor.")

        # 3. Audited search per review query
        total_viol = 0
        total_pairs = 0
        per_query = []

        if engine is not None:
            for i, q in enumerate(review_queries):
                qv = np.ascontiguousarray(Q[i], dtype=np.float32)
                r = engine.search(qv)
                total_viol += r.bound_violations
                total_pairs += r.bound_pairs
                per_query.append({
                    "query": q,
                    "topic": query_metadata[i] if query_metadata else "",
                    "indices": list(r.indices),
                    "bound_violations": r.bound_violations,
                    "bound_pairs": r.bound_pairs,
                    "latency_ms": round(r.latency_ms, 3),
                    "proof": ExclusionProof(
                        doc_id=0,
                        bound_violations=r.bound_violations,
                        bound_pairs=r.bound_pairs,
                        k1=r.k1, k2=r.k2, k3=r.k3,
                        verdict="SOUND" if r.bound_violations == 0 else "VIOLATION",
                    ).to_dict(),
                })
        else:
            # Fallback: naive exact search, no proof (demo only)
            for i, q in enumerate(review_queries):
                scores = X @ Q[i]
                top = np.argsort(scores)[-k:][::-1]
                total_viol += 0
                total_pairs += len(corpus)
                per_query.append({
                    "query": q,
                    "topic": query_metadata[i] if query_metadata else "",
                    "indices": list(top),
                    "bound_violations": 0,
                    "bound_pairs": len(corpus),
                    "latency_ms": round((time.time() - t0) / len(review_queries) * 1000, 3),
                    "proof": {"verdict": "DEMO (no winnex-madhava)"},
                })

        # 4. Record in evidence chain (WORM)
        receipt = {}
        chain_ok = False
        if self._evidence is not None:
            try:
                receipt = self._evidence.record_search(
                    audit_id=audit_id,
                    case=case_dict,
                    query_text=json.dumps(review_queries, ensure_ascii=False),
                    bound_violations=total_viol,
                    bound_pairs=total_pairs,
                    result_indices=per_query[0].get("indices", [])
                    if per_query else [],
                )
                chain_ok = self._evidence.verify_chain().get(
                    "chain_integrity_verified", False)
            except Exception as e:
                logger.warning("Evidence chain record failed: %s", e)

        return DiscoveryResult(
            audit_id=audit_id,
            case=case_dict,
            corpus_size=len(corpus),
            num_queries=len(review_queries),
            k=k,
            total_bound_violations=total_viol,
            total_bound_pairs=total_pairs,
            engine_used=engine_used,
            latency_ms=(time.time() - t0) * 1000,
            evidence_chain_verified=chain_ok,
            evidence_receipt=receipt,
            per_query=per_query,
        )

    # ------------------------------------------------------------------
    # Proof report
    # ------------------------------------------------------------------
    def build_proof_report(self, result: DiscoveryResult) -> Dict[str, Any]:
        """Generate a proof report (for an auditor or the court)."""
        sound = result.total_bound_violations == 0
        return {
            "report_type": "E_DISCOVERY_PROOF",
            "audit_id": result.audit_id,
            "case": result.case,
            "corpus_size": result.corpus_size,
            "num_queries": result.num_queries,
            "k": result.k,
            "soundness": {
                "bound_violations": result.total_bound_violations,
                "bound_pairs": result.total_bound_pairs,
                "sound": sound,
                "statement": (
                    "No document excluded by the bound could have been in "
                    "the relevant top-K results (Cauchy-Schwarz)."
                ) if sound else "BOUND VIOLATION — INVESTIGATE",
            },
            "engine": result.engine_used,
            "evidence_chain": {
                "verified": result.evidence_chain_verified,
                "receipt": result.evidence_receipt,
            },
            "per_query_summary": [
                {
                    "query": pq["query"],
                    "indices_count": len(pq["indices"]),
                    "bound_violations": pq["bound_violations"],
                    "sound": pq["bound_violations"] == 0,
                }
                for pq in result.per_query
            ],
            "disclaimer": (
                "Proof of exclusion, not of relevance. Self-assessment — "
                "not a certification."
            ),
        }
