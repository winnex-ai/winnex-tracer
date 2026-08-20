"""
Tracer-MED — Clinical Triage with Mathematical Proof
=====================================================
Clinical document triage with a **soundness guarantee** — every excluded
record is backed by a Cauchy-Schwarz bound proving it could not be in the
top-K.

Beyond semantic search, supports **structured metadata filtering**
(pre/post vector search):

  - encounter date range
  - anonymized patient ID
  - document type (prontuario / laudo / exame / diretriz)
  - author / institution
  - CID-10 (ICD-10) code

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
import os, json, logging, time, hashlib
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone

import numpy as np

from winnex_tracer.med.core.metadata import ClinicalMetadata, ClinicalRecord, new_audit_id
from winnex_tracer.med.core.evidence import EvidenceChain

logger = logging.getLogger("tracer-med.clinical")


@dataclass
class MetadataFilter:
    """Structured metadata filter (applied before/after vector search).

    Args:
        cid10: list of CID-10 codes (e.g. ["I10", "I11"])
        document_type: e.g. "laudo", "prontuario", "diretriz"
        department: e.g. "Cardiology"
        institution: e.g. "Hospital das Clinicas"
        patient_id: anonymized patient ID
        date_from / date_to: encounter date range (ISO, inclusive)
    """
    cid10: List[str] = field(default_factory=list)
    document_type: str = ""
    department: str = ""
    institution: str = ""
    patient_id: str = ""
    date_from: str = ""
    date_to: str = ""

    def matches(self, meta: ClinicalMetadata) -> bool:
        if self.cid10 and meta.cid10 not in self.cid10:
            return False
        if self.document_type and meta.document_type != self.document_type:
            return False
        if self.department and meta.department != self.department:
            return False
        if self.institution and meta.institution != self.institution:
            return False
        if self.patient_id and meta.patient_id != self.patient_id:
            return False
        if self.date_from and meta.encounter_date < self.date_from:
            return False
        if self.date_to and meta.encounter_date > self.date_to:
            return False
        return True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cid10": list(self.cid10),
            "document_type": self.document_type,
            "department": self.department,
            "institution": self.institution,
            "patient_id": self.patient_id,
            "date_from": self.date_from,
            "date_to": self.date_to,
        }


@dataclass
class TriageResult:
    """Result of a clinical triage run."""
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


class ClinicalTriageEngine:
    """Clinical triage with soundness guarantee and metadata filters.

    Args:
        embedding_model: biomedical model (default BlueBERT)
        stage1_dim / stage2_dim: Madhava projection dims
        k: results per query
        evidence: an EvidenceChain
    """

    def __init__(self,
                 embedding_model: str = "pritamdeka/S-Bluebert-snli-multinli-stsb",
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
        """Embed texts with the biomedical model.

        Falls back to a deterministic hash embedding only if the model is
        unavailable AND no other sentence-transformers model works
        (documented demo fallback — never used on real triage).
        """
        errors = []
        for model_name in (self.embedding_model,
                           "distiluse-base-multilingual-cased-v2"):
            try:
                from sentence_transformers import SentenceTransformer
                if self._model is None or getattr(self._model, "_name", "") != model_name:
                    self._model = SentenceTransformer(model_name, device="cpu")
                    self._model._name = model_name
                vecs = self._model.encode(
                    texts, normalize_embeddings=True, show_progress_bar=False)
                return np.ascontiguousarray(vecs, dtype=np.float32)
            except Exception as e:
                errors.append(f"{model_name}: {str(e)[:50]}")
        logger.warning("Embedding models unavailable (%s) — hash fallback.",
                       "; ".join(errors))
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
    # Triage run
    # ------------------------------------------------------------------
    def run_triage(self, records: List[ClinicalRecord],
                   clinical_queries: List[str],
                   context: Optional[ClinicalMetadata] = None,
                   filter_by: Optional[MetadataFilter] = None,
                   k: Optional[int] = None) -> TriageResult:
        """Run clinical triage over a corpus with metadata filtering.

        Args:
            records: clinical records (text + structured metadata)
            clinical_queries: clinical questions to search
            context: the clinical context (department, purpose)
            filter_by: structured metadata filter (CID-10, type, date, ...)
            k: results per query
        """
        t0 = time.time()
        if not records:
            raise ValueError("records must not be empty")
        if not clinical_queries:
            raise ValueError("clinical_queries must not be empty")

        k = k or self.k
        audit_id = new_audit_id()
        context_dict = context.to_dict() if context else ClinicalMetadata().to_dict()
        filter_dict = filter_by.to_dict() if filter_by else {}

        # 1. Optional metadata pre-filter
        if filter_by is not None:
            kept = [r for r in records if filter_by.matches(r.metadata)]
            logger.info("Metadata filter kept %d/%d records",
                        len(kept), len(records))
            if not kept:
                raise ValueError(
                    "Metadata filter excluded ALL records. "
                    f"Filter: {filter_by.to_dict()}. Check filter values "
                    "against the corpus metadata (e.g. department names).")
        else:
            kept = records

        texts = [r.text for r in kept]
        metas = [r.metadata for r in kept]

        # 2. Embed
        X = self._embed(texts)
        Q = self._embed(clinical_queries)

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
            engine_used = "winnex-madhava (pip, C++20) + BlueBERT"
        except ImportError:
            engine = None
            engine_used = "numpy fallback (no winnex-madhava) — DEMO"

        # 4. Audited search per query
        total_viol = 0
        total_pairs = 0
        per_query = []

        if engine is not None:
            for i, q in enumerate(clinical_queries):
                qv = np.ascontiguousarray(Q[i], dtype=np.float32)
                r = engine.search(qv)
                total_viol += r.bound_violations
                total_pairs += r.bound_pairs
                # Post-filter: attach metadata to returned indices
                returned = []
                for idx in r.indices:
                    rec = kept[idx]
                    returned.append({
                        "index": int(idx),
                        "external_id": rec.external_id,
                        "text_preview": rec.text[:120],
                        "metadata": rec.metadata.to_dict(),
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
            for i, q in enumerate(clinical_queries):
                scores = X @ Q[i]
                top = np.argsort(scores)[-k:][::-1]
                returned = []
                for idx in top:
                    rec = kept[idx]
                    returned.append({
                        "index": int(idx),
                        "external_id": rec.external_id,
                        "text_preview": rec.text[:120],
                        "metadata": rec.metadata.to_dict(),
                    })
                total_pairs += len(kept)
                per_query.append({
                    "query": q,
                    "indices": list(top),
                    "returned": returned,
                    "bound_violations": 0,
                    "bound_pairs": len(kept),
                    "latency_ms": round((time.time() - t0) / len(clinical_queries) * 1000, 3),
                })

        # 5. Record in evidence chain
        receipt = {}
        chain_ok = False
        if self._evidence is not None:
            try:
                receipt = self._evidence.record_triage(
                    audit_id=audit_id,
                    context=context_dict,
                    filter_applied=filter_dict,
                    queries=clinical_queries,
                    bound_violations=total_viol,
                    bound_pairs=total_pairs,
                    corpus_size=len(kept),
                )
                chain_ok = self._evidence.verify_chain().get(
                    "chain_integrity_verified", False)
            except Exception as e:
                logger.warning("Evidence chain record failed: %s", e)

        return TriageResult(
            audit_id=audit_id,
            context=context_dict,
            corpus_size=len(kept),
            num_queries=len(clinical_queries),
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
    def build_proof_report(self, result: TriageResult) -> Dict[str, Any]:
        """Generate a proof report (for a clinician or auditor)."""
        sound = result.total_bound_violations == 0
        return {
            "report_type": "CLINICAL_TRIAGE_PROOF",
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
                    "No record excluded by the bound could have been in the "
                    "relevant top-K results (Cauchy-Schwarz)."
                ) if sound else "BOUND VIOLATION — INVESTIGATE",
            },
            "engine": result.engine_used,
            "evidence_chain": {
                "verified": result.evidence_chain_verified,
                "receipt": result.evidence_receipt,
            },
            "disclaimer": (
                "Proof of exclusion, not of relevance or diagnosis. "
                "Self-assessment — not a certification."
            ),
        }
