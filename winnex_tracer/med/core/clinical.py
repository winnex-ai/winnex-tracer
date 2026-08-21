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
import os, json, logging, time, hashlib, threading
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

from winnex_tracer.med.core.metadata import ClinicalMetadata, ClinicalRecord, new_audit_id
from winnex_tracer.med.core.evidence import EvidenceChain

logger = logging.getLogger("tracer-med.clinical")


def _text_hash(text: str) -> str:
    """Short content-addressed key for an embedding cache entry.

    The hash of the text (not an arbitrary id) means the SAME corpus text is
    never re-embedded across triages — the Gargalo #3 fix. First 16 hex chars
    (64 bits) is sufficient for a cache key; collisions only re-embed once.
    """
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


class EmbeddingCache:
    """Persistent, content-addressed cache of text → embedding vector.

    Gargalo #3 remediation: the MED engine used to re-embed the WHOLE corpus
    on every run_triage. This cache persists vectors keyed by the text hash, so
    subsequent triages over the same corpus load vectors instead of calling the
    embedding model.

    Backend: a JSON file (``TRACER_MED_EMBEDDING_CACHE``) written atomically.
    The same interface (``get``/``put``) is what a PostgreSQL JSONB or Redis
    backend would implement — swap the two methods to persist elsewhere.
    """

    def __init__(self, path: Optional[str] = None):
        self.path = path or os.environ.get(
            "TRACER_MED_EMBEDDING_CACHE",
            "/var/lib/tracer-med/embedding_cache.json")
        self._lock = threading.Lock()
        self._cache: Dict[str, List[float]] = {}
        self._load()

    def _load(self) -> None:
        p = Path(self.path)
        if not p.exists():
            return
        try:
            with open(p) as f:
                data = json.load(f)
            self._cache = data.get("vectors", {})
        except Exception as e:
            logger.warning("EmbeddingCache: failed to load %s: %s", self.path, e)

    def _save(self) -> None:
        try:
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
            tmp = f"{self.path}.tmp"
            with open(tmp, "w") as f:
                json.dump({"vectors": self._cache}, f)
            os.replace(tmp, self.path)  # atomic
        except Exception as e:
            logger.warning("EmbeddingCache: failed to save %s: %s", self.path, e)

    def get(self, text: str) -> Optional[List[float]]:
        key = _text_hash(text)
        with self._lock:
            return self._cache.get(key)

    def put(self, text: str, vector: List[float]) -> None:
        key = _text_hash(text)
        with self._lock:
            self._cache[key] = [float(x) for x in vector]
        self._save()


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
                 k: int = 10, evidence=None,
                 embedding_cache: Optional[EmbeddingCache] = None):
        self.embedding_model = embedding_model
        self.stage1_dim = stage1_dim
        self.stage2_dim = stage2_dim
        self.k = k
        self._evidence = evidence or EvidenceChain()
        self._model = None
        # Content-addressed persistent cache (Gargalo #3). When set, corpus
        # vectors are loaded from the cache on repeat triages instead of
        # re-embedding the whole corpus.
        self._embedding_cache = embedding_cache or EmbeddingCache()

    # ------------------------------------------------------------------
    # Embedding
    # ------------------------------------------------------------------
    def _get_or_create_embeddings(self, texts: List[str]) -> np.ndarray:
        """Embed a batch, serving repeated texts from the persistent cache.

        Gargalo #3 fix: only texts whose hash is NOT in the cache are passed to
        the embedding model; their vectors are persisted for future triages.
        If the cache backend is unavailable the method falls back to embedding
        everything (no data loss, only the speed benefit is lost).
        """
        if self._embedding_cache is None:
            return self._embed(texts)
        vectors: List[Optional[List[float]]] = [None] * len(texts)
        to_embed: List[int] = []
        for i, t in enumerate(texts):
            cached = self._embedding_cache.get(t)
            if cached is not None:
                vectors[i] = cached
            else:
                to_embed.append(i)
        if to_embed:
            missing_texts = [texts[i] for i in to_embed]
            try:
                new_vectors = self._embed(missing_texts)
            except Exception:
                # Cache backend may have failed; embed everything instead.
                logger.warning(
                    "Tracer-MED: embedding cache read failed — re-embedding")
                return self._embed(texts)
            for j, i in enumerate(to_embed):
                vec = new_vectors[j].tolist()
                vectors[i] = vec
                try:
                    self._embedding_cache.put(texts[i], vec)
                except Exception as e:
                    logger.warning(
                        "Tracer-MED: embedding cache write failed: %s", e)
        return np.ascontiguousarray(
            np.array(vectors, dtype=np.float32), dtype=np.float32)

    # ------------------------------------------------------------------
    # Embedding
    # ------------------------------------------------------------------
    def _embed(self, texts: List[str]) -> np.ndarray:
        """Embed texts with a REAL embedding model.

        Raises:
            RuntimeError: if no embedding model is available. There is NO
                fallback — a triage without a real model must FAIL loudly
                rather than silently produce meaningless vectors.
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
        raise RuntimeError(
            "ClinicalTriageEngine: no real embedding model available. "
            f"Tried {'; '.join(errors)}. Install a sentence-transformers "
            "model (e.g. pip install sentence-transformers) or provide "
            "pre-computed embeddings. Refusing to fall back to a hash "
            "embedding — a triage without a real model is meaningless.")

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
        # Gargalo #3: corpus vectors come from the persistent content-addressed
        # cache; only unseen texts are embedded. Queries are embedded fresh.
        X = self._get_or_create_embeddings(texts)
        Q = self._get_or_create_embeddings(clinical_queries)

        # 3. Build Madhava engine (real, with bound proof)
        try:
            import winnex_madhava as wm
            engine = wm.build_engine(
                np.ascontiguousarray(X, dtype=np.float32),
                dim=X.shape[1], metric="cosine", quant="int8",
                stage1_dim=min(self.stage1_dim, X.shape[1]),
                stage2_dim=min(self.stage2_dim, X.shape[1]),
                k=k, k1_fraction=0.05,
                # Bounded Stage-2 survivors (Gargalo #2): postfilter=True scores
                # every survivor exactly; cap k2 to bound query cost.
                # Configurable via env (TRACER_MED_K2_MAX).
                k2_fraction=float(
                    os.environ.get("TRACER_MED_K2_FRACTION", "0.005")),
                k2_max=int(os.environ.get("TRACER_MED_K2_MAX", "500")),
                modulation=True, postfilter=True,
            )
            engine_used = "winnex-madhava (pip, C++20) + BlueBERT"
        except ImportError:
            raise RuntimeError(
                "ClinicalTriageEngine: winnex-madhava is required for "
                "soundness-guaranteed triage. Install it "
                "(pip install winnex-madhava). Refusing to fall back to a "
                "numpy scan — the proof guarantee requires the real motor.")

        # 4. Audited search per query
        total_viol = 0
        total_pairs = 0
        per_query = []

        if engine is not None:
            for i, q in enumerate(clinical_queries):
                qv = np.ascontiguousarray(Q[i], dtype=np.float32)

                # Audited search with Ed25519 non-repudiation, aligned with
                # Tracer-GOV. With winnex-madhava >= 1.9.2 the motor returns a
                # lightweight AuditCommitment (count + global threshold +
                # boundary sample) via search_with_commitment; winnex_tracer's
                # compliance layer signs it (make_worm_record) and the ~500-byte
                # signed record is appended to the WORM evidence chain. Fallback:
                # < 1.9.2 → search_audited certificate; else plain search.
                commitment = None
                worm_receipt = {}
                from winnex_tracer.persistence import WormStorage

                if hasattr(engine, "search_with_commitment"):
                    # Ed25519 non-repudiation (aligned with Tracer-GOV). The
                    # signer is FAIL-CLOSED without WORM_SIGNING_PRIVATE_KEY_*:
                    # in that case we degrade to the certificate/EvidenceChain
                    # path instead of failing the clinical triage (the MED
                    # service may run without a signing key; the GOV service
                    # requires one).
                    try:
                        from winnex_tracer.core import make_worm_record
                        rec = make_worm_record(
                            engine, qv, k=int(k), max_sample=50,
                            query_vector_bytes=qv.tobytes())
                        commitment = rec
                        total_viol += int(rec["bound_violations"])
                        total_pairs += int(rec["bound_pairs"])
                        indices = list(rec["indices"])
                        latency_ms = float(rec.get("_latency_ms", 0.0))
                        try:
                            worm_path = os.environ.get(
                                "TRACER_MED_EVIDENCE_PATH",
                                "/var/lib/tracer-med/evidence")
                            worm_receipt = WormStorage(
                                base_path=worm_path).append(
                                {"commitment": rec, "_ctx": {"query": q}})
                        except Exception as e:
                            logger.warning(
                                "Tracer-MED: WORM evidence persist failed: %s", e)
                    except Exception as e:
                        logger.warning(
                            "Tracer-MED: signed commitment unavailable "
                            "(WORM_SIGNING_PRIVATE_KEY_* not set?) — "
                            "degrading to search_audited certificate: %s", e)
                        commitment = None
                        ar = engine.search_audited(
                            qv, k=int(k), max_audit_records=500)
                        total_viol += int(ar["bound_violations"])
                        total_pairs += int(ar["bound_pairs"])
                        indices = list(ar["indices"])
                        latency_ms = float(ar["latency_ms"])
                elif hasattr(engine, "search_audited"):
                    ar = engine.search_audited(
                        qv, k=int(k), max_audit_records=500)
                    total_viol += int(ar["bound_violations"])
                    total_pairs += int(ar["bound_pairs"])
                    indices = list(ar["indices"])
                    latency_ms = float(ar["latency_ms"])
                else:
                    r = engine.search(qv)
                    total_viol += r.bound_violations
                    total_pairs += r.bound_pairs
                    indices = list(r.indices)
                    latency_ms = float(r.latency_ms)

                # Post-filter: attach metadata to returned indices
                returned = []
                for idx in indices:
                    rec = kept[int(idx)]
                    returned.append({
                        "index": int(idx),
                        "external_id": rec.external_id,
                        "text_preview": rec.text[:120],
                        "metadata": rec.metadata.to_dict(),
                    })
                per_query.append({
                    "query": q,
                    "indices": indices,
                    "returned": returned,
                    "bound_violations": int(commitment["bound_violations"]) if commitment else 0,
                    "bound_pairs": int(commitment["bound_pairs"]) if commitment else total_pairs,
                    "latency_ms": round(latency_ms, 3),
                    "commitment": commitment,
                    "worm_receipt": worm_receipt,
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
