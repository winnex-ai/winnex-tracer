"""
winnex-tracer-core — Audit Commitment Signer (Ed25519 non-repudiation)
================================================================
The shared audit-trail path for the Winnex tracer family (gov/med/jus/gap).

Hybrid responsibility split (defeats the "lying engine" attack):

  1. C++ motor (winnex-madhava >= 1.9.2) returns the lightweight
     AuditCommitment: total_excluded_count + global_threshold + a
     deterministic boundary sample (up to max_sample). No hash, no key,
     no O(N) allocation.
  2. THIS compliance layer (the trusted signer) verifies the commitment is
     consistent, computes an integrity hash over the raw fields, and signs
     the payload with an Ed25519 private key held in the environment / KMS —
     NEVER in the C++ binary.
  3. The WORM stores the signed payload (~500 bytes), so even a compromised
     engine cannot forge past records: it does not hold the signing key.

The public key (derived from the private key at deploy time) is distributed
to auditors and used by the /verify endpoints.

License: Business Source License 1.1 (BSL 1.1)
"""
import hashlib
import json
import os
import time
import uuid
from typing import Any, Dict, Optional

# PyNaCl (Ed25519) — hard dependency for non-repudiation.
try:
    import nacl.signing
    import nacl.exceptions
    _HAS_NACL = True
except ImportError:
    _HAS_NACL = False


def _require_nacl():
    if not _HAS_NACL:
        raise RuntimeError(
            "Ed25519 signing requires PyNaCl: pip install pynacl. "
            "The commitment signer refuses to fall back to an insecure hash."
        )


def _get_signing_key() -> "nacl.signing.SigningKey":
    """Load the Ed25519 signing key from the environment / KMS.

    Never hardcoded. Sources, in order:
      1. WORM_SIGNING_PRIVATE_KEY_HEX  (32-byte seed as hex)
      2. WORM_SIGNING_PRIVATE_KEY_FILE (path to a hex seed file)
    """
    _require_nacl()
    key_hex = os.environ.get("WORM_SIGNING_PRIVATE_KEY_HEX", "").strip()
    if not key_hex:
        key_file = os.environ.get("WORM_SIGNING_PRIVATE_KEY_FILE", "").strip()
        if key_file and os.path.exists(key_file):
            with open(key_file) as f:
                key_hex = f.read().strip()
    if not key_hex:
        raise RuntimeError(
            "WORM_SIGNING_PRIVATE_KEY_HEX (or _FILE) not set. The compliance "
            "service refuses to sign without a configured Ed25519 key."
        )
    try:
        seed = bytes.fromhex(key_hex)
    except ValueError as exc:
        raise RuntimeError("WORM_SIGNING_PRIVATE_KEY_HEX is not valid hex.") from exc
    if len(seed) != 32:
        raise RuntimeError(
            f"Ed25519 seed must be 32 bytes, got {len(seed)}. "
            "Generate with: python -c \"import nacl.signing,os; "
            "print(nacl.signing.SigningKey(os.urandom(32)).encode().hex())\""
        )
    return nacl.signing.SigningKey(seed)


def public_key_hex() -> str:
    """The public verify key (hex) — distribute to auditors."""
    sk = _get_signing_key()
    return sk.verify_key.encode().hex()


def _exact_float(value: Any) -> str:
    """Serialize a float to its EXACT canonical representation.

    WHY (2026-09-03, correção C): the old `round(float(x), 6)` could INVERT
    the core proof `upper_bound < global_threshold`. The commitment samples the
    docs NEAREST the threshold (boundary-biased) — precisely where the gap can
    be < 1e-6. If ub and threshold differ by < 5e-7 and straddle a rounding
    boundary, `round(ub, 6) >= round(thr, 6)` while `ub < thr` in the motor —
    the signed record would contradict the proof it is supposed to witness.

    `float.hex()` is the IEEE-754 exact, canonical, deterministic representation
    of the value the motor decided with (a float32 promoted to Python float).
    It is JSON-serializable (as a string), reproduces the comparison bit-for-bit,
    and is stable across runs/processes — so the Ed25519 signature still covers
    an immutable payload. Auditors can decode hex → float with `float.fromhex`.
    """
    return float(value).hex()


def payload_float(value: Any) -> float:
    """Decodifica um float do payload assinado.

    Espelho de `_exact_float`. Os campos numéricos do WORM record vão como
    `float.hex()` (Correção C), então consumidores que fazem `float(x)`
    quebram com `ValueError: could not convert string to float: '0x1.ep-8'`.

    Aceita os dois formatos, para ler registros antigos gravados antes da
    Correção C sem migração.
    """
    if isinstance(value, str):
        return float.fromhex(value)
    return float(value)


def commitment_to_payload(
    commitment: Dict[str, Any],
    query_vector_bytes: bytes,
    k_requested: int,
    audit_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Build the deterministic payload to be signed, from the C++ commitment.

    Args:
        commitment: the dict from engine.search_with_commitment(...)
        query_vector_bytes: raw float32 query bytes (for the fingerprint)
        k_requested: the k passed to the search
        audit_id: optional explicit audit_id. When omitted, a new uuid is
            generated. Callers (tracer-gov/med) pass the government metadata
            audit_id so the commitment and the metadata share ONE id.
    Returns:
        payload dict (unsorted canonical keys are fine — we sort_keys in
        hashlib/sign).
    """
    samples = [
        {
            "doc_id": int(s["doc_id"]),
            # Correção C: valor EXATO (float.hex), não round(,6) — ver _exact_float.
            "upper_bound": _exact_float(s["upper_bound"]),
            "excluded": bool(s["excluded"]),
        }
        for s in commitment.get("sampled_records", [])
    ]
    return {
        "audit_id": audit_id or str(uuid.uuid4()),
        "timestamp": time.time(),
        "query_fingerprint": hashlib.sha256(query_vector_bytes).hexdigest(),
        "k_requested": int(k_requested),
        "total_provably_excluded": int(commitment["total_excluded_count"]),
        # Correção C: global_threshold EXATO (float.hex) — a prova ub<thr não
        # pode ser invertida por arredondamento no registro assinado.
        "global_threshold": _exact_float(commitment["global_threshold"]),
        "bound_pairs": int(commitment["bound_pairs"]),
        "bound_violations": int(commitment["bound_violations"]),
        "indices": [int(i) for i in commitment.get("indices", [])],
        "sampled_records": samples,
    }


def integrity_hash(payload: Dict[str, Any]) -> str:
    """SHA-256 over the canonical JSON of the payload.

    This is the C++→Python integrity check: the Python signer computes it
    over the raw fields it received, so any corruption in transit (or any
    tampering by a compromised engine) changes the hash and the signature
    will not verify against the stored commitment.
    """
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


def sign_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Sign the canonical payload with Ed25519 → the WORM record.

    The returned record is ~500 bytes and carries:
      - all payload fields (audit_id, count, threshold, sample, ...)
      - integrity_hash  (the C++→Python consistency proof)
      - signature_hex   (Ed25519 over the canonical payload)
      - public_key_hint ("ed25519-v1" — which verify key family to use)
    """
    sk = _get_signing_key()
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    sig = sk.sign(canonical).signature
    record = {
        **payload,
        "integrity_hash": hashlib.sha256(canonical).hexdigest(),
        "signature_hex": sig.hex(),
        "signature_algorithm": "Ed25519",
        "public_key_hint": "ed25519-v1",
    }
    return record


def verify_record(record: Dict[str, Any], public_key_hex_str: str) -> Dict[str, Any]:
    """Verify a WORM record's Ed25519 signature + integrity hash.

    Args:
        record: the stored WORM record
        public_key_hex_str: the auditor's copy of the public verify key (hex)
    Returns:
        dict: {status: "VALID"|"INVALID", reason: str, verified: bool}
    """
    _require_nacl()
    # Copy — never mutate the caller's dict.
    rec = dict(record)
    sig_hex = rec.pop("signature_hex", "")
    alg = rec.pop("signature_algorithm", "")
    ih = rec.pop("integrity_hash", "")
    # public_key_hint is signed-metadata added AFTER the signature; it must be
    # excluded from the canonical bytes exactly as it was at sign time.
    rec.pop("public_key_hint", "")
    # _latency_ms is informational metadata added after signing; exclude it too.
    rec.pop("_latency_ms", "")
    # _coverage is post-signature metadata added by
    # InstrumentedEngine.make_worm_record when min_coverage is enforced. Like
    # _latency_ms it did not exist at sign time, so it must not participate in
    # the canonical bytes.
    rec.pop("_coverage", "")
    if not sig_hex:
        return {"status": "INVALID", "reason": "missing signature_hex", "verified": False}
    try:
        vk = nacl.signing.VerifyKey(bytes.fromhex(public_key_hex_str))
    except Exception as exc:
        return {"status": "INVALID", "reason": f"bad public key: {exc}", "verified": False}

    # 1. Signature check (non-repudiation — defeats the lying engine).
    canonical = json.dumps(rec, sort_keys=True, separators=(",", ":")).encode()
    try:
        vk.verify(canonical, bytes.fromhex(sig_hex))
    except nacl.exceptions.BadSignatureError:
        return {"status": "INVALID", "reason": "Ed25519 signature invalid (tampered)", "verified": False}

    # 2. Integrity hash check (C++→Python consistency).
    if ih and hashlib.sha256(canonical).hexdigest() != ih:
        return {"status": "INVALID", "reason": "integrity_hash mismatch", "verified": False}

    return {"status": "VALID", "reason": "Ed25519 signature + integrity hash verified", "verified": True}


def make_worm_record(
    engine,
    query_vec,
    k: int = 10,
    max_sample: int = 50,
    query_vector_bytes: Optional[bytes] = None,
    audit_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Full pipeline: motor commitment → signed WORM record (~500 bytes).

    Args:
        engine: a winnex_madhava engine with search_with_commitment
        query_vec: the float32 query vector (np.ndarray)
        k: top-k requested
        max_sample: boundary sample size (default 50)
        audit_id: optional explicit audit_id. Callers (tracer-gov/med) pass
            the government metadata audit_id so the commitment and the
            metadata share ONE id (the API returns the metadata id and WORM
            lookups by that id must resolve the record). When omitted, a new
            uuid is generated inside commitment_to_payload.
    Returns:
        signed WORM record (ready for WormStorage.append)
    """
    if query_vector_bytes is None:
        query_vector_bytes = query_vec.tobytes()
    if hasattr(engine, "search_with_commitment"):
        commitment = engine.search_with_commitment(
            query_vec, k=int(k), max_sample=int(max_sample))
    else:
        raise RuntimeError(
            "engine has no search_with_commitment — need winnex-madhava >= 1.9.2"
        )
    payload = commitment_to_payload(
        commitment, query_vector_bytes, k, audit_id=audit_id)
    record = sign_payload(payload)
    # Attach latency from the motor (informational, not signed).
    record["_latency_ms"] = float(commitment.get("latency_ms", 0.0))
    return record
