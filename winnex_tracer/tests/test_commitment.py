"""
winnex-tracer-core — AuditCommitment tests (Ed25519 non-repudiation).

The commitment is the shared audit-trail path for the tracer family:
the motor returns a lightweight count+threshold+sample, and this layer
signs it with Ed25519 so a compromised engine cannot forge past records.

Run:  python -m pytest winnex_tracer_core/tests/ -v
"""
import json
import os

import numpy as np
import pytest

from winnex_tracer.core import (
    make_worm_record,
    verify_record,
    public_key_hex,
    commitment_to_payload,
    sign_payload,
)
from winnex_tracer.persistence import WormStorage


@pytest.fixture(autouse=True)
def _ed25519_key(monkeypatch):
    monkeypatch.setenv("WORM_SIGNING_PRIVATE_KEY_HEX", "00" * 32)


def test_sign_and_verify_roundtrip():
    """A signed commitment verifies VALID; tampering is detected."""
    payload = {
        "audit_id": "a1",
        "total_provably_excluded": 15540,
        "global_threshold": 0.5996,
        "sampled_records": [{"doc_id": 1, "upper_bound": 0.1, "excluded": True}],
    }
    record = sign_payload(payload)
    v = verify_record(dict(record), public_key_hex())
    assert v["status"] == "VALID"


def test_tampered_count_invalid():
    """The 'lying engine' attack: changing the count breaks the signature."""
    payload = {"audit_id": "a1", "total_provably_excluded": 15540}
    record = sign_payload(payload)
    tampered = dict(record)
    tampered["total_provably_excluded"] = 0  # attacker forges "nothing excluded"
    v = verify_record(tampered, public_key_hex())
    assert v["status"] == "INVALID"
    assert "signature" in v["reason"]


def test_wrong_key_invalid():
    payload = {"audit_id": "a1", "total_provably_excluded": 1}
    record = sign_payload(payload)
    v = verify_record(dict(record), "11" * 32)
    assert v["status"] == "INVALID"


def test_missing_key_refused():
    os.environ.pop("WORM_SIGNING_PRIVATE_KEY_HEX", None)
    with pytest.raises(RuntimeError):
        sign_payload({"audit_id": "a1"})


def test_worm_append_and_verify_integrity(tmp_path):
    """WORM append + hash-chain integrity (the shared base)."""
    w = WormStorage(base_path=str(tmp_path))
    w.append({"audit_id": "a1", "data": "x"})
    w.append({"audit_id": "a2", "data": "y"})
    rep = w.verify_integrity()
    assert rep["total_blocks"] == 2
    assert rep["chain_integrity_verified"]
    assert rep["violations"] == 0


def test_commitment_to_payload_shape():
    """commitment_to_payload produces the canonical signed fields."""
    commitment = {
        "total_excluded_count": 10,
        "global_threshold": 0.5,
        "bound_pairs": 100,
        "bound_violations": 0,
        "indices": [1, 2, 3],
        "sampled_records": [{"doc_id": 7, "upper_bound": 0.4, "excluded": True}],
    }
    p = commitment_to_payload(commitment, np.zeros(32, dtype=np.float32).tobytes(), k_requested=10)
    assert p["total_provably_excluded"] == 10
    # Correção C: floats vão no payload como float.hex() (IEEE-754 exato), não
    # round(,6). O round podia inverter `upper_bound < global_threshold` na
    # fronteira amostrada, e o registro assinado contradiria a própria prova.
    assert float.fromhex(p["global_threshold"]) == 0.5
    assert p["k_requested"] == 10
    assert p["bound_violations"] == 0
    assert "query_fingerprint" in p
    assert len(p["sampled_records"]) == 1
    assert float.fromhex(p["sampled_records"][0]["upper_bound"]) == 0.4
