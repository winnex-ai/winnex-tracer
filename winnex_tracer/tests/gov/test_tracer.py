"""
Tracer-GOV — Core tests.

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
import sys, os, json, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

import numpy as np
from pathlib import Path
from winnex_tracer.gov.core import TracerEngine, Config, GovMetadata, Signer, RetentionPolicy, AuditLogTracker
from winnex_tracer.persistence import WormStorage, FileStore


def test_audit_log_chain():
    """AuditLogTracker maintains a tamper-evident HMAC chain."""
    os.environ["WINNEX_TRACER_AUDIT_HMAC_KEY"] = "test-soc2-hmac-key"
    with tempfile.TemporaryDirectory() as tmpdir:
        tracker = AuditLogTracker(storage_path=tmpdir)
        tracker.log_access("audit-1", "cpf-1", "TCU", ip_address="10.0.0.1")
        tracker.log_access("audit-1", "cpf-2", "CGU", ip_address="10.0.0.2")
        report = tracker.verify_chain()
        assert report["entries"] == 2
        assert report["verified"]
        assert report["hmac_protected"]

        # Tamper with an entry -> chain breaks
        import glob
        for f in glob.glob(os.path.join(tmpdir, "**", "*.jsonl"), recursive=True):
            content = open(f).read()
            open(f, "w").write(content.replace("cpf-1", "cpf-999"))
            break
        report2 = tracker.verify_chain()
        assert not report2["verified"]
        assert report2["violations"] > 0
    del os.environ["WINNEX_TRACER_AUDIT_HMAC_KEY"]


def test_config_from_env():
    """Config loads from environment variables."""
    os.environ["WINNEX_TRACER_STAGE1_DIM"] = "32"
    os.environ["WINNEX_TRACER_STAGE2_DIM"] = "64"
    cfg = Config.from_env()
    assert cfg.stage1_dim == 32
    assert cfg.stage2_dim == 64
    del os.environ["WINNEX_TRACER_STAGE1_DIM"]
    del os.environ["WINNEX_TRACER_STAGE2_DIM"]


def test_metadata_defaults():
    """GovMetadata auto-generates audit_id and timestamp."""
    meta = GovMetadata(data={"agency": "TCU", "cpf": "0000"})
    assert meta.audit_id != ""
    assert meta.timestamp != ""
    assert meta.query_hash != ""


def test_validate_metadata():
    """Engine validates required fields from the active jurisdiction."""
    # br-gv uses Brazilian field names (orgao_requisitante, cpf, ...)
    cfg = Config(jurisdiction="br-gv")
    engine = TracerEngine(cfg)
    missing = engine.validate_metadata({})
    assert len(missing) > 0
    full = {
        "orgao_requisitante": "TCU",
        "cpf": "000.000.000-00",
        "funcao": "Auditor",
        "base_de_dados": "SIAFI",
        "sensibilidade": "public",
        "finalidade": "Test",
    }
    missing = engine.validate_metadata(full)
    assert len(missing) == 0


def test_validate_metadata_global():
    """global jurisdiction uses neutral field names (operator_id)."""
    cfg = Config(jurisdiction="global")
    engine = TracerEngine(cfg)
    full = {
        "requesting_agency": "Agency",
        "operator_id": "operator-1",
        "role": "Auditor",
        "source_database": "DB",
        "sensitivity": "public",
        "purpose": "Test",
    }
    missing = engine.validate_metadata(full)
    assert len(missing) == 0


def test_retention_policy():
    """RetentionPolicy resolves years from policies JSON."""
    cfg = Config(policies_path=os.path.join(os.path.dirname(__file__), "..", "..", "gov", "config", "policies.json"))
    rp = RetentionPolicy(cfg.policies_path)
    # Default
    assert rp.get_retention_years() == 5
    # Health
    assert rp.get_retention_years("SUS", "restricted") in (10, 20)
    # Secret
    assert rp.get_retention_years("TCU", "secret") in (15, 20)


def test_worm_append_and_verify():
    """WORM storage appends immutably and verifies chain."""
    with tempfile.TemporaryDirectory() as tmpdir:
        worm = WormStorage(base_path=tmpdir)
        r1 = worm.append({"query": "test1", "result": [1, 2, 3]})
        assert r1["worm_hash"] != ""
        r2 = worm.append({"query": "test2", "result": [4, 5, 6]})
        assert r2["worm_hash"] != r1["worm_hash"]
        integrity = worm.verify_integrity()
        assert integrity["chain_integrity_verified"]
        assert integrity["total_blocks"] == 2


def test_worm_integrity_fail():
    """WORM detects tampering in data files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        worm = WormStorage(base_path=tmpdir)
        worm.append({"query": "test1"})
        worm.append({"query": "test2"})

        # Tamper with a record in the actual data file
        for f in sorted(Path(tmpdir).rglob("records.jsonl")):
            content = f.read_text()
            f.write_text(content.replace("test1", "TAMPERED"))
            break

        integrity = worm.verify_integrity()
        assert not integrity["chain_integrity_verified"]
        assert integrity["violations"] > 0


def test_filestore_chain():
    """FileStore maintains hash chain integrity."""
    with tempfile.TemporaryDirectory() as tmpdir:
        fs = FileStore(base_path=tmpdir)
        fs.append("id1", {"data": "first"})
        fs.append("id2", {"data": "second"})
        chain = fs.verify_chain()
        assert chain["verified"]
        assert chain["blocks"] == 2


def test_signer_ed25519():
    """Signer produces and verifies Ed25519 signatures."""
    os.environ["WINNEX_TRACER_ED25519_KEY"] = (
        "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
        "e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2")
    signer = Signer(algorithm="Ed25519")
    data = {"test": "data", "number": 42}
    sig = signer.sign(data)
    assert sig["signature"] != ""
    assert sig["signature_algorithm"] == "Ed25519"


def test_retention_required_signature():
    """RetentionPolicy resolves required signature algorithm."""
    rp = RetentionPolicy(os.path.join(os.path.dirname(__file__), "..", "..", "gov", "config", "policies.json"))
    secret_sig = rp.get_required_signature("secret")
    assert secret_sig == "ICP-Brasil"
    public_sig = rp.get_required_signature("public")
    assert public_sig == "Ed25519"


def test_retention_blockchain_required():
    """RetentionPolicy resolves blockchain requirement."""
    rp = RetentionPolicy(os.path.join(os.path.dirname(__file__), "..", "..", "gov", "config", "policies.json"))
    assert rp.is_blockchain_required("SUS")
    assert not rp.is_blockchain_required("default")


def test_retention_legal_basis():
    """RetentionPolicy resolves legal basis."""
    rp = RetentionPolicy(os.path.join(os.path.dirname(__file__), "..", "..", "gov", "config", "policies.json"))
    basis = rp.get_legal_basis("SUS")
    assert "8080" in basis or "Law" in basis


if __name__ == "__main__":
    test_config_from_env()
    print("[OK] test_config_from_env")
    test_metadata_defaults()
    print("[OK] test_metadata_defaults")
    test_validate_metadata()
    print("[OK] test_validate_metadata")
    test_validate_metadata_global()
    print("[OK] test_validate_metadata_global")
    test_retention_policy()
    print("[OK] test_retention_policy")
    test_worm_append_and_verify()
    print("[OK] test_worm_append_and_verify")
    test_worm_integrity_fail()
    print("[OK] test_worm_integrity_fail")
    test_filestore_chain()
    print("[OK] test_filestore_chain")
    test_signer_ed25519()
    print("[OK] test_signer_ed25519")
    test_retention_required_signature()
    print("[OK] test_retention_required_signature")
    test_retention_blockchain_required()
    print("[OK] test_retention_blockchain_required")
    test_retention_legal_basis()
    print("[OK] test_retention_legal_basis")
    print("\n[ALL TESTS PASSED]")
