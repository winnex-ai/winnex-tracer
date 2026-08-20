"""
Tracer-GOV — Jurisdiction & localization tests.

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from winnex_tracer.gov.core.jurisdiction import (
    reload_jurisdictions,
    get_jurisdiction,
    list_jurisdictions,
)
from winnex_tracer.gov.compliance.localized import generate_localized_report
from winnex_tracer.gov.core import TracerEngine, Config, GovMetadata
import numpy as np


def test_list_jurisdictions():
    """All expected jurisdictions are present."""
    reload_jurisdictions()
    codes = list_jurisdictions()
    for expected in ["global", "br-gv", "us-gv", "eu-gv",
                     "pt-gv", "es-gv", "fr-gv", "de-gv", "it-gv"]:
        assert expected in codes, f"missing {expected}"


def test_inheritance_eu_to_member():
    """pt-gv inherits EU agencies + has its own."""
    reload_jurisdictions()
    pt = get_jurisdiction("pt-gv")
    agencies = pt.policies.get("agencies", {})
    # Inherited from eu-gv
    assert "European Commission" in agencies
    assert "EDPB" in agencies
    # Local overrides
    assert "Tribunal de Contas" in agencies
    assert "CNPD" in agencies
    assert pt.parent == "eu-gv"


def test_inheritance_sensitivity():
    """pt-gv sensitivity overrides eu-gv defaults."""
    reload_jurisdictions()
    pt = get_jurisdiction("pt-gv")
    sens = pt.get_sensitivity("restricted")
    assert sens.get("required_signature") == "Cartao de Cidadao"
    assert "58/2019" in sens.get("legal_basis", "")


def test_brazil_states():
    """br-gv defines states (go, sp, rj, mg)."""
    reload_jurisdictions()
    br = get_jurisdiction("br-gv")
    states = br.policies.get("states", {})
    assert "go" in states
    assert states["go"]["name"] == "Goias"
    assert states["sp"]["name"] == "Sao Paulo"


def test_localized_reports_languages():
    """Each jurisdiction's report is in its own language."""
    reload_jurisdictions()
    record = {
        "metadata": {},
        "audit": [], "total_excluded": 0,
        "violations_64d": 0, "violations_128d": 0,
        "signature": "", "signature_algorithm": "",
        "worm_hash": "", "blockchain_tx": "",
        "generated_at": "2026-08-06T00:00:00+00:00",
    }
    expected_lang = {
        "br-gv": "pt-BR", "us-gv": "en-US", "eu-gv": "en",
        "pt-gv": "pt-PT", "es-gv": "es", "fr-gv": "fr",
        "de-gv": "de", "it-gv": "it",
    }
    for code, lang in expected_lang.items():
        r = generate_localized_report(code, record)
        assert r["language"] == lang, f"{code}: got {r['language']}, want {lang}"
        assert r["jurisdiction"] == code


def test_engine_mode_public_internal():
    """Mode validation: internal requires credential."""
    # public OK
    cfg = Config(jurisdiction="br-gv", mode="public")
    eng = TracerEngine(cfg)
    assert eng.jurisdiction_code == "br-gv"

    # internal without credential → error
    try:
        Config(jurisdiction="br-gv", mode="internal")
        TracerEngine(Config(jurisdiction="br-gv", mode="internal"))
        assert False, "should have raised"
    except ValueError:
        pass

    # internal with credential OK
    eng2 = TracerEngine(Config(
        jurisdiction="br-gv", mode="internal",
        internal_credential="secret"))
    assert eng2.config.mode == "internal"


def test_search_stamps_jurisdiction():
    """search_with_audit stamps jurisdiction/mode/language on result."""
    cfg = Config(jurisdiction="pt-gv", mode="public")
    eng = TracerEngine(cfg)
    vecs = np.random.randn(100, 64).astype(np.float32)
    eng.build(vecs)
    md = GovMetadata(data={"agency": "x", "purpose": "test"})
    res = eng.search_with_audit(vecs[0], md, k=5)
    assert res.jurisdiction == "pt-gv"
    assert res.language == "pt-PT"
    assert res.mode == "public"


def test_unknown_jurisdiction_falls_back_global():
    """Unknown jurisdiction falls back to global without crashing."""
    cfg = Config(jurisdiction="xx-unknown")
    eng = TracerEngine(cfg)
    assert eng.jurisdiction_code == "global"


# ---------------------------------------------------------------------------
# Regionalized metadata (global / multilanguage)
# ---------------------------------------------------------------------------
def test_br_gv_accepts_english_field_names():
    """br-gv (Portuguese jurisdiction) maps generic EN names to the local ones.

    The tool is global: a client sending `requesting_agency` to br-gv must
    have it mapped to `orgao_requisitante` (the br-gv required field)."""
    eng = TracerEngine(Config(jurisdiction="br-gv", mode="public"))
    data = {
        "requesting_agency": "TCU",
        "cpf": "000.000.000-00",
        "role": "Auditor",
        "source_database": "SIAFI",
        "sensitivity": "public",
        "purpose": "audit",
    }
    mapped = eng._map_metadata_fields(data)
    assert mapped["orgao_requisitante"] == "TCU"
    assert mapped["funcao"] == "Auditor"
    assert mapped["base_de_dados"] == "SIAFI"
    assert mapped["finalidade"] == "audit"
    assert eng.validate_metadata(data) == []


def test_br_gv_accepts_portuguese_field_names():
    """br-gv with native Portuguese field names passes through unchanged."""
    eng = TracerEngine(Config(jurisdiction="br-gv", mode="public"))
    data = {
        "orgao_requisitante": "TCU",
        "cpf": "000.000.000-00",
        "funcao": "Auditor",
        "base_de_dados": "SIAFI",
        "sensibilidade": "public",
        "finalidade": "audit",
    }
    assert eng.validate_metadata(data) == []


def test_us_gv_accepts_english_field_names():
    """us-gv uses English natively — no mapping needed."""
    eng = TracerEngine(Config(jurisdiction="us-gv", mode="public"))
    data = {
        "requesting_agency": "EPA",
        "operator_id": "op-1",
        "role": "Analyst",
        "source_database": "DB",
        "sensitivity": "restricted",
        "purpose": "compliance",
    }
    assert eng.validate_metadata(data) == []


def test_br_gv_reports_missing_regional_fields():
    """Missing required fields are reported in the jurisdiction's names."""
    eng = TracerEngine(Config(jurisdiction="br-gv", mode="public"))
    missing = eng.validate_metadata({})
    assert "orgao_requisitante" in missing
    assert "cpf" in missing
    assert "funcao" in missing


if __name__ == "__main__":
    test_list_jurisdictions()
    print("[OK] test_list_jurisdictions")
    test_inheritance_eu_to_member()
    print("[OK] test_inheritance_eu_to_member")
    test_inheritance_sensitivity()
    print("[OK] test_inheritance_sensitivity")
    test_brazil_states()
    print("[OK] test_brazil_states")
    test_localized_reports_languages()
    print("[OK] test_localized_reports_languages")
    test_engine_mode_public_internal()
    print("[OK] test_engine_mode_public_internal")
    test_search_stamps_jurisdiction()
    print("[OK] test_search_stamps_jurisdiction")
    test_unknown_jurisdiction_falls_back_global()
    print("[OK] test_unknown_jurisdiction_falls_back_global")
    print("\n[ALL JURISDICTION TESTS PASSED]")
