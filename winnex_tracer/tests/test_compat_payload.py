"""
Compatibilidade de formato do payload assinado (Correção C).

A Correção C trocou `round(float(x), 6)` por `float.hex()` nos campos
numéricos do WORM record:

    antes:  "upper_bound": 0.4
    agora:  "upper_bound": "0x1.999999999999ap-2"

Registros já gravados são imutáveis e continuam verificáveis — a assinatura
cobre os bytes originais. O risco está nos CONSUMIDORES: qualquer código que
faça `float(rec["upper_bound"])` quebra com registros novos, e qualquer código
que só entenda `float.hex()` quebra com os antigos.

A varredura (2026-10-29) encontrou um único consumidor de dado assinado em
formato cru — `gov/core/tracer.py` — e ele foi corrigido para `payload_float`,
que aceita os dois formatos. Os demais (`lgpd.py`, `server.py`,
`tracer.py` legacy e `search_audited`) leem `GovAuditRecord` já convertido
para float, ou o dict do motor ao vivo (não assinado): nenhum precisa mudar.

Estes testes fixam a ponte para que a próxima mudança de formato não passe
despercebida.

Run:  python -m pytest winnex_tracer/tests/test_compat_payload.py -v
"""
import json
import os

import numpy as np
import pytest

from winnex_tracer.core.commitment import (
    payload_float,
    sign_payload,
    verify_record,
    public_key_hex,
)

_KEY = "7a" * 32


@pytest.fixture(autouse=True)
def _key(monkeypatch):
    monkeypatch.setenv("WORM_SIGNING_PRIVATE_KEY_HEX", _KEY)


# ---------------------------------------------------------------------------
# payload_float: aceita os dois formatos
# ---------------------------------------------------------------------------
def test_payload_float_le_formato_novo():
    """float.hex() → float."""
    assert payload_float("0x1.999999999999ap-2") == pytest.approx(0.4)
    assert payload_float(float(0.5).hex()) == 0.5


def test_payload_float_le_formato_antigo():
    """Registro pré-Correção C: float cru continua legível."""
    assert payload_float(0.4) == pytest.approx(0.4)
    assert payload_float(1) == 1.0
    assert payload_float(np.float32(0.25)) == pytest.approx(0.25)


def test_payload_float_hex_e_exato():
    """O round-trip hex preserva o valor bit a bit — a razão da Correção C."""
    v = 0.123456789012345
    assert payload_float(payload_float.__globals__["_exact_float"](v)) == v


# ---------------------------------------------------------------------------
# Registro ANTIGO assinado continua verificável
# ---------------------------------------------------------------------------
def test_registro_formato_antigo_verifica():
    """Um WORM record gravado antes da Correção C ainda valida.

    A assinatura cobre os bytes originais; `verify_record` não recanoniza.
    Portanto registros históricos continuam auditáveis — o que muda é só a
    leitura dos campos pelo consumidor.
    """
    payload_antigo = {
        "audit_id": "registro-historico-1",
        "timestamp": 1793230591.0,
        "query_fingerprint": "abc123",
        "k_requested": 10,
        "total_provably_excluded": 15540,
        "global_threshold": 0.5996,          # float cru, formato pré-C
        "bound_pairs": 100000,
        "bound_violations": 0,
        "indices": [1, 2, 3],
        "sampled_records": [
            {"doc_id": 7, "upper_bound": 0.4, "excluded": True},
        ],
    }
    rec = sign_payload(payload_antigo)

    out = verify_record(dict(rec), public_key_hex())
    assert out["status"] == "VALID", out

    # E o consumidor consegue ler os campos do registro antigo.
    assert payload_float(rec["global_threshold"]) == pytest.approx(0.5996)
    assert payload_float(rec["sampled_records"][0]["upper_bound"]) == \
        pytest.approx(0.4)


def test_registro_formato_novo_verifica():
    """Um WORM record gravado depois da Correção C valida."""
    payload_novo = {
        "audit_id": "registro-novo-1",
        "total_provably_excluded": 145670,
        "global_threshold": float(0.7451).hex(),
        "bound_pairs": 145673,
        "bound_violations": 0,
        "indices": [0, 1, 2],
        "sampled_records": [
            {"doc_id": 0, "upper_bound": float(0.2133).hex(),
             "excluded": True},
        ],
    }
    rec = sign_payload(payload_novo)
    assert verify_record(dict(rec), public_key_hex())["status"] == "VALID"
    assert payload_float(rec["sampled_records"][0]["upper_bound"]) == \
        pytest.approx(0.2133)


def test_adulterar_registro_antigo_invalida():
    """Registro histórico também é inforjável — a assinatura cobre os bytes."""
    payload = {
        "audit_id": "h2", "total_provably_excluded": 100,
        "global_threshold": 0.5,
        "sampled_records": [{"doc_id": 1, "upper_bound": 0.4,
                             "excluded": True}],
    }
    rec = sign_payload(payload)
    t = dict(rec)
    t["total_provably_excluded"] = 0
    assert verify_record(t, public_key_hex())["status"] == "INVALID"


# ---------------------------------------------------------------------------
# O consumidor corrigido: gov/TracerEngine lê o payload assinado
# ---------------------------------------------------------------------------
def test_tracer_engine_le_registro_assinado():
    """O caminho real: engine → make_worm_record → GovAuditRecord.

    Este é o teste que a varredura justificou. Antes de `payload_float`, este
    caminho levantava `ValueError: could not convert string to float`.
    """
    pytest.importorskip("winnex_madhava")
    from winnex_tracer.gov.core.tracer import (
        Config, GovMetadata, TracerEngine,
    )

    os.environ.setdefault("WINNEX_TRACER_ED25519_KEY",
                          "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
                          "e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2")
    d = 64
    rng = np.random.default_rng(0)
    vecs = rng.normal(size=(2000, d)).astype(np.float32)
    vecs /= np.linalg.norm(vecs, axis=1, keepdims=True)

    eng = TracerEngine(Config(stage1_dim=d, stage2_dim=d))
    eng.build(vecs)
    res = eng.search_with_audit(
        vecs[0], GovMetadata(data={"agency": "x", "purpose": "test"}), k=5)

    # Não levantou, e os campos numéricos são float de verdade.
    for r in res.audit:
        assert isinstance(r.upper_bound, float)
        assert isinstance(r.threshold, float)
        assert not isinstance(r.upper_bound, str)


def test_tracer_engine_marca_garantias():
    """A degradação fica marcada no resultado, não escondida."""
    pytest.importorskip("winnex_madhava")
    from winnex_tracer.gov.core.tracer import (
        Config, GovMetadata, TracerEngine,
    )

    os.environ.setdefault("WINNEX_TRACER_ED25519_KEY",
                          "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
                          "e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2")
    rng = np.random.default_rng(1)
    vecs = rng.normal(size=(500, 64)).astype(np.float32)
    vecs /= np.linalg.norm(vecs, axis=1, keepdims=True)

    eng = TracerEngine(Config(stage1_dim=64, stage2_dim=64))
    eng.build(vecs)
    res = eng.search_with_audit(
        vecs[0], GovMetadata(data={"agency": "x"}), k=5)

    g = res.engine_guarantees
    assert "cauchy_schwarz_bound" in g
    assert "search_with_commitment" in g
    assert "ed25519_signed" in g
    # A cobertura é declarada: vazio ou não, está dito.
    assert any(x.startswith("certificate_") for x in g)
