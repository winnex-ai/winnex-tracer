"""
Testes de degradação de garantia — a regra que o sistema não pode violar.

  **Se o sistema vai degradar, que degrade ruidosamente, com métrica
  auditável, não escondido atrás de um `return "numpy"`.**

Três invariantes testadas aqui:

  1. `Signer(algorithm="Ed25519")` LEVANTA quando PyNaCl falta — nunca troca
     por HMAC e devolve sucesso. HMAC só com `algorithm="HMAC"` explícito.
  2. Nenhuma chave default. Sem `WINNEX_TRACER_ED25519_KEY`, o sistema não
     assina. Uma chave constante no código-fonte é pública, e um "segredo"
     público não forja nada.
  3. `TracerEngine` sem backend com garantias LEVANTA — não cai para numpy
     silenciosamente. A degradação voluntária é declarada
     (`require_guarantees=False`) e fica marcada no resultado.

Run:  python -m pytest winnex_tracer/tests/test_degradacao.py -v
"""
import importlib
import os
import sys

import pytest

from winnex_tracer.core.signer import Signer, SignatureGuaranteeError
from winnex_tracer.gov.core.tracer import (
    BackendGuaranteeError,
    Config,
    TracerEngine,
)

_KEY = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"


# ---------------------------------------------------------------------------
# 1. Ed25519 não degrada para HMAC
# ---------------------------------------------------------------------------
def test_ed25519_sem_pynacl_levanta(monkeypatch):
    """Sem PyNaCl, Ed25519 LEVANTA — não assina com HMAC."""
    monkeypatch.setenv("WINNEX_TRACER_ED25519_KEY", _KEY)
    # Simula PyNaCl ausente.
    monkeypatch.setitem(sys.modules, "nacl", None)
    monkeypatch.setitem(sys.modules, "nacl.signing", None)

    s = Signer(algorithm="Ed25519")
    with pytest.raises(SignatureGuaranteeError) as e:
        s.sign({"audit_id": "a1"})

    msg = str(e.value)
    assert "PyNaCl" in msg
    # A mensagem precisa explicar a diferença de garantia, não só falhar.
    assert "repudiation" in msg or "non-repudiation" in msg
    # E precisa dizer como pedir HMAC de propósito.
    assert 'algorithm="HMAC"' in msg


def test_ed25519_nunca_devolve_hmac(monkeypatch):
    """O caminho de sucesso nunca produz um algoritmo diferente do pedido."""
    monkeypatch.setenv("WINNEX_TRACER_ED25519_KEY", _KEY)
    out = Signer(algorithm="Ed25519").sign({"a": 1})
    assert out["signature_algorithm"] == "Ed25519"
    assert out["verify_key"]           # chave pública publicada
    assert out["signature"]


def test_assinatura_ed25519_verifica(monkeypatch):
    """A assinatura produzida verifica com a chave pública devolvida."""
    nacl_signing = pytest.importorskip("nacl.signing")
    import json

    monkeypatch.setenv("WINNEX_TRACER_ED25519_KEY", _KEY)
    data = {"audit_id": "a1", "total_provably_excluded": 7}
    out = Signer(algorithm="Ed25519").sign(data)

    vk = nacl_signing.VerifyKey(bytes.fromhex(out["verify_key"]))
    canonical = json.dumps(data, sort_keys=True).encode()
    vk.verify(canonical, bytes.fromhex(out["signature"]))   # não levanta


# ---------------------------------------------------------------------------
# 2. Sem chave default
# ---------------------------------------------------------------------------
def test_ed25519_sem_chave_levanta(monkeypatch):
    """Sem a chave no ambiente, o sistema não assina — e não inventa uma."""
    monkeypatch.delenv("WINNEX_TRACER_ED25519_KEY", raising=False)
    monkeypatch.delenv("WINNEX_TRACER_ED25519_KEY_FILE", raising=False)

    with pytest.raises(SignatureGuaranteeError) as e:
        Signer(algorithm="Ed25519").sign({"a": 1})
    msg = str(e.value)
    assert "WINNEX_TRACER_ED25519_KEY" in msg
    assert "secret manager" in msg


def test_ed25519_chave_curta_levanta(monkeypatch):
    """Chave com tamanho errado é recusada com a instrução de gerar outra."""
    monkeypatch.setenv("WINNEX_TRACER_ED25519_KEY", "aa" * 16)   # 16 bytes
    with pytest.raises(SignatureGuaranteeError) as e:
        Signer(algorithm="Ed25519").sign({"a": 1})
    assert "32 bytes" in str(e.value)
    assert "SigningKey" in str(e.value)


def test_ed25519_chave_nao_hex_levanta(monkeypatch):
    monkeypatch.setenv("WINNEX_TRACER_ED25519_KEY", "não-é-hex")
    with pytest.raises(SignatureGuaranteeError):
        Signer(algorithm="Ed25519").sign({"a": 1})


def test_hmac_explicito_funciona(monkeypatch):
    """HMAC só existe quando pedido; devolve o algoritmo real e o aviso."""
    monkeypatch.setenv("WINNEX_TRACER_HMAC_KEY", "chave-de-teste")
    out = Signer(algorithm="HMAC").sign({"a": 1})
    assert out["signature_algorithm"] == "HMAC-SHA3-256"
    # O registro precisa declarar que NÃO é não-repúdio.
    assert "non-repudiation" in out["note"]


def test_hmac_sem_chave_levanta(monkeypatch):
    """Sem chave HMAC, levanta — a constante do código-fonte não é segredo."""
    monkeypatch.delenv("WINNEX_TRACER_HMAC_KEY", raising=False)
    with pytest.raises(SignatureGuaranteeError) as e:
        Signer(algorithm="HMAC").sign({"a": 1})
    assert "WINNEX_TRACER_HMAC_KEY" in str(e.value)
    assert "default" in str(e.value)


# ---------------------------------------------------------------------------
# 3. O backend não degrada silenciosamente
# ---------------------------------------------------------------------------
def test_backend_sem_garantias_levanta(monkeypatch):
    """Sem backend com garantias, `auto` LEVANTA em vez de usar numpy."""
    t = importlib.import_module("winnex_tracer.gov.core.tracer")
    monkeypatch.setattr(t, "_HAS_CPP_ENGINE", False)
    monkeypatch.setattr(t, "_HAS_MADHAVA_PIP", False)
    monkeypatch.setattr(t, "_HAS_PY_ENGINE", False)

    eng = TracerEngine(Config())
    with pytest.raises(BackendGuaranteeError) as e:
        eng._resolve_backend()

    msg = str(e.value)
    # Precisa dizer o que falta e o que aconteceria de errado.
    assert "winnex-madhava" in msg
    assert "total_provably_excluded=0" in msg
    # E como declarar a degradação de propósito.
    assert "require_guarantees=False" in msg


def test_backend_degradacao_declarada_e_permitida(monkeypatch):
    """Com require_guarantees=False, o numpy é usado — explicitamente."""
    t = importlib.import_module("winnex_tracer.gov.core.tracer")
    monkeypatch.setattr(t, "_HAS_CPP_ENGINE", False)
    monkeypatch.setattr(t, "_HAS_MADHAVA_PIP", False)
    monkeypatch.setattr(t, "_HAS_PY_ENGINE", False)

    eng = TracerEngine(Config(require_guarantees=False))
    assert eng._resolve_backend() == "builtin"


def test_backend_com_garantias_e_aceito(monkeypatch):
    """Havendo Madhava, o backend é o madhava_pip — sem aviso nem recusa."""
    t = importlib.import_module("winnex_tracer.gov.core.tracer")
    monkeypatch.setattr(t, "_HAS_CPP_ENGINE", False)
    monkeypatch.setattr(t, "_HAS_MADHAVA_PIP", True)
    monkeypatch.setattr(t, "_HAS_PY_ENGINE", False)

    eng = TracerEngine(Config())
    assert eng._resolve_backend() == "madhava_pip"


def test_preferencia_builtin_explicita_e_respeitada():
    """Pedir `builtin` no config é declaração, não acidente."""
    eng = TracerEngine(Config(engine_preference="builtin"))
    assert eng._resolve_backend() == "builtin"
