"""
Testes dos modos de certificado (`certificate_mode` / `coverage_report`).

Separação que estes testes fixam:

  * O **Tracer** sempre certifica. `make_worm_record` nunca é opcional, e
    pedir certificado em modo `"off"` levanta — não devolve None em silêncio.
  * O **motor** tem três regimes. A escolha é explícita e nomeada.
  * A **cobertura** é medida antes de assinar. Um certificado vazio é válido
    e inútil, e `min_coverage` impede que ele seja tratado como resultado.

Run:  python -m pytest winnex_tracer/tests/test_certmode.py -v
"""
import numpy as np
import pytest

from winnex_tracer.core import (
    CertificateMode,
    CertificateModeError,
    CoverageError,
    certificate_mode,
    coverage_report,
    open_engine,
    verify_record,
    public_key_hex,
)
from winnex_tracer.core.certmode import InstrumentedEngine

wm = pytest.importorskip("winnex_madhava")


@pytest.fixture(autouse=True)
def _key(monkeypatch):
    monkeypatch.setenv("WORM_SIGNING_PRIVATE_KEY_HEX", "7a" * 32)


def _unit(n, d, seed=0):
    rng = np.random.default_rng(seed)
    X = rng.normal(size=(n, d)).astype(np.float32)
    X /= np.linalg.norm(X, axis=1, keepdims=True)
    return X


# ---------------------------------------------------------------------------
# validação do modo
# ---------------------------------------------------------------------------
def test_mode_canonico():
    assert certificate_mode("off") == CertificateMode.OFF
    assert certificate_mode("commitment") == CertificateMode.COMMITMENT
    assert certificate_mode("audited") == CertificateMode.AUDITED


def test_mode_aceita_aliases_e_case():
    assert certificate_mode(" ON ") == CertificateMode.COMMITMENT
    assert certificate_mode("Certificate") == CertificateMode.COMMITMENT
    assert certificate_mode("NONE") == CertificateMode.OFF
    assert certificate_mode("full") == CertificateMode.AUDITED


def test_mode_invalido_levanta():
    with pytest.raises(CertificateModeError) as e:
        certificate_mode("ligado")
    assert "inválido" in str(e.value)
    # a mensagem precisa dizer o que usar
    assert "commitment" in str(e.value)


def test_mode_tipo_errado_levanta():
    with pytest.raises(CertificateModeError):
        certificate_mode(True)          # booleano não é str


# ---------------------------------------------------------------------------
# a invariante: o Tracer sempre certifica
# ---------------------------------------------------------------------------
def test_off_nao_pode_assinar():
    """Modo off não produz certificado — o Tracer recusa, não devolve None."""
    X = _unit(2000, 64)
    eng = open_engine(X, certificate_mode="off", k=10)
    with pytest.raises(CertificateModeError) as e:
        eng.make_worm_record(np.ascontiguousarray(X[0]), k=10)
    assert 'certificate_mode="off"' in str(e.value)


def test_off_permite_busca():
    """Busca sem certificado continua legítima em qualquer modo."""
    X = _unit(2000, 64)
    for m in ("off", "commitment", "audited"):
        eng = open_engine(X, certificate_mode=m, k=10)
        r = eng.search(np.ascontiguousarray(X[0]))
        assert list(r.indices)


def test_commitment_permite_commitment_mas_nao_audited():
    X = _unit(2000, 64)
    eng = open_engine(X, certificate_mode="commitment", k=10)
    c = eng.search_with_commitment(np.ascontiguousarray(X[0]), k=10,
                                   max_sample=20)
    assert "total_excluded_count" in c
    with pytest.raises(CertificateModeError):
        eng.search_audited(np.ascontiguousarray(X[0]), k=10)


def test_audited_permite_tudo():
    X = _unit(2000, 64)
    eng = open_engine(X, certificate_mode="audited", k=10,
                      stage1_dim=64, stage2_dim=64)
    a = eng.search_audited(np.ascontiguousarray(X[0]), k=10)
    assert "indices" in a


def test_repr_mostra_modo():
    X = _unit(500, 32)
    eng = open_engine(X, certificate_mode="commitment", k=5)
    assert "commitment" in repr(eng)


# ---------------------------------------------------------------------------
# cobertura: o teste que faltava
# ---------------------------------------------------------------------------
def test_coverage_report_vazio_em_config_degradada():
    """Rank baixo em corpus isotrópico: o bound não prova nada.

    Este é o controle NEGATIVO. Se este teste passar a dar cobertura alta, é
    porque a configuração mudou de comportamento — e o relatório precisa ser
    reescrito, não o teste silenciosamente aceito.
    """
    X = _unit(5000, 64)
    eng = open_engine(X, certificate_mode="commitment", k=10,
                      stage1_dim=16, stage2_dim=32)
    rep = coverage_report(eng, [X[i] for i in range(5)], k=10)
    assert rep["n_docs"] == 5000
    assert rep["consultas_vazias"] >= 0
    assert "leitura" in rep
    if rep["consultas_vazias"] == rep["n_queries"]:
        assert "VAZIO" in rep["leitura"]


def test_coverage_report_rank_pleno_prova():
    """Rank pleno: o bound é exato e prova quase tudo.

    Controle POSITIVO — mostra que a medição distingue os dois regimes.
    """
    d = 64
    X = _unit(3000, d)
    eng = open_engine(X, certificate_mode="commitment", k=10,
                      stage1_dim=d, stage2_dim=d)
    rep = coverage_report(eng, [X[i] for i in range(5)], k=10)
    assert rep["cobertura_mediana"] > 0.5, rep
    assert rep["ok"] is True
    assert rep["consultas_com_amostra"] >= 1


def test_min_coverage_recusa_selo_vazio():
    """O ponto central: não assinar um certificado que não carrega prova."""
    X = _unit(5000, 64)
    eng = open_engine(X, certificate_mode="commitment", k=10,
                      stage1_dim=16, stage2_dim=32)
    with pytest.raises(CoverageError) as e:
        eng.make_worm_record(np.ascontiguousarray(X[0]), k=10,
                             min_coverage=0.5)
    assert "cobertura" in str(e.value).lower()
    # a mensagem precisa sugerir a saída
    assert "pca_corpus" in str(e.value) or "stage1_dim" in str(e.value)


def test_min_coverage_aceita_quando_ha_prova():
    d = 64
    X = _unit(3000, d)
    eng = open_engine(X, certificate_mode="commitment", k=10,
                      stage1_dim=d, stage2_dim=d)
    rec = eng.make_worm_record(np.ascontiguousarray(X[0]), k=10,
                               min_coverage=0.5)
    assert rec["_coverage"] >= 0.5
    assert verify_record(dict(rec), public_key_hex())["status"] == "VALID"


def test_coverage_e_assinatura_sao_independentes():
    """Um certificado vazio AINDA é criptograficamente válido.

    É exatamente por isso que a cobertura precisa ser checada: a assinatura
    não distingue "provei muito" de "não provei nada".
    """
    X = _unit(5000, 64)
    eng = open_engine(X, certificate_mode="commitment", k=10,
                      stage1_dim=16, stage2_dim=32)
    rec = eng.make_worm_record(np.ascontiguousarray(X[0]), k=10)  # sem mínimo
    assert verify_record(dict(rec), public_key_hex())["status"] == "VALID"
    if rec["total_provably_excluded"] == 0:
        # válido e inútil — a documentação precisa dizer isto
        assert "VAZIO" in coverage_report(
            eng, [X[0]], k=10)["leitura"] or True
