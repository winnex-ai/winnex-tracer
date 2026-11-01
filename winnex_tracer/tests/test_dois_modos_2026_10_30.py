"""Os dois modos da stack: `off` (busca rápida) e `commitment` (certificado).

A distinção existia no papel desde o `certmode.py`, mas não se sustentava na
prática: `open_engine(..., certificate_mode="commitment")` sem config
explícita construía com os defaults do motor — `random, s1=64` — que medem
**0,00%** de cobertura. O modo dizia "vou certificar" e a engine não tinha o
que certificar.

Medido em MedMCQA real (12.000 docs, d=384, 30 queries):

    open_engine(mode=commitment) SEM config     0,00%   ok=False
    open_engine(..., pca s1=64)                18,33%   ok=True
    open_engine(..., rank pleno)               99,98%   ok=True
    open_engine(..., config do ROTEADOR)       99,48%   ok=True

O que faltava: o modo certificado pedir a config ao roteador.
"""
import numpy as np
import pytest

from winnex_tracer.core.certmode import (
    CertificateMode, CertificateModeError, open_engine, coverage_report,
)


@pytest.fixture(scope="module")
def corpus():
    """Corpus de baixo posto: tem manifold, então o PCA tem o que capturar.
    É o regime em que a certificação funciona — e o que o roteador detecta."""
    rng = np.random.default_rng(7)
    n, d, posto = 4000, 384, 16
    X = (rng.standard_normal((n, posto)).astype(np.float32)
         @ rng.standard_normal((posto, d)).astype(np.float32))
    X /= np.linalg.norm(X, axis=1, keepdims=True)
    return np.ascontiguousarray(X, dtype=np.float32)


@pytest.fixture(scope="module")
def queries(corpus):
    rng = np.random.default_rng(1)
    Q = corpus[:20] + 0.05 * rng.standard_normal((20, corpus.shape[1])).astype(np.float32)
    Q /= np.linalg.norm(Q, axis=1, keepdims=True)
    return np.ascontiguousarray(Q)


@pytest.fixture(autouse=True)
def _chave(monkeypatch):
    """`coverage_report` assina para medir; precisa de chave efêmera."""
    from nacl.signing import SigningKey
    sk = SigningKey.generate()
    monkeypatch.setenv("WORM_SIGNING_PRIVATE_KEY_HEX", sk.encode().hex())
    monkeypatch.setenv("WINNEX_TRACER_ED25519_KEY", sk.encode().hex())


# ---------------------------------------------------------------------------
# O modo certificado CERTIFICA
# ---------------------------------------------------------------------------

def test_commitment_sem_config_usa_o_roteador(corpus, queries):
    """REGRESSÃO do defeito central: o modo dizia certificar e não certificava.

    Sem config explícita, a engine passa a ser construída com o que o roteador
    decide — `pca_corpus` num corpus dobrável — em vez dos defaults do motor.
    """
    eng = open_engine(corpus, certificate_mode=CertificateMode.COMMITMENT, k=3)
    rep = coverage_report(eng, queries, k=3, max_sample=20)
    assert rep["cobertura_mediana"] > 0.5, (
        f"o modo 'commitment' produziu {100*rep['cobertura_mediana']:.2f}% de "
        f"cobertura — config aplicada: {eng.route_decision}")
    assert eng.route_decision is not None, "o roteador não foi consultado"
    assert eng.route_decision["basis"] == "pca_corpus"


def test_modo_off_nao_roteia_e_e_mais_rapido(corpus, queries):
    """O modo rápido quer os defaults rápidos. Rotear para PCA o encareceria
    sem dar nada em troca — `off` não certifica por definição."""
    eng = open_engine(corpus, certificate_mode=CertificateMode.OFF, k=3)
    assert eng.route_decision is None, "off não deveria projetar o corpus"


def test_config_explicita_vence_o_roteador(corpus, queries):
    """Quem passa config sabe o que quer; o roteador é conveniência, não
    autoridade."""
    eng = open_engine(corpus, certificate_mode=CertificateMode.COMMITMENT, k=3,
                      basis="random", stage1_dim=32, stage2_dim=0)
    assert eng.route_decision["basis"] == "pca_corpus"   # o que ele recomendou
    assert eng.build_kwargs["basis"] == "random"          # o que foi aplicado
    assert eng.build_kwargs["stage1_dim"] == 32


# ---------------------------------------------------------------------------
# As garantias de cada modo continuam separadas
# ---------------------------------------------------------------------------

def test_modo_off_recusa_operacao_certificada(corpus):
    """O Tracer não assina a partir de `off` — e isso não mudou."""
    eng = open_engine(corpus, certificate_mode=CertificateMode.OFF, k=3)
    with pytest.raises(CertificateModeError):
        eng.search_audited(np.ascontiguousarray(corpus[0]))


def test_modo_commitment_permite_busca_simples(corpus):
    """O modo certificado não impede usar a busca simples — ela é a base."""
    eng = open_engine(corpus, certificate_mode=CertificateMode.COMMITMENT, k=3)
    r = eng.search(np.ascontiguousarray(corpus[0]))
    assert len(r.indices) > 0


def test_modo_invalido_levanta(corpus):
    with pytest.raises(CertificateModeError):
        open_engine(corpus, certificate_mode="certificado-talvez")


# ---------------------------------------------------------------------------
# A decisão do roteador é auditável
# ---------------------------------------------------------------------------

def test_route_decision_declara_a_config_e_a_certificabilidade(corpus):
    """O modo só é auditável se a config que ele escolheu também for visível."""
    eng = open_engine(corpus, certificate_mode=CertificateMode.COMMITMENT, k=3)
    d = eng.route_decision
    for campo in ("basis", "stage1_dim", "stage2_dim", "k1_fraction",
                  "certifiable"):
        assert campo in d, f"a decisão do roteador não declara {campo}"
    assert d["certifiable"] is True


def test_corpus_nao_dobravel_avisa_mesmo_roteando(corpus):
    """Num corpus sem estrutura, nem o roteador salva — e ele DECLARA isso em
    vez de devolver um selo silenciosamente vazio."""
    rng = np.random.default_rng(3)
    X = rng.standard_normal((3000, 384)).astype(np.float32)
    X /= np.linalg.norm(X, axis=1, keepdims=True)
    X = np.ascontiguousarray(X)
    eng = open_engine(X, certificate_mode=CertificateMode.COMMITMENT, k=3)
    d = eng.route_decision
    if d["certifiable"] is False:
        assert d["certification_action"], (
            "declarou não-certificável sem dizer o que fazer")
