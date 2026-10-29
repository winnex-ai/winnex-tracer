"""
winnex-tracer-core — Modos de certificado (escolha explícita do motor)
======================================================================

DISTINÇÃO FUNDAMENTAL
---------------------
O **Tracer** existe para certificar. `make_worm_record` sempre assina — isso
não é opcional e não deve ser. É o que distingue o Tracer do Madhava.

O **Madhava**, por si, é uma busca vetorial. Ele pode operar em três regimes,
e quem chama escolhe. O problema, antes deste módulo, era que essa escolha
era implícita: `search()` não certifica nada, mas nada avisava, e era fácil
assinar um certificado de cobertura zero como se fosse resultado.

Este módulo torna a escolha **explícita, nomeada e verificável**:

    certificate_mode="off"         search()                   sem certificado
    certificate_mode="commitment"  search_with_commitment()   certificado leve
    certificate_mode="audited"     search_with_audit()/audited certificado + amostras

USO
---
    from winnex_tracer.core.certmode import open_engine, coverage_report

    # 1. Escolha explícita no build
    eng = open_engine(corpus, certificate_mode="commitment", k=3)

    # 2. A engine só aceita a operação que o modo permite
    eng.search(q)                    # OK
    eng.search_audited(q)            # CertificateModeError — modo não permite

    # 3. Antes de assinar, meça a cobertura
    rep = coverage_report(eng, [q], k=3)
    if rep["ok"]:
        rec = eng.make_worm_record(q)     # assina (Tracer sempre certifica)

POR QUE ISSO IMPORTA — medição de 2026-10-28
--------------------------------------------
Ver `ESTUDO_STACK_CERTIFICADO.md`. Resumo:

  corpus real de saúde (145.673 docs), MiniLM-L6 (384d), k=3:
      basis="random"    s1=64/s2=128  ->  cobertura  0,000%
      basis="pca_corpus" s1=64/s2=128  ->  cobertura 93,299%
      basis="random"    s1=d/s2=d      ->  cobertura 99,998%  (rank pleno)

A cobertura é propriedade do **corpus + configuração**, não do motor. Um
certificado vazio é criptograficamente válido e semanticamente inútil: atesta
que "nada foi provado", não que "nada deveria ser provado".
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

import numpy as np

__all__ = [
    "CertificateMode",
    "CertificateModeError",
    "CoverageError",
    "certificate_mode",
    "open_engine",
    "InstrumentedEngine",
    "coverage_report",
]


# ---------------------------------------------------------------------------
# Modos
# ---------------------------------------------------------------------------
class CertificateMode:
    """Os três regimes de certificado do motor.

    OFF
        `search()` — a busca mais rápida. NÃO produz certificado.
        O Tracer não pode assinar a partir deste modo; use-o apenas quando
        não há auditoria envolvida.

    COMMITMENT
        `search_with_commitment()` — devolve o commitment leve
        (`total_excluded_count`, `global_threshold`, amostra de borda).
        Custo medido: **+0,09 ms** sobre `search()` em 145.673 documentos.
        Este é o modo recomendado para produção auditável.

    AUDITED
        `search_audited()` — devolve o registro completo por documento
        excluído (`doc_id`, cosseno verdadeiro, cosseno projetado, resíduo,
        `upper_bound`, `threshold`). Mais caro; para investigação e perícia.
    """

    OFF = "off"
    COMMITMENT = "commitment"
    AUDITED = "audited"

    ALL = (OFF, COMMITMENT, AUDITED)

    #: modo -> nome do método no motor
    _METHOD = {
        OFF: "search",
        COMMITMENT: "search_with_commitment",
        AUDITED: "search_audited",
    }

    #: modos que produzem certificado (o Tracer só assina a partir destes)
    CERTIFYING = (COMMITMENT, AUDITED)


class CertificateModeError(ValueError):
    """Modo de certificado inválido, ou operação não permitida pelo modo."""


class CoverageError(RuntimeError):
    """O certificado foi pedido, mas a cobertura é insuficiente para assinar."""


def _validate_mode(mode: str) -> str:
    """Normaliza e valida um modo de certificado.

    Aceita variações comuns ("on", "cert", "certificate") para reduzir atrito,
    mas o valor canônico é sempre um de CertificateMode.ALL.

    Raises:
        CertificateModeError: se o modo não for reconhecido.
    """
    if not isinstance(mode, str):
        raise CertificateModeError(
            f"certificate_mode deve ser str, recebeu {type(mode).__name__}"
        )
    m = mode.strip().lower()
    aliases = {
        "on": CertificateMode.COMMITMENT,
        "cert": CertificateMode.COMMITMENT,
        "certificate": CertificateMode.COMMITMENT,
        "commit": CertificateMode.COMMITMENT,
        "true": CertificateMode.COMMITMENT,
        "none": CertificateMode.OFF,
        "false": CertificateMode.OFF,
        "no": CertificateMode.OFF,
        "audit": CertificateMode.AUDITED,
        "full": CertificateMode.AUDITED,
    }
    m = aliases.get(m, m)
    if m not in CertificateMode.ALL:
        raise CertificateModeError(
            f"certificate_mode={mode!r} inválido. "
            f"Use um de {CertificateMode.ALL} "
            f'(ex.: certificate_mode="commitment").'
        )
    return m


#: Alias público da validação, para quem quiser normalizar antes de construir.
certificate_mode = _validate_mode


# ---------------------------------------------------------------------------
# Engine instrumentada
# ---------------------------------------------------------------------------
class InstrumentedEngine:
    """Envolve uma engine do Madhava e impõe o modo de certificado escolhido.

    A engine subjacente é acessível como `.engine` para casos que este módulo
    não cobre. As operações expostas respeitam o modo:

        modo="off"         -> .search() disponível; os demais levantam
        modo="commitment"  -> .search() e .search_with_commitment()
        modo="audited"     -> todas, incluindo .search_audited()

    Bloquear `search()` no modo certificado seria hostil: a busca sem
    certificado continua legítima (é só leitura). O que se bloqueia é o
    contrário — pedir certificado num modo que não o produz, que era o erro
    silencioso.
    """

    def __init__(self, engine: Any, mode: str = CertificateMode.COMMITMENT,
                 *, build_kwargs: Optional[Dict[str, Any]] = None):
        self.engine = engine
        self.mode = _validate_mode(mode)
        self.build_kwargs = dict(build_kwargs or {})

    # -- capacidades -------------------------------------------------------
    @property
    def certifies(self) -> bool:
        """Este modo produz certificado?"""
        return self.mode in CertificateMode.CERTIFYING

    def _require(self, needed: str) -> None:
        """Garante que o modo atual suporta a operação pedida."""
        order = {CertificateMode.OFF: 0,
                 CertificateMode.COMMITMENT: 1,
                 CertificateMode.AUDITED: 2}
        if order[self.mode] < order[needed]:
            raise CertificateModeError(
                f"operação exige certificate_mode={needed!r}, "
                f"mas a engine está em {self.mode!r}. "
                f'Reconstrua com open_engine(..., certificate_mode="{needed}").'
            )

    # -- busca -------------------------------------------------------------
    def search(self, query, *a, **kw):
        """Busca sem certificado. Sempre permitida (é só leitura)."""
        return self.engine.search(query, *a, **kw)

    def search_with_commitment(self, query, *a, **kw):
        """Certificado leve. Exige modo >= commitment."""
        self._require(CertificateMode.COMMITMENT)
        return self.engine.search_with_commitment(query, *a, **kw)

    def search_audited(self, query, *a, **kw):
        """Certificado detalhado. Exige modo == audited."""
        self._require(CertificateMode.AUDITED)
        return self.engine.search_audited(query, *a, **kw)

    # `search_with_audit` é o nome usado internamente pelo make_worm_record em
    # algumas versões; expor como alias evita surpresa.
    def search_with_audit(self, query, *a, **kw):
        self._require(CertificateMode.AUDITED)
        fn = getattr(self.engine, "search_with_audit",
                     getattr(self.engine, "search_audited"))
        return fn(query, *a, **kw)

    # -- delegação transparente -------------------------------------------
    def __getattr__(self, name):
        return getattr(self.engine, name)

    def __repr__(self):
        return (f"InstrumentedEngine(mode={self.mode!r}, "
                f"engine={type(self.engine).__name__})")

    # -- conveniência: o caminho do Tracer ---------------------------------
    def make_worm_record(self, query, k: int = 10, max_sample: int = 50,
                         *, min_coverage: float = 0.0):
        """Assina o commitment desta consulta (o Tracer SEMPRE certifica).

        Diferença em relação a `winnex_tracer.core.make_worm_record`: aqui a
        operação do motor é a do modo escolhido, e `min_coverage` permite
        recusar um selo sobre nada.

        Args:
            min_coverage: fração mínima de documentos provados descartados
                (`total_provably_excluded / n_docs`) para aceitar assinar.
                Default 0.0 = comportamento histórico. Use > 0 para exigir
                que o certificado carregue prova de verdade.
        """
        from .commitment import make_worm_record as _mwr

        if not self.certifies:
            raise CertificateModeError(
                'certificate_mode="off" não produz certificado; '
                "o Tracer não tem o que assinar. "
                'Reconstrua com certificate_mode="commitment".'
            )
        rec = _mwr(self.engine, query, k=k, max_sample=max_sample)
        if min_coverage > 0:
            n = int(getattr(self.engine, "num_vectors", lambda: 0)() or 0)
            excl = int(rec.get("total_provably_excluded", 0))
            cob = (excl / n) if n else 0.0
            if cob < min_coverage:
                raise CoverageError(
                    f"cobertura {cob*100:.3f}% < mínimo "
                    f"{min_coverage*100:.1f}% ({excl}/{n} provados). "
                    "O selo atestaria que nada foi provado. "
                    'Verifique a configuração do motor: use '
                    'basis="pca_corpus" ou stage1_dim=stage2_dim=d.'
                )
            rec["_coverage"] = round(cob, 6)
        return rec


# ---------------------------------------------------------------------------
# Construção
# ---------------------------------------------------------------------------
def open_engine(corpus, certificate_mode: str = CertificateMode.COMMITMENT,
                **build_kwargs) -> InstrumentedEngine:
    """Constrói uma engine do Madhava já com o modo de certificado explícito.

    Exemplo:
        eng = open_engine(X, certificate_mode="commitment", k=3,
                          basis="pca_corpus", stage1_dim=64, stage2_dim=128)

    Args:
        corpus: (n, d) embeddings.
        certificate_mode: "off" | "commitment" | "audited".
        **build_kwargs: repassados a `winnex_madhava.build_engine`.

    Raises:
        CertificateModeError: modo inválido.
        ImportError: winnex_madhava ausente.
    """
    mode = _validate_mode(certificate_mode)
    try:
        import winnex_madhava as wm
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "open_engine requer winnex-madhava: pip install winnex-madhava"
        ) from exc

    kw = dict(build_kwargs)
    kw.setdefault("dim", int(np.asarray(corpus).shape[1]))
    eng = wm.build_engine(corpus, **kw)
    return InstrumentedEngine(eng, mode, build_kwargs=kw)


# ---------------------------------------------------------------------------
# Cobertura
# ---------------------------------------------------------------------------
def coverage_report(engine, queries: Iterable, k: int = 10,
                    *, max_sample: int = 50,
                    min_coverage: float = 0.0) -> Dict[str, Any]:
    """Mede quanto o certificado realmente cobre, antes de assinar nada.

    Um certificado com `total_provably_excluded == 0` é válido e inútil: ele
    atesta que o bound não provou nada. Esta função responde "o selo carrega
    prova?" com números, para que a decisão de assinar seja informada.

    Args:
        engine: engine do Madhava ou InstrumentedEngine.
        queries: sequência de vetores de consulta.
        k: top-k.
        max_sample: amostra de borda por consulta.
        min_coverage: limiar para `ok`. Default 0.0 (só exige > 0 quando
            qualquer prova aparecer). Passe o seu SLA, ex. 0.5.

    Returns:
        dict com n_docs, n_queries, cobertura mediana/mínima/máxima,
        consultas_com_amostra, consultas_vazias, ok, e a config do motor.
    """
    from .commitment import make_worm_record as _mwr

    eng = engine.engine if isinstance(engine, InstrumentedEngine) else engine
    qs = list(queries)
    n = int(getattr(eng, "num_vectors", lambda: 0)() or 0)

    excl: List[int] = []
    smp: List[int] = []
    for q in qs:
        rec = _mwr(eng, np.ascontiguousarray(q), k=k, max_sample=max_sample)
        excl.append(int(rec.get("total_provably_excluded", 0)))
        smp.append(len(rec.get("sampled_records", []) or []))

    nq = max(1, len(qs))
    cob = [(e / n) if n else 0.0 for e in excl]
    mediana = float(np.median(cob)) if cob else 0.0
    vazias = sum(1 for e in excl if e == 0)

    return {
        "n_docs": n,
        "n_queries": len(qs),
        "cobertura_mediana": round(mediana, 6),
        "cobertura_minima": round(min(cob), 6) if cob else 0.0,
        "cobertura_maxima": round(max(cob), 6) if cob else 0.0,
        "excluidos_mediana": int(np.median(excl)) if excl else 0,
        "consultas_com_amostra": sum(1 for s in smp if s > 0),
        "consultas_vazias": vazias,
        "fracao_vazias": round(vazias / nq, 4),
        # `ok` responde a pergunta que importa: o certificado carrega prova?
        # Exigir cobertura mediana > 0 (nao apenas >= min_coverage) impede que
        # um certificado vazio em quase todas as consultas seja reportado como
        # saudavel quando min_coverage=0.
        "ok": bool(mediana > 0 and mediana >= min_coverage),
        "min_coverage_exigido": min_coverage,
        "config": _safe_config(eng),
        "leitura": _leitura(mediana, vazias, nq),
    }


def _safe_config(eng) -> Dict[str, Any]:
    try:
        c = eng.config()
        return {k: getattr(c, k) for k in dir(c)
                if not k.startswith("_") and not callable(getattr(c, k))}
    except Exception:
        return {}


def _leitura(mediana: float, vazias: int, nq: int) -> str:
    if mediana >= 0.5:
        return ("certificado com prova real: metade ou mais do corpus e "
                "provadamente descartado por consulta.")
    if mediana > 0:
        return (f"certificado parcial ({mediana*100:.2f}%): carrega prova, "
                "mas cobre pouco. Verifique basis/stage_dim.")
    if vazias == nq:
        return ("certificado VAZIO em todas as consultas: o bound nao provou "
                "nada. Nao assine como se fosse resultado. Use "
                'basis="pca_corpus" ou stage1_dim=stage2_dim=d.')
    return "certificado vazio na maioria das consultas; cobertura marginal."
