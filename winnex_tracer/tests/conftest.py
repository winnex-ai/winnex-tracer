"""
Configuração compartilhada dos testes.

O Tracer precisa do motor Madhava
=================================
`med`, `jus`, `gap` e `gov` recusam operar sem `winnex-madhava`:

    RuntimeError: ClinicalTriageEngine: winnex-madhava is required for
    soundness-guaranteed triage. Install it (pip install winnex-madhava).
    Refusing to fall back to a numpy scan — the proof guarantee requires
    the real motor.

Isso é o comportamento CORRETO — é o princípio de honestidade aplicado: sem
o limite de Cauchy-Schwarz não existe certificado, e um selo vazio
aparentando validade é pior que uma falha barulhenta.

O problema era de sequência suja: os testes desses quatro módulos assumiam
o motor instalado sem declarar isso, então em ambiente limpo eles falhavam
com `RuntimeError` — 29 testes, sem que ficasse claro se era bug ou
dependência faltando.

Esta configuração torna a dependência explícita: os testes dos módulos que
requerem o motor são marcados com `requires_engine` e ficam SKIPPED (com
razão legível) quando ele não está disponível, em vez de falhar de forma
ambígua. `gov` não é marcado em bloco porque parte dos testes de compliance
e jurisdição não toca o motor — nesses, o próprio teste decide.
"""
import pytest


def _has_engine() -> bool:
    try:
        import winnex_madhava  # noqa: F401
        return True
    except ImportError:
        return False


HAS_ENGINE = _has_engine()

requires_engine = pytest.mark.skipif(
    not HAS_ENGINE,
    reason=(
        "requer winnex-madhava (pip install 'winnex-tracer[madhava]'). "
        "med/jus/gap recusam operar sem o motor porque o certificado de "
        "exclusao depende do limite de Cauchy-Schwarz — a recusa e o "
        "comportamento correto, nao um bug."
    ),
)
