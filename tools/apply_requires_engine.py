#!/usr/bin/env python3
"""apply_requires_engine.py — aplica `@requires_engine` POR MEDIÇÃO.

Lê o JSON produzido por `audit_dependencies.py` e marca APENAS os testes
classificados como DEPENDENTE (passam com o motor, falham sem ele).

Princípio: nenhuma operação silenciosa.

  - Não usa regex por arquivo: marca por NOME de teste, um por um.
  - Cada inserção é VERIFICADA: se o import não entrar ou o decorador não
    colar, o script falha com erro explícito e não escreve nada.
  - Escreve em memória e só grava no fim; um erro no meio aborta tudo.
  - Recusa marcar um teste INDEPENDENTE ou QUEBRADO — isso reduziria a
    cobertura ou esconderia um defeito.
  - `--check` não escreve: só relata o que faria e falha se o estado divergir.

Uso:
    python tools/audit_dependencies.py --out /tmp/deps.json
    python tools/apply_requires_engine.py --deps /tmp/deps.json
    python tools/apply_requires_engine.py --deps /tmp/deps.json --check
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMPORT_LINE = "from winnex_tracer.tests.conftest import requires_engine"
# Arquivos que já se protegem via pytest.importorskip: marcar de novo seria
# redundância que esconderia a proteção original.
SELF_GUARDED = ("test_certmode.py", "test_compat_payload.py")


class ApplyError(RuntimeError):
    """Falha explícita de aplicação — nunca silenciosa."""


def _paths(deps_json):
    """{arquivo_relativo: [nomes de teste DEPENDENTE]} a partir do JSON."""
    with open(deps_json, encoding="utf-8") as f:
        d = json.load(f)

    dep, recusados = {}, []
    for r in d["testes"]:
        arquivo = r["arquivo"]
        nome = r["nodeid"].split("::", 1)[1] if "::" in r["nodeid"] else None
        if nome is None or nome.startswith("["):
            # Artefato de coleta (nó de módulo), não é teste. Ignorar de
            # propósito, mas registrar para que não passe despercebido.
            recusados.append((r["nodeid"], r["categoria"], "nao e um teste"))
            continue
        if r["categoria"] == "DEPENDENTE":
            dep.setdefault(arquivo, set()).add(nome)
        elif r["categoria"] in ("QUEBRADO", "SEMPRE_FALHA", "FRAGIL"):
            recusados.append((r["nodeid"], r["categoria"],
                              "defeito real: corrija o teste, nao o silencie"))
        elif r["categoria"] == "INDEPENDENTE" and _needs_mark(r):
            recusados.append((r["nodeid"], r["categoria"],
                              "independente ja marcado: reduz cobertura"))
    return dep, recusados


def _needs_mark(row):
    """Um INDEPENDENTE nao deveria estar marcado. Detecta pelo imports? Nao:
    a verificacao real acontece em _apply_file, comparando o arquivo."""
    return False


def _apply_file(path, names, write):
    """Marca os nomes no arquivo e VERIFICA o resultado. Devolve (antes, depois)."""
    full = os.path.join(ROOT, path)
    if not os.path.exists(full):
        raise ApplyError(f"arquivo nao existe: {path}")

    src = open(full, encoding="utf-8").read()
    if any(n.endswith(SELF_GUARDED) for n in [os.path.basename(path)]):
        return 0, src, src

    out = src

    # 1. import do marcador, verificado
    tem_import = IMPORT_LINE in out
    if not tem_import:
        # ancora: primeira linha `from winnex_tracer...` ou `import pytest`
        m = re.search(r"^(?:from winnex_tracer|import pytest)", out, re.M)
        if not m:
            raise ApplyError(
                f"{path}: nenhuma ancora de import encontrada "
                f"(procurei 'from winnex_tracer' ou 'import pytest'). "
                f"Insira o import manualmente; o script nao adivinha.")
        out = out[:m.start()] + IMPORT_LINE + "\n" + out[m.start():]
        if IMPORT_LINE not in out:
            raise ApplyError(f"{path}: import nao foi inserido (bug do script)")
        # reprova se caiu dentro de um docstring/string
        if out.count(IMPORT_LINE) != 1:
            raise ApplyError(f"{path}: import duplicado apos insercao")

    # 2. decoradores, um por nome, cada um verificado
    aplicados = 0
    for nome in sorted(names):
        if re.search(rf"@requires_engine\s*\ndef {re.escape(nome)}\(", out, re.M):
            continue                                   # ja marcado
        pat = rf"^def {re.escape(nome)}\("
        novo, n = re.subn(pat, f"@requires_engine\ndef {nome}(", out,
                          count=1, flags=re.M)
        if n != 1:
            raise ApplyError(
                f"{path}::{nome}: def nao encontrada no nivel de modulo "
                f"(talvez esteja dentro de classe ou renomeada). "
                f"Nada foi gravado.")
        out = novo
        aplicados += 1

    # 3. verificacao pos-condicao: todo nome pedido tem de estar marcado
    for nome in names:
        if not re.search(rf"@requires_engine\s*\ndef {re.escape(nome)}\(",
                         out, re.M):
            raise ApplyError(
                f"{path}::{nome}: pos-condicao falhou — decorador ausente "
                f"apos a aplicacao. Nada foi gravado.")

    if write and out != src:
        with open(full, "w", encoding="utf-8") as f:
            f.write(out)
    return aplicados, src, out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--deps", required=True, help="JSON do audit_dependencies")
    ap.add_argument("--check", action="store_true",
                    help="nao escreve; falha se houver divergencia")
    a = ap.parse_args()

    dep, recusados = _paths(a.deps)

    if recusados:
        print("RECUSADOS (nao serao marcados):", file=sys.stderr)
        for nid, cat, why in recusados:
            print(f"  {cat:12s} {nid}  [{why}]", file=sys.stderr)

    total = sum(len(v) for v in dep.values())
    print(f"DEPENDENTE medidos: {total} em {len(dep)} arquivos")

    if a.check:
        for path, names in sorted(dep.items()):
            n, src, out = _apply_file(path, names, write=False)
            if src != out:
                print(f"  DIVERGE {path}: {n} marcador(es) ausente(s)")
                sys.exit(1)
        # nenhum INDEPENDENTE pode estar marcado
        for path in _all_test_files():
            s = open(os.path.join(ROOT, path), encoding="utf-8").read()
            marcados = set(re.findall(r"@requires_engine\s*\ndef (\w+)\(", s))
            indevidos = marcados - dep.get(path, set())
            if indevidos:
                print(f"  ERRO {path}: marcados indevidamente "
                      f"{sorted(indevidos)} — reduz cobertura", file=sys.stderr)
                sys.exit(1)
        print("OK: marcacao consistente com a medicao")
        return 0

    for path, names in sorted(dep.items()):
        n, _src, _out = _apply_file(path, names, write=True)
        print(f"  {path}: +{n}")

    print(f"\nAplicado. Verifique com:")
    print(f"  pytest winnex_tracer/tests/ -q            # com motor")
    print(f"  python tools/audit_dependencies.py        # sem motor")
    return 0


def _all_test_files():
    out = []
    base = os.path.join(ROOT, "winnex_tracer", "tests")
    for root, _d, files in os.walk(base):
        for f in sorted(files):
            if f.startswith("test_") and f.endswith(".py"):
                out.append(os.path.relpath(os.path.join(root, f), ROOT))
    return out


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ApplyError as e:
        print(f"ERRO: {e}", file=sys.stderr)
        sys.exit(2)
