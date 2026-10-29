#!/usr/bin/env python3
"""audit_dependencies.py — auditoria de dependências da suíte, por medição.

Não adivinha. Para CADA teste, mede:

  1. resultado COM o motor instalado   (passed / failed / error)
  2. resultado SEM o motor             (passed / failed / error)
  3. importações de módulos do produto  (análise estática do AST)

E classifica:

  INDEPENDENTE   passa nos dois          -> nunca deve ser marcado/skipped
  DEPENDENTE     passa com, falha sem   -> requer o motor, marcador legítimo
  QUEBRADO       falha com o motor      -> defeito real, não é dependência
  SEMPRE_FALHA   falha nos dois         -> defeito real
  FRAGIL         passa sem, falha com   -> ordem/estado sujo

A regra de engenharia: um teste só pode ser marcado `requires_engine` se for
DEPENDENTE. Marcar INDEPENDENTE reduz cobertura silenciosamente — que é o
padrão de degradação que a suíte existe para impedir.

Uso:
    python tools/audit_dependencies.py --out dependencias.json
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import re
import subprocess
import sys
import textwrap

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTS = os.path.join(ROOT, "winnex_tracer", "tests")

# Executa pytest com winnex_madhava bloqueado (simula ambiente sem o extra).
BLOCKER = textwrap.dedent('''
    import sys
    class _Blocker:
        def find_module(self, name, path=None):
            return self if name == "winnex_madhava" or name.startswith("winnex_madhava.") else None
        def load_module(self, name):
            raise ImportError("bloqueado: simula ambiente sem winnex-madhava")
    sys.meta_path.insert(0, _Blocker())
''')


def _run(pytest_args, block_engine: bool):
    """Roda pytest e devolve {nodeid: outcome}."""
    cmd = [sys.executable]
    if block_engine:
        cmd += ["-c", BLOCKER + textwrap.dedent('''
            import pytest, sys
            sys.exit(pytest.main(sys.argv[1:]))
        ''')[1:], "-q", "--no-header", "-p", "no:cacheprovider",
            "--tb=no", "-rA"]
    else:
        cmd += ["-m", "pytest", "-q", "--no-header", "-p", "no:cacheprovider",
                "--tb=no", "-rA"]
    cmd += pytest_args
    env = dict(os.environ, PYTHONPATH=ROOT)
    out = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, env=env)
    return _parse(out.stdout + out.stderr), out.stdout + out.stderr


_OUTCOME_LINE = re.compile(
    r"^(PASSED|FAILED|ERROR|SKIPPED|XFAIL|XPASS)\s+(\S+)")


def _parse(text):
    res = {}
    for line in text.splitlines():
        m = _OUTCOME_LINE.match(line.strip())
        if m:
            res[m.group(2)] = m.group(1)
    return res


def _imports_of(path):
    """Módulos do produto importados (análise estática)."""
    try:
        tree = ast.parse(open(path, encoding="utf-8").read())
    except (OSError, SyntaxError):
        return set()
    mods = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            mods.add(node.module)
    return {m for m in mods if m.startswith("winnex_tracer")
            or m.startswith("winnex_madhava")}


def _test_files():
    out = []
    for root, _d, files in os.walk(TESTS):
        for f in sorted(files):
            if f.startswith("test_") and f.endswith(".py"):
                out.append(os.path.join(root, f))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="dependencias.json")
    ap.add_argument("--filter", default="", help="substring do path dos testes")
    a = ap.parse_args()

    files = _test_files()
    if a.filter:
        files = [f for f in files if a.filter in f]
    rel = [os.path.relpath(f, ROOT) for f in files]

    print(f"[1] rodando {len(rel)} arquivos COM o motor...", flush=True)
    com, log_com = _run(rel, block_engine=False)
    print(f"    {len(com)} testes coletados", flush=True)

    print("[2] rodando SEM o motor...", flush=True)
    sem, log_sem = _run(rel, block_engine=True)
    print(f"    {len(sem)} testes coletados", flush=True)

    print("[3] análise estática de imports...", flush=True)
    imports = {os.path.relpath(f, ROOT): sorted(_imports_of(f)) for f in files}

    # classificação por medição
    rows = []
    nodeids = sorted(set(com) | set(sem))
    for nid in nodeids:
        with_e = com.get(nid, "MISSING")
        without = sem.get(nid, "MISSING")
        if with_e == "PASSED" and without == "PASSED":
            cat = "INDEPENDENTE"
        elif with_e == "PASSED" and without != "PASSED":
            cat = "DEPENDENTE"
        elif with_e != "PASSED" and without == "PASSED":
            cat = "FRAGIL"
        elif with_e == "FAILED" and without == "FAILED":
            cat = "SEMPRE_FALHA"
        else:
            cat = "QUEBRADO"
        f = nid.split("::")[0]
        rows.append({"nodeid": nid, "arquivo": f,
                     "com_motor": with_e, "sem_motor": without,
                     "categoria": cat, "imports": imports.get(f, [])})

    payload = {
        "resumo": {
            "total": len(rows),
            "com_motor": {k: sum(1 for r in rows if r["com_motor"] == k)
                          for k in ("PASSED", "FAILED", "ERROR", "SKIPPED")},
            "sem_motor": {k: sum(1 for r in rows if r["sem_motor"] == k)
                          for k in ("PASSED", "FAILED", "ERROR", "SKIPPED")},
            "categorias": {},
        },
        "testes": rows,
    }
    for r in rows:
        c = r["categoria"]
        payload["resumo"]["categorias"][c] = \
            payload["resumo"]["categorias"].get(c, 0) + 1

    out = os.path.join(ROOT, a.out) if not os.path.isabs(a.out) else a.out
    with open(out, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    s = payload["resumo"]
    print("\n" + "=" * 66)
    print(f"COM motor : {s['com_motor']}")
    print(f"SEM motor : {s['sem_motor']}")
    print(f"categorias: {s['categorias']}")
    print("=" * 66)

    dep = [r["nodeid"] for r in rows if r["categoria"] == "DEPENDENTE"]
    ind = [r["nodeid"] for r in rows if r["categoria"] == "INDEPENDENTE"]
    que = [r["nodeid"] for r in rows if r["categoria"] in
           ("QUEBRADO", "SEMPRE_FALHA", "FRAGIL")]
    print(f"\nDEPENDENTE   ({len(dep)}) — marcador requires_engine é legítimo")
    print(f"INDEPENDENTE ({len(ind)}) — NUNCA devem ser marcados")
    print(f"DEFEITO      ({len(que)}) — não é dependência, é bug")
    for n in que:
        r = next(x for x in rows if x["nodeid"] == n)
        print(f"    {r['categoria']:12s} {n}")
    with open(out.replace(".json", "_dep.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(dep))
    print(f"\nSalvo: {out} (+ lista de dependentes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
