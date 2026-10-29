"""Regressão da cadeia WORM: `prev_hash` tem de ser o último bloco GRAVADO.

O defeito (corrigido em 1.1.2)
------------------------------
`WormStorage.__init__` lia o estado da cadeia (`.chain`) uma única vez e
guardava em `self._last_hash`. Todo `append` subsequente montava o bloco com
esse valor em cache. Com duas instâncias vivas sobre o mesmo `base_path`, ou
com uma instância longeva e outra efêmera, o segundo escritor gravava um
`prev_hash` obsoleto e a cadeia se rompia de forma PERMANENTE — sem que
ninguém tivesse adulterado nada. `verify_integrity()` então reportava
violação num histórico íntegro.

Esse é o padrão de uso NORMAL do tracer-med, e não um caso exótico:

  * `EvidenceChain.__init__` guarda um `WormStorage` pela vida do processo
    (`winnex_tracer/med/core/evidence.py`);
  * `ClinicalTriageEngine.run_triage` abre `WormStorage(...)` novo a cada
    consulta (`winnex_tracer/med/core/clinical.py`).

Medido antes da correção: 4 processos × 5 appends → 20 blocos, 9 violações.
Depois: 20 blocos, 0 violações.

O que estes testes fixam
------------------------
1. Uma instância efêmera por append (o caso que já funcionava).
2. Instância LONGEVA escrevendo depois de uma efêmera — a regressão exata.
3. Concorrência multiprocesso real (fcntl.flock).
4. A cadeia ainda detecta adulteração — a correção não pode ter afrouxado a
   verificação para "passar".
"""
import json
import multiprocessing as mp
import shutil
import sys

import pytest

from winnex_tracer.persistence import WormStorage


def _verify(base):
    return WormStorage(base_path=base).verify_integrity()


# ---------------------------------------------------------------------------
# 1. O caso que já funcionava (controle — se este quebrar, a correção regrediu)
# ---------------------------------------------------------------------------
def test_ephemeral_instances_chain_ok(tmp_path):
    base = str(tmp_path)
    for i in range(4):
        WormStorage(base_path=base).append({"audit_id": f"a{i}"})
    rep = _verify(base)
    assert rep["total_blocks"] == 4
    assert rep["chain_integrity_verified"], rep["violations_detail"]


# ---------------------------------------------------------------------------
# 2. A REGRESSÃO: instância longeva + instância efêmera no mesmo diretório
# ---------------------------------------------------------------------------
def test_long_lived_instance_sees_writes_from_others(tmp_path):
    """O `prev_hash` do bloco 3 tem de apontar para o bloco 2 (hash real).

    Sob o bug, o bloco 3 saía com `prev_hash == ""` (o estado que a instância
    longeva tinha em cache desde a construção), e `verify_integrity()` acusava
    exatamente `{"block": 2, "expected_prev": <hash do bloco 1>, "found_prev": ""}`.
    """
    base = str(tmp_path)
    long_lived = WormStorage(base_path=base)          # cache = b"" agora

    for i in range(2):
        WormStorage(base_path=base).append({"audit_id": f"e{i}"})

    receipt = long_lived.append({"audit_id": "triage"})
    rep = _verify(base)

    assert rep["chain_integrity_verified"], rep["violations_detail"]
    assert rep["violations"] == 0
    # O prev_hash do último bloco é não vazio e é o hash do bloco anterior.
    assert receipt["worm_prev_hash"] != ""
    assert receipt["worm_prev_hash"] == _hash_of_block(base, 1)


def _hash_of_block(base, idx):
    blocks = []
    for f in sorted(WormStorage(base_path=base).base_path.rglob("records.jsonl")):
        with open(f) as fh:
            for line in fh:
                line = line.strip()
                if line:
                    blocks.append(json.loads(line))
    return blocks[idx]["block_hash"]


def test_repeated_appends_from_one_instance(tmp_path):
    """Uma instância sozinha continua encadeando (sem falso positivo)."""
    base = str(tmp_path)
    w = WormStorage(base_path=base)
    for i in range(5):
        w.append({"audit_id": f"s{i}"})
    rep = _verify(base)
    assert rep["total_blocks"] == 5
    assert rep["chain_integrity_verified"], rep["violations_detail"]


# ---------------------------------------------------------------------------
# 3. Concorrência real entre processos
# ---------------------------------------------------------------------------
def _worker(args):
    base, pid, n = args
    # O padrão do serviço: uma instância por processo, anexando ao longo da vida.
    w = WormStorage(base_path=base)
    for j in range(n):
        w.append({"audit_id": f"p{pid}-{j}"})


def test_concurrent_processes_keep_chain_intact(tmp_path):
    base = str(tmp_path)
    procs = [mp.Process(target=_worker, args=((base, i, 5),)) for i in range(4)]
    for p in procs:
        p.start()
    for p in procs:
        p.join()

    assert all(p.exitcode == 0 for p in procs), [p.exitcode for p in procs]
    rep = _verify(base)
    assert rep["total_blocks"] == 20, rep
    assert rep["chain_integrity_verified"], rep["violations_detail"]
    assert rep["violations"] == 0, rep["violations_detail"]


# ---------------------------------------------------------------------------
# 4. A correção NÃO pode ter afrouxado a detecção de adulteração
# ---------------------------------------------------------------------------
def test_tampering_still_detected(tmp_path):
    """Se a cadeia passasse a "verificar" depois da correção, isso seria pior
    que o bug: o selo atestaria integridade sobre conteúdo alterado."""
    base = str(tmp_path)
    w = WormStorage(base_path=base)
    w.append({"audit_id": "a1", "valor": 10})
    w.append({"audit_id": "a2", "valor": 20})

    daily = sorted(WormStorage(base_path=base).base_path.rglob("records.jsonl"))[0]
    lines = [json.loads(x) for x in daily.read_text().splitlines() if x.strip()]
    lines[0]["data"]["valor"] = 999          # adultera o conteúdo do bloco 0
    daily.write_text("\n".join(json.dumps(b, ensure_ascii=False) for b in lines) + "\n")

    rep = _verify(base)
    assert not rep["chain_integrity_verified"]
    assert rep["violations"] >= 1


def test_survives_on_non_posix_without_fcntl(tmp_path):
    """Sem fcntl (Windows) o append ainda tem de funcionar — só perde a
    exclusão entre processos, que é explícita e documentada, não um crash."""
    import winnex_tracer.persistence.worm as worm_mod
    saved = worm_mod.fcntl
    try:
        worm_mod.fcntl = None
        base = str(tmp_path)
        w = worm_mod.WormStorage(base_path=base)
        w.append({"audit_id": "x1"})
        w.append({"audit_id": "x2"})
        rep = worm_mod.WormStorage(base_path=base).verify_integrity()
        assert rep["total_blocks"] == 2
        assert rep["chain_integrity_verified"], rep["violations_detail"]
    finally:
        worm_mod.fcntl = saved
