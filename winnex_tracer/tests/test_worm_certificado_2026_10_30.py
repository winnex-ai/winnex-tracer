"""Três correções no WORM e no certificado (2026-10-30).

Cada uma foi encontrada por teste adversarial, e cada teste abaixo reproduz o
ataque que a motivou. O que importa aqui não é "o código roda" — é que a
afirmação feita no registro seja **checável**, e que o WORM não perca blocos
em silêncio.
"""
import json
import os
import pathlib
import tempfile

import numpy as np
import pytest
from nacl.signing import SigningKey


@pytest.fixture()
def chave(monkeypatch):
    """Chave efêmera por teste — nunca a de produção, nunca em disco."""
    sk = SigningKey.generate()
    monkeypatch.setenv("WORM_SIGNING_PRIVATE_KEY_HEX", sk.encode().hex())
    monkeypatch.setenv("WINNEX_TRACER_ED25519_KEY", sk.encode().hex())
    return sk.verify_key.encode().hex()


@pytest.fixture()
def worm():
    from winnex_tracer.persistence import WormStorage
    tmp = tempfile.mkdtemp()
    yield WormStorage(tmp)
    import shutil
    shutil.rmtree(tmp, ignore_errors=True)


def _payload(**kw):
    base = {
        "audit_id": "t", "total_provably_excluded": 0,
        "global_threshold": float(0.5).hex(), "bound_pairs": 20000,
        "bound_violations": 0, "indices": [1, 2, 3], "sampled_records": [],
        "k_requested": 3,
    }
    base.update(kw)
    return base


# ---------------------------------------------------------------------------
# 1. TRUNCAMENTO — o WORM apagava o fim sem acusar
# ---------------------------------------------------------------------------

def test_truncamento_do_fim_e_detectado(worm):
    """REGRESSÃO. A verificação validava a cadeia CONTRA ELA MESMA: cada
    bloco confere prev_hash com o anterior. Apagar o fim não viola nenhuma
    dessas relações — os sobreviventes continuam consistentes.

    Medido antes da correção: 20 blocos → apagar 5 → violations=0,
    chain_integrity_verified=True, e o .chain apontando para um hash que não
    existia mais em disco.
    """
    for i in range(20):
        worm.append({"audit_id": f"a{i}", "v": i})
    assert worm.verify_integrity()["violations"] == 0

    arq = sorted(pathlib.Path(worm.base_path).rglob("records.jsonl"))[0]
    linhas = arq.read_text().strip().split("\n")
    arq.write_text("\n".join(linhas[:-5]) + "\n")

    r = worm.verify_integrity()
    assert r["total_blocks"] == 15
    assert r["truncation_detected"] is True, (
        "o WORM apagou 5 blocos do fim e não acusou")
    assert r["violations"] >= 1
    assert r["chain_integrity_verified"] is False


def test_truncamento_total_e_detectado(worm):
    """Caso extremo: todos os blocos apagados, .chain intacto."""
    for i in range(5):
        worm.append({"audit_id": f"b{i}"})
    for f in pathlib.Path(worm.base_path).rglob("records.jsonl"):
        f.write_text("")
    r = worm.verify_integrity()
    assert r["truncation_detected"] is True


def test_verificacao_contra_ancora_externa(worm):
    """A âncora copiada para FORA do filesystem fecha o buraco que o .chain
    sozinho não fecha: um atacante com permissão de escrita reescreve os dois.

    Aqui o atacante trunca o JSONL E reescreve o .chain — o
    `verify_integrity` interno não tem como saber. A âncora pinada pelo
    cliente sabe, porque compara contagem e ponta.
    """
    for i in range(10):
        worm.append({"audit_id": f"c{i}"})
    ancora = worm.compute_anchor()
    assert ancora["block_count"] == 10

    arq = sorted(pathlib.Path(worm.base_path).rglob("records.jsonl"))[0]
    linhas = arq.read_text().strip().split("\n")
    # ataque: apaga 3 e reescreve o .chain para o novo último hash
    arq.write_text("\n".join(linhas[:-3]) + "\n")
    (pathlib.Path(worm.base_path) / ".chain").write_text(
        json.loads(linhas[-4])["block_hash"])

    # a verificação interna agora passa (o atacante foi consistente)…
    assert worm.verify_integrity()["truncation_detected"] is False
    # …mas a âncora externa não.
    v = worm.verify_against_anchor(ancora)
    assert v["anchor_valid"] is False
    assert {p["field"] for p in v["problems"]} == {"block_count", "last_hash"}


# ---------------------------------------------------------------------------
# 2. BLOCK NUMBER — o receipt devolvia o número de ARQUIVOS
# ---------------------------------------------------------------------------

def test_block_number_e_sequencial(worm):
    """REGRESSÃO. Era `len(rglob("records.jsonl"))` — o número de arquivos
    diários. Medido: 20 appends no mesmo dia devolviam block_number=1 em
    todos os 20. Um receipt é a testemunha que o cliente guarda; devolver 1
    quando existem 20 é pior que não devolver nada, porque parece contador."""
    numeros = [worm.append({"audit_id": f"n{i}"})["block_number"]
               for i in range(1, 8)]
    assert numeros == list(range(1, 8))


# ---------------------------------------------------------------------------
# 3. CLAIM SANITY — a assinatura não cobria a afirmação
# ---------------------------------------------------------------------------

def test_afirmacao_impossivel_e_rejeitada(chave):
    """REGRESSÃO do achado central. Assinei com a chave LEGÍTIMA
    `total_provably_excluded = 99999` num corpus de 20.000 — exclusão
    matematicamente impossível — e o `verify_record` devolvia VALID.

    A assinatura prova que o registro não mudou. Não prova que a afirmação
    era verdadeira quando foi assinada. Este teste exige as duas coisas.
    """
    import winnex_tracer.core as tc
    rec = tc.sign_payload(_payload(total_provably_excluded=99999,
                                   n_corpus=20000, pruned_by_bound=99999))
    v = tc.verify_record(rec, chave)
    assert v["status"] == "INVALID"
    assert v["signature_valid"] is True, (
        "a assinatura em si continua válida — o que não passa é a afirmação")
    assert "impossible" in v["reason"] or ">" in v["reason"] or "contradicts" in v["reason"]


def test_motor_comprometido_afirmando_100_por_cento_e_rejeitado(chave):
    """O modelo de ameaça declarado: 'nem um binário C++ comprometido forja
    registros, porque nunca possui a chave'. Verdade para a assinatura — mas
    medido, um motor mentindo 100% do corpus passava como VALID."""
    import winnex_tracer.core as tc

    class MotorComprometido:
        def search_with_commitment(self, q, k=10, max_sample=50):
            return {"indices": [0, 1, 2], "total_excluded_count": 20000,
                    "global_threshold": 0.99, "bound_pairs": 20000,
                    "bound_violations": 0, "latency_ms": 0.1,
                    "n_corpus": 20000, "pruned_by_bound": 20000,
                    "sampled_records": [{"doc_id": 7, "upper_bound": 0.10,
                                         "excluded": True}]}

    q = np.ascontiguousarray(np.zeros(4, dtype=np.float32))
    rec = tc.make_worm_record(MotorComprometido(), q, k=3, max_sample=20)
    v = tc.verify_record(rec, chave)
    assert v["status"] == "INVALID", (
        "um motor pode afirmar excluir 100% do corpus e o selo sai VALID")


def test_pruned_por_bound_divergente_do_total_e_rejeitado(chave):
    """`total_provably_excluded` e `pruned_by_bound` descrevem o MESMO fato
    por dois caminhos. Divergir significa que um deles não descreve o que o
    motor fez."""
    import winnex_tracer.core as tc
    rec = tc.sign_payload(_payload(total_provably_excluded=100, n_corpus=20000,
                                   pruned_by_bound=900))
    v = tc.verify_record(rec, chave)
    assert v["status"] == "INVALID"


# ---------------------------------------------------------------------------
# 4. OS FALSOS POSITIVOS — registros legítimos TÊM de continuar válidos
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("total,n,k", [
    (0, 20000, 3),        # nada provado: válido e inútil, mas válido
    (19997, 20000, 3),    # exatamente N-k: o teto real, medido em rank_pleno
    (15540, 20000, 10),   # valor do corpus histórico real
    (145670, 145673, 3),  # valor do corpus arXiv real
    (9997, 10000, 3),     # top-K grande e ajustado
])
def test_registros_legitimos_continuam_validos(chave, total, n, k):
    """Contraprova: o limite em N-k é o TETO TEÓRICO. Se o motor prova
    excluir N-k documentos, os k restantes são exatamente o top-K — a
    afirmação é consistente.

    Os dois valores do meio são os dos corpora reais dos testes existentes;
    eles ficam exatamente em N-k, o que confirma o limite."""
    import winnex_tracer.core as tc
    rec = tc.sign_payload(_payload(total_provably_excluded=total, n_corpus=n,
                                   pruned_by_bound=total, k_requested=k,
                                   bound_pairs=n))
    v = tc.verify_record(rec, chave)
    assert v["status"] == "VALID", f"{total}/{n} k={k}: {v['reason']}"
    assert v["claim_checkable"] is True


def test_registro_antigo_sem_n_corpus_continua_validando(chave):
    """Compatibilidade: registros gravados antes desta correção não têm
    `n_corpus` e não podem ser confrontados. Eles continuam validando — mas o
    veredito DECLARA que a afirmação não é checável, em vez de fingir."""
    import winnex_tracer.core as tc
    velho = {"audit_id": "y", "total_provably_excluded": 15540,
             "global_threshold": float(0.4).hex(), "bound_pairs": 20000,
             "bound_violations": 0, "indices": [1, 2], "sampled_records": []}
    v = tc.verify_record(tc.sign_payload(velho), chave)
    assert v["status"] == "VALID"
    assert v["claim_checkable"] is False
    assert "not checkable" in v["reason"]


# ---------------------------------------------------------------------------
# 5. O CAMINHO REAL produz registro checável
# ---------------------------------------------------------------------------

def test_o_commitment_do_motor_produz_registro_checavel(chave):
    """O payload só é confrontável se o motor PROPAGAR os campos de escopo.
    Antes, `commitment_to_payload` lia 8 chaves fixas e descartava o resto."""
    import winnex_tracer.core as tc

    class MotorComEscopo:
        def search_with_commitment(self, q, k=10, max_sample=50):
            return {"indices": [3, 1, 2], "total_excluded_count": 19997,
                    "global_threshold": 0.42, "bound_pairs": 20000,
                    "bound_violations": 0, "latency_ms": 0.2,
                    "n_corpus": 20000, "exact_scored": 20000,
                    "pruned_by_bound": 19997, "pruned_by_prefilter": 0,
                    "recall_guarantee": "exact_global",
                    "recall_guarantee_basis": "scored_all",
                    "sampled_records": [{"doc_id": 5, "upper_bound": 0.1,
                                         "excluded": True}]}

    q = np.ascontiguousarray(np.zeros(4, dtype=np.float32))
    rec = tc.make_worm_record(MotorComEscopo(), q, k=3, max_sample=20)
    for campo in ("n_corpus", "exact_scored", "pruned_by_bound",
                  "pruned_by_prefilter", "recall_guarantee",
                  "recall_guarantee_basis"):
        assert campo in rec, f"o certificado não assina {campo}"
    v = tc.verify_record(rec, chave)
    assert v["status"] == "VALID"
    assert v["claim_checkable"] is True


# ---------------------------------------------------------------------------
# 6. FSYNC E DURABILIDADE — o .chain é ponteiro, não dado
# ---------------------------------------------------------------------------

def test_chain_ausente_e_reconstruida_do_jsonl(worm):
    """REGRESSÃO. Sem o .chain, `_load_chain_state` devolvia b"" e o append
    seguinte gravava prev_hash="" no meio de um histórico existente —
    corrompendo a cadeia em vez de continuá-la. E o append NÃO falhava:
    produzia um registro inválido em silêncio.

    O .chain é derivável: é o último block_hash do JSONL. Reconstruir é a
    diferença entre "perdi o cache" e "perdi a cadeia"."""
    for i in range(5):
        worm.append({"audit_id": f"r{i}"})
    (pathlib.Path(worm.base_path) / ".chain").unlink()

    from winnex_tracer.persistence import WormStorage
    w2 = WormStorage(worm.base_path)
    w2.append({"audit_id": "pos_crash"})
    r = w2.verify_integrity()
    assert r["violations"] == 0, "a cadeia quebrou depois de perder o .chain"
    assert r["total_blocks"] == 6


def test_chain_atrasado_nao_quebra_a_cadeia(worm):
    """O caso do crash entre gravar o bloco (fsyncado) e gravar o ponteiro: o
    .chain fica apontando para o penúltimo. Reconstruir só quando o arquivo
    FALTA não cobria isso — medido, a cadeia quebrava (viol=1).

    A comparação certa é com a última linha do JSONL, que é sempre a verdade
    porque é o dado fsyncado."""
    for i in range(5):
        worm.append({"audit_id": f"s{i}"})
    arq = sorted(pathlib.Path(worm.base_path).rglob("records.jsonl"))[0]
    linhas = arq.read_text().strip().split("\n")
    (pathlib.Path(worm.base_path) / ".chain").write_text(
        json.loads(linhas[-2])["block_hash"])   # ponteiro atrasado

    from winnex_tracer.persistence import WormStorage
    w2 = WormStorage(worm.base_path)
    w2.append({"audit_id": "depois"})
    r = w2.verify_integrity()
    assert r["violations"] == 0, "ponteiro atrasado quebrou a cadeia"
    assert r["total_blocks"] == 6


def test_append_nao_e_O_N(worm):
    """REGRESSÃO que EU introduzi ao corrigir o `block_number`: a contagem de
    blocos entrou no `_load_chain_state`, que roda DENTRO DA TRAVA a cada
    append. Isso tornava o WORM quadrático — medido 0,224 ms/call em 2.000
    blocos, ~8,3 ms por append em 100.000.

    Uma correção de campo de receipt não pode custar o throughput do WORM."""
    import time
    for i in range(40):
        worm.append({"audit_id": f"c{i}"})
    t0 = time.perf_counter()
    for i in range(40):
        worm.append({"audit_id": f"d{i}"})
    cedo = (time.perf_counter() - t0) / 40

    for i in range(400):
        worm.append({"audit_id": f"e{i}"})
    t0 = time.perf_counter()
    for i in range(40):
        worm.append({"audit_id": f"f{i}"})
    tarde = (time.perf_counter() - t0) / 40

    # 10x mais blocos não pode custar 2x mais por append.
    assert tarde < cedo * 2.0, (
        f"append degradou com o tamanho: {cedo*1e3:.3f}ms -> {tarde*1e3:.3f}ms "
        f"(varredura O(N) de volta ao caminho quente)")


def test_durable_chain_preserva_a_opcao(worm):
    """O fsync do .chain virou opt-in. Quem exigir que o ponteiro sobreviva a
    um crash sem reconstrução passa `durable_chain=True`; o padrão economiza
    39% do append confiando no dado fsyncado + reconstrução."""
    from winnex_tracer.persistence import WormStorage
    w = WormStorage(worm.base_path, durable_chain=True)
    w.append({"audit_id": "dur"})
    assert w._durable_chain is True
    assert WormStorage(worm.base_path)._durable_chain is False
