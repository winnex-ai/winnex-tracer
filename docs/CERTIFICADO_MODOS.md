# Certificado: como escolher, e por que a escolha é explícita

**Versão:** `winnex-tracer` 1.1.0+ (`winnex_tracer/core/certmode.py`)
**Medições:** 2026-10-28 · MedMCQA real, 145.673 documentos · MiniLM-L6 (384d)

---

## 1. A distinção que organiza tudo

> **O Tracer sempre certifica. O Madhava tem escolha.**

São duas camadas com responsabilidades diferentes, e confundi-las é a origem
do erro que este documento corrige.

| | `winnex-madhava` | `winnex-tracer` |
|---|---|---|
| o que é | busca vetorial | trilha de auditoria |
| certificado | **opcional** — três regimes | **obrigatório** |
| `search()` | existe, não certifica | não se aplica |
| `make_worm_record()` | não tem | **sempre assina** |

Perguntar "como desligo o certificado do Tracer" é a pergunta errada. O
Tracer existe para certificar. A pergunta certa é **"qual operação do motor
eu quero"** — e essa escolha agora é nomeada.

---

## 2. Os três modos

```python
from winnex_tracer.core import open_engine

eng = open_engine(corpus, certificate_mode="commitment", k=3)
```

| modo | método do motor | o que devolve | custo* |
|---|---|---|---|
| `"off"` | `search()` | índices apenas | base |
| `"commitment"` | `search_with_commitment()` | contagem + limiar + amostra | **+0,09 ms** |
| `"audited"` | `search_audited()` | registro por documento excluído | +~1 ms |

\* medido em 145.673 documentos; a base é 13,02 ms por consulta.

### `"off"` — busca pura

Para quando não há auditoria envolvida: protótipo, avaliação de recall,
benchmark de latência.

```python
eng = open_engine(corpus, certificate_mode="off", k=10)
r = eng.search(q)                       # ok

eng.make_worm_record(q)                 # CertificateModeError
```

O erro é deliberado: um certificado que não existe não pode ser assinado. Sem
isso, `make_worm_record` devolveria um registro vazio que *parece* válido.

### `"commitment"` — o recomendado para produção auditável

```python
eng = open_engine(corpus, certificate_mode="commitment", k=10)
eng.search_with_commitment(q)
# {'total_excluded_count': 145670, 'global_threshold': 0.7451,
#  'sampled_records': [...], 'bound_violations': 0, 'indices': [...]}
```

O Tracer assina isso diretamente:

```python
from winnex_tracer.core import verify_record, public_key_hex
rec = eng.make_worm_record(q, k=10, min_coverage=0.5)
verify_record(dict(rec), public_key_hex())["status"]   # "VALID"
```

**Custo: +0,09 ms.** É o único acréscimo sobre a busca crua. Não há razão para
usar `"off"` em produção auditável.

### `"audited"` — perícia

Devolve, por documento excluído: `doc_id`, `true_cosine`, `projected_cosine`,
`residual_norm`, `upper_bound`, `threshold`. Use quando alguém precisa
**conferir a prova**, não apenas saber que ela existe.

```python
a = eng.search_audited(q, k=3, max_audit_records=10)
a["audit"][0]
# {'doc_id': 0, 'true_cosine': 0.2132, 'upper_bound': 0.2133, 'threshold': 0.7451}
```

---

## 3. O erro que matou a cobertura do certificado

Um certificado com `total_provably_excluded == 0` é **criptograficamente
válido e semanticamente inútil**. Ele atesta que o bound não provou nada.

Medido em MedMCQA real, k=3:

| configuração do motor | cobertura | consultas com amostra |
|---|---:|---:|
| `basis="random"`, `stage1_dim=64`, `stage2_dim=128` (**default**) | **0,000%** | 3/20 |
| `basis="random"`, `stage1_dim=d`, `stage2_dim=d` | **99,998%** | 20/20 |
| `basis="pca_corpus"`, `stage1_dim=64`, `stage2_dim=128` | 93,299% | 20/20 |

A cobertura é propriedade do **corpus + configuração**, não do motor. Com
rank baixo, o resíduo `e(v) = sqrt(1 − ‖Pv‖²)` fica grande, o bound
`UB = ‖Pv‖‖Pq‖ + e(v)e(q)` fica perto de 1,0 e não consegue provar exclusão
nenhuma.

### A configuração correta

```python
# certificação com build rápido — recomendado
eng = open_engine(X, certificate_mode="commitment", k=3,
                  basis="random", stage1_dim=X.shape[1], stage2_dim=X.shape[1])
```

Build a 1M vetores, d=384:

| configuração | build | vs HNSW | cobertura |
|---|---:|---:|---:|
| `random` 64/128 (default) | 6,3 s | 16,6× mais rápido | 0% |
| **`random` pleno** | **21,6 s** | **4,8× mais rápido** | **100%** |
| `pca_corpus` 64/128 | 36,2 s | 2,9× mais rápido | 0% |

Rank pleno preserva a vantagem de build **e** certifica tudo. `pca_corpus` com
rank baixo é o pior dos dois mundos: paga o solver e não certifica.

---

## 4. Verificar antes de assinar

```python
from winnex_tracer.core import coverage_report

rep = coverage_report(eng, queries, k=3, min_coverage=0.5)
```

```python
{
  "n_docs": 145673,
  "cobertura_mediana": 0.99998,
  "excluidos_mediana": 145670,
  "consultas_com_amostra": 20,
  "consultas_vazias": 0,
  "fracao_vazias": 0.0,
  "ok": True,
  "leitura": "certificado com prova real: metade ou mais do corpus é
              provadamente descartado por consulta."
}
```

`ok` é `False` quando a cobertura mediana é zero — mesmo que
`min_coverage=0`. Um certificado vazio nunca é "ok".

### Recusar o selo vazio

```python
try:
    rec = eng.make_worm_record(q, k=3, min_coverage=0.5)
except CoverageError as e:
    # cobertura 0.000% < mínimo 50.0% (0/145673 provados).
    # O selo atestaria que nada foi provado.
    # Verifique a configuração do motor: use basis="pca_corpus" ou
    # stage1_dim=stage2_dim=d.
    ...
```

`min_coverage` é o único jeito de o Tracer **recusar** assinar. Sem ele, o
Tracer cumpre a invariante e assina — inclusive um selo vazio, que é válido.

---

## 5. Referência rápida

```python
CertificateMode.OFF         # "off"
CertificateMode.COMMITMENT  # "commitment"
CertificateMode.AUDITED     # "audited"
CertificateMode.ALL         # os três
CertificateMode.CERTIFYING # os que produzem certificado
```

Aliases aceitos: `"on"`, `"cert"`, `"certificate"`, `"commit"`, `"true"`
→ `commitment`; `"none"`, `"false"`, `"no"` → `off`; `"audit"`, `"full"`
→ `audited`. Maiúsculas e espaços são normalizados.

| exceção | quando |
|---|---|
| `CertificateModeError` | modo inválido, ou operação não permitida pelo modo |
| `CoverageError` | `min_coverage` exigido e a cobertura ficou abaixo |

---

## 6. O que continua valendo

- O certificado é **Ed25519 + hash encadeado**. Adulterar `total_provably_excluded`,
  `global_threshold`, `bound_pairs` ou qualquer campo da amostra invalida a
  assinatura. Testado em `tests/test_certmode.py`.
- `bound_violations = 0` vale para o **escopo declarado** (`pool_only` vs
  `exact_global`). Não é garantia global por omissão.
- A camada de assinatura está correta. O que faltava era medir **o que** ela
  assinava — e é isso que `coverage_report` e `min_coverage` resolvem.
