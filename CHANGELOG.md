# Changelog

Formato: [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/).
Versionamento: [Semantic Versioning](https://semver.org/lang/pt-BR/).

A versão **canônica** vive em `winnex_tracer/__init__.py:__version__`.
`pyproject.toml` a lê dinamicamente (`dynamic = ["version"]`), e a tag `v*`
precisa corresponder exatamente — o workflow de publicação falha antes do
build se não corresponder.

## [Não publicado]

### Corrigido — o WORM apagava o fim sem acusar

`verify_integrity()` validava a cadeia **contra ela mesma**: cada bloco confere
`prev_hash` com o anterior. Apagar blocos do fim não viola nenhuma dessas
relações — os sobreviventes continuam mutuamente consistentes.

Medido: 20 blocos → apagar os últimos 5 → `violations=0`,
`chain_integrity_verified=True`, e o `.chain` apontando para um hash que não
existia mais em disco. Para um WORM usado em conformidade LGPD/LAI, remoção
silenciosa é falha de requisito.

Agora o `.chain` (escrito sob a mesma trava do bloco) é comparado com o
**último bloco realmente em disco**. Custo zero. Campos novos:
`truncation_detected`, `truncation_detail`.

**Escopo declarado:** isso pega truncamento de cauda, **não** um atacante que
reescreva os dois arquivos. Para esse caso, `compute_anchor()` +
`verify_against_anchor()`: a âncora copiada para **fora** do filesystem compara
`block_count` e `last_hash` e não pode ser derrotada de dentro. Testado: o
atacante trunca o JSONL **e** reescreve o `.chain` — a verificação interna
passa, a contra-âncora falha.

### Corrigido — `block_number` do receipt era o número de arquivos

Era `len(rglob("records.jsonl"))`. Medido: 20 `append` no mesmo dia devolviam
`block_number=1` em **todos os 20`. O receipt é a testemunha que o cliente
guarda; devolver 1 quando existem 20 é pior que não devolver nada, porque
**parece** um contador. Agora conta blocos, mantido do estado em disco na carga
e incrementado sob a trava.

### Corrigido — o certificado provava integridade, não soundness

O achado central. Assinei com a chave **legítima** `total_provably_excluded =
99999` num corpus de 20.000 — exclusão matematicamente impossível — e o
`verify_record` devolvia **VALID**. Um motor comprometido afirmando excluir
**100% do corpus** também passava.

> A assinatura prova que o registro **não mudou**. Não prova que a afirmação
> era verdadeira **quando foi assinada**.

Correção em duas pontas:

- `commitment_to_payload` propaga os campos de escopo quando o motor os emite:
  `n_corpus`, `exact_scored`, `pruned_by_bound`, `pruned_by_prefilter`,
  `recall_guarantee`, `recall_guarantee_basis`. **Aditivo e opcional** —
  motores antigos continuam assinando o payload anterior.
- `verify_record` faz **claim sanity**: `total <= n_corpus - k` (provar que
  todo documento está fora de um top-K de k≥1 é contradição),
  `bound_pairs <= n_corpus`, e `pruned_by_bound == total` (descrevem o mesmo
  fato por dois caminhos). O veredito expõe `claim_checkable` e diz na razão
  quando a afirmação **não é confrontável**, em vez de fingir que é.

**O limite em N−k é o teto teórico**, e os dois corpora reais dos testes
existentes ficam exatamente nele: `15540 = 20000−10` e `145670 = 145673−3`.
Isso confirma o limite em vez de contradizê-lo.

### Custos

`verify_record` 0,033 ms (+0,001), `append` 1,850 ms / 541 blocos/s
(inalterado), `verify_integrity` 0,60 ms.

**Tests:** 166 passed (152 anteriores + 14 novos em
`test_worm_certificado_2026_10_30.py`).

## [1.1.2] — 2026-10-29

Correção de integridade da cadeia WORM. Sem mudança na API pública.

### Corrigido

- **`WormStorage.append` encadeava contra estado obsoleto.** O `prev_hash`
  de cada bloco vinha de `self._last_hash`, lido uma única vez no
  `__init__`. Com duas instâncias vivas sobre o mesmo `base_path` — ou uma
  instância longeva ao lado de uma efêmera — o escritor seguinte gravava um
  `prev_hash` velho e **a cadeia se rompia de forma permanente**, sem que
  nada tivesse sido adulterado. `verify_integrity()` então acusava violação
  num histórico íntegro.

  Esse é o padrão de uso normal do `tracer-med`, não um caso exótico:
  `EvidenceChain` mantém um `WormStorage` pela vida do processo, enquanto
  `ClinicalTriageEngine.run_triage` abre `WormStorage()` novo a cada
  consulta. Medido antes da correção: 4 processos × 5 appends → 20 blocos,
  **9 violações de cadeia**; e uma triagem clínica real terminava com
  `evidence_chain_verified=False` sobre eventos legítimos.

  A correção relê o estado da cadeia **sob trava exclusiva** (`fcntl.flock`
  em `.append.lock`), e mantém a trava até o `.chain` ser substituído, de
  modo que "ler último hash → gravar bloco → atualizar `.chain`" é atômico
  entre processos. O `.chain` passa a ser escrito via arquivo temporário +
  `os.replace`. Sem `fcntl` (Windows), `append` continua funcionando e a
  ausência de exclusão entre processos é explícita, não um crash silencioso.

  Regressão coberta por `winnex_tracer/tests/test_worm_chain.py` (6 casos),
  incluindo concorrência multiprocesso real e um controle que verifica que a
  adulteração de conteúdo **continua sendo detectada** — uma correção que
  fizesse a cadeia "verificar" depois de alterada seria pior que o defeito.

## [1.1.1] — 2026-10-29

Correção de segurança e honestidade. Sem mudança na API pública.

### Corrigido

- **`Signer(algorithm="Ed25519")` não degrada mais para HMAC.** Sem PyNaCl,
  a função produzia HMAC-SHA3 e devolvia sucesso. Ed25519 prova *quem*
  assinou para qualquer portador da chave pública (não-repúdio); HMAC prova
  apenas que alguém com a chave secreta gerou aquilo — e esse alguém é
  justamente quem teria poder de forjar. A troca substituía "o operador não
  pode repudiar" por "confie no operador", em silêncio. Agora levanta
  `SignatureGuaranteeError`. HMAC continua disponível apenas por pedido
  explícito (`algorithm="HMAC"`), com chave obrigatória e o registro
  declarando que não é não-repúdio.

- **Nenhuma chave default.** Sem `WINNEX_TRACER_ED25519_KEY` (ou `_FILE`), o
  signer não assina. Também não gera chave descartável. Uma constante no
  código-fonte é uma chave pública, e um "segredo" público não forja nada.

- **`TracerEngine` não cai para numpy em silêncio.**
  `_resolve_backend()` retornava `"builtin"` quando não havia backend com
  garantias. Esse backend não tem limite de Cauchy-Schwarz nem
  `search_with_commitment` — as duas garantias que são o produto — e o
  registro que produzisse sairia assinado com `total_provably_excluded=0`,
  aparentando válido. Agora levanta `BackendGuaranteeError`. A degradação
  voluntária é declarada (`Config(require_guarantees=False)`) e fica marcada
  no resultado via `engine_guarantees`, incluindo `certificate_EMPTY`.

- **Correção C, agora completa.** O payload assinado passou de
  `round(float(x), 6)` para `float.hex()`: o arredondamento podia inverter
  `upper_bound < global_threshold` na fronteira amostrada, e o registro
  assinado contradiria a própria prova. Agora os consumidores usam
  `payload_float()`, que lê os dois formatos — registros gravados antes da
  mudança continuam legíveis e verificáveis, sem migração.

### Adicionado

- **`winnex_tracer.core.certmode`** — escolha explícita da operação do motor:

  ```python
  open_engine(corpus, certificate_mode="off" | "commitment" | "audited")
  ```

  O Tracer sempre certifica (`make_worm_record` é incondicional). O que é
  opcional é a operação do motor, e agora ela é nomeada. Pedir certificado
  num modo que não o produz levanta `CertificateModeError` em vez de devolver
  um registro vazio de aparência válida.

- **`coverage_report()` e `min_coverage`** — medem quanto o certificado cobre
  antes de assinar, e recusam o selo vazio com `CoverageError`.

- **`tools/audit_dependencies.py`** — classifica cada teste por medição
  (roda a suíte com e sem o motor) em INDEPENDENTE / DEPENDENTE / QUEBRADO /
  SEMPRE_FALHA / FRÁGIL.

- **`tools/apply_requires_engine.py`** — aplica `@requires_engine` apenas aos
  DEPENDENTE medidos, por nome, com verificação de pós-condição e falha
  explícita. Recusa marcar teste independente ou com defeito.

### Medições associadas (dados reais)

MedMCQA, 145.673 documentos, MiniLM-L6 (384d), k=3:

| configuração | cobertura do certificado |
|---|---:|
| `basis="random"`, rank baixo (default) | 0,000% |
| `basis="random"`, rank pleno (`stage1_dim=stage2_dim=d`) | 99,998% |
| `basis="pca_corpus"` | 93,299% |

A cobertura é propriedade do corpus + configuração, não do motor: com rank
baixo o resíduo `e(v) = sqrt(1 − ‖Pv‖²)` fica grande, o bound fica perto de
1,0 e não consegue provar exclusão.

### Documentação

- `docs/CERTIFICADO_MODOS.md` — os três modos, custos medidos, a tabela de
  cobertura e a configuração correta do motor.
- `docs/HONESTIDADE_E_AUDITABILIDADE.md` — o princípio: se o sistema vai
  degradar, que degrade ruidosamente, com métrica auditável.

### Suíte de testes

- 146 testes passando com o motor instalado.
- 101 passando, 32 skipped sem o motor — o mesmo número de antes de qualquer
  marcação, então nenhuma cobertura foi perdida.
- Invariante executável: `INDEPENDENTE == 101`.

## [1.1.0] — anterior

- Assinatura de commitment compartilhada; auditoria WORM com busca paralela;
  cache de embeddings persistente.
