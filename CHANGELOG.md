# Changelog

Formato: [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/).
Versionamento: [Semantic Versioning](https://semver.org/lang/pt-BR/).

A versão **canônica** vive em `winnex_tracer/__init__.py:__version__`.
`pyproject.toml` a lê dinamicamente (`dynamic = ["version"]`), e a tag `v*`
precisa corresponder exatamente — o workflow de publicação falha antes do
build se não corresponder.

## [Não publicado]

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
