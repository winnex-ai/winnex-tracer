# Honestidade e auditabilidade

**O princípio:** se o sistema vai degradar, que degrade **ruidosamente**, com
métrica auditável — não escondido atrás de um `return "numpy"`.

Este documento fixa a regra e mostra onde ela está implementada.

---

## 1. O que é fallback silencioso — e por que não é bug

Um fallback é silencioso quando o sistema troca a garantia que você pediu por
uma mais fraca, executa com sucesso, e não avisa.

Não é "ter um plano B". Plano B explícito é engenharia boa. O que o torna
silencioso são três coisas juntas:

1. **A garantia muda de qualidade** — não é a mesma coisa mais devagar, é outra coisa
2. **O caminho de execução é indistinguível** — sem exceção, sem warning, mesmo tipo de retorno
3. **A saída tem a mesma forma** — parece que funcionou do jeito que você pediu

A distinção importa porque **não é um bug**. Um bug quebra algo e aparece numa
fila de defeitos. Isto é *erosão silenciosa da garantia fundamental*: o
resultado continua parecendo válido, a suíte fica verde, e a falha só emerge
sob contestação — quando alguém questiona um laudo e descobre que a trilha não
sustenta o que prometia. Aí o defeito já está no passado.

---

## 2. O caso concreto: Ed25519 cair para HMAC

### O código antes

```python
def _sign_ed25519(self, data):
    try:
        import nacl.signing
        ...
    except ImportError:
        key = os.environ.get("WINNEX_TRACER_ED25519_KEY", "tracer-gov-dev-key")
        sig = hmac.new(key.encode(), data, "sha3_256").hexdigest()
        return {"signature": sig, "signature_algorithm": "Ed25519-HMAC", ...}
```

Sem PyNaCl, produzia HMAC e devolvia sucesso. Se a variável de ambiente não
estivesse setada, a "assinatura" usava a constante `"tracer-gov-dev-key"`,
escrita no código-fonte — que é pública. Qualquer pessoa que leia o
repositório poderia forjar esses registros.

### Por que a troca é grave

| | Ed25519 | HMAC-SHA3 |
|---|---|---|
| prova que | **quem** assinou | que alguém com a chave secreta gerou |
| verificação | qualquer um, com a chave **pública** | só quem tem a chave **secreta** |
| auditor externo | verifica sozinho | precisa confiar no operador |
| forjar sem a chave | inviável | inviável |

O ponto é o terceiro. O `commitment.py` existe para o cenário: *"even a
compromised engine cannot forge past records"*. Não-repúdio significa que o
operador **não consegue** repudiar. Com HMAC, o operador tem a chave secreta —
é exatamente quem teria poder de forjar. O argumento de auditoria se desmonta.

O `commitment.py` já tinha a postura certa:

```python
raise RuntimeError(
    "Ed25519 signing requires PyNaCl: pip install pynacl. "
    "The commitment signer refuses to fall back to an insecure hash."
)
```

Duas funções do mesmo pacote, assinando registros do mesmo sistema, com
posturas opostas.

### O código depois

```python
try:
    import nacl.signing
except ImportError as exc:
    raise SignatureGuaranteeError(
        "Ed25519 signing requires PyNaCl: pip install pynacl. "
        "The signer refuses to fall back to HMAC: that would replace "
        "non-repudiation (verifiable by anyone with the public key) "
        "with a symmetric secret and report success. "
        'If a symmetric MAC is genuinely what you want, request it '
        'explicitly: Signer(algorithm="HMAC").'
    ) from exc
```

HMAC continua existindo, mas só por pedido explícito — e o registro diz o que é:

```python
Signer(algorithm="HMAC")   # exige WINNEX_TRACER_HMAC_KEY, sem default
# {"signature_algorithm": "HMAC-SHA3-256",
#  "note": "symmetric MAC, requested explicitly: proves possession of the
#           shared key, NOT non-repudiation..."}
```

---

## 3. Nenhuma chave default

```python
key_hex = os.environ.get("WINNEX_TRACER_ED25519_KEY", "").strip()
if not key_hex:
    raise SignatureGuaranteeError(
        "WINNEX_TRACER_ED25519_KEY (or _FILE) not set. "
        "The signer never generates a throwaway key or falls back to "
        "a default: a record signed with an unknown or hardcoded key "
        "cannot be repudiated NOR trusted."
    )
```

A chave vem de `WINNEX_TRACER_ED25519_KEY` ou `WINNEX_TRACER_ED25519_KEY_FILE`
(ambiente / secret manager), ou o sistema não assina. Tamanho e hexadecimal são
validados, com a instrução de como gerar outra na mensagem de erro.

---

## 4. O backend não degrada em silêncio

`TracerEngine._resolve_backend()` tinha quatro níveis e caía para numpy sem
avisar:

```python
# antes
if _HAS_CPP_ENGINE:   return "cpp"
if _HAS_MADHAVA_PIP:  return "madhava_pip"
if _HAS_PY_ENGINE:    return "python"
return "builtin"        # numpy, sem garantia alguma
```

As garantias em questão são o produto:

1. **Limite de Cauchy-Schwarz verificável** — produz o commitment e o certificado de exclusão
2. **`search_with_commitment`** — é o que o WORM assina

Um backend numpy não tem nenhuma das duas. Ele responde consultas; o registro
que produzir sairia assinado com `total_provably_excluded = 0` e pareceria
saudável.

```python
# depois
if _HAS_CPP_ENGINE:   return "cpp"
if _HAS_MADHAVA_PIP:  return "madhava_pip"
if _HAS_PY_ENGINE:    return "python"

if self.config.require_guarantees:
    raise BackendGuaranteeError(
        "Nenhum backend com garantias disponivel... o registro sairia "
        "assinado e VAZIO (total_provably_excluded=0), aparentando valido."
    )
return "builtin"
```

### A degradação voluntária é declarada e marcada

`Config(require_guarantees=False)` é a única forma de aceitar um backend sem
garantias. É uma afirmação explícita no código de quem chamou. E o resultado
carrega a marca:

```python
result.engine_guarantees = [
    "cauchy_schwarz_bound",
    "search_with_commitment",
    "ed25519_signed",
    "certificate_EMPTY(0_exclusions_proved)",   # ou certificate_non_empty
]
```

A degradação fica **no próprio registro**, visível para quem audita, em vez de
escondida atrás do nome do backend.

---

## 5. A mesma regra na escolha do certificado

`winnex_tracer/core/certmode.py` aplica o princípio na configuração do motor:

```python
eng = open_engine(X, certificate_mode="commitment")
rep = coverage_report(eng, queries, k=3)

rec = eng.make_worm_record(q, k=3, min_coverage=0.5)
# CoverageError: cobertura 0.000% < mínimo 50.0% (0/145673 provados).
# O selo atestaria que nada foi provado.
# Use basis="pca_corpus" ou stage1_dim=stage2_dim=d.
```

`basis="random"` com rank baixo é o mesmo padrão no nível da configuração: o
motor aceita, executa, e não avisa que não vai conseguir provar nada.
`coverage_report` e `min_coverage` convertem esse fallback silencioso numa
escolha visível e medida.

Medido em MedMCQA (145.673 docs), k=3:

| configuração | cobertura | consultas com amostra |
|---|---:|---:|
| `basis="random"` rank baixo (default) | **0,000%** | 3/20 |
| `basis="random"` rank pleno | **99,998%** | 20/20 |
| `basis="pca_corpus"` | 93,299% | 20/20 |

---

## 6. As três regras, resumidas

| domínio | antes | depois |
|---|---|---|
| assinatura | HMAC silencioso + chave default no código | `raise`; HMAC só com `algorithm="HMAC"`; chave obrigatória do ambiente |
| backend | numpy silencioso | `raise`; `require_guarantees=False` declara; `engine_guarantees` marca |
| certificado | cobertura 0% assinada como sucesso | `coverage_report` mede; `min_coverage` recusa; `certificate_mode` nomeia |

**A regra única:** a garantia pedida é honrada, ou o sistema recusa. Nunca
substituída por uma mais fraca que devolve sucesso.

---

## 7. Testes

`tests/test_degradacao.py` (12 testes) fixa as invariantes:

| teste | o que prova |
|---|---|
| `test_ed25519_sem_pynacl_levanta` | sem PyNaCl, levanta — não assina com HMAC |
| `test_ed25519_nunca_devolve_hmac` | o caminho de sucesso nunca troca o algoritmo |
| `test_ed25519_sem_chave_levanta` | sem chave, não assina e não inventa uma |
| `test_hmac_explicito_funciona` | HMAC devolve o algoritmo real e o aviso de não-repúdio |
| `test_hmac_sem_chave_levanta` | a constante do código-fonte não é segredo |
| `test_backend_sem_garantias_levanta` | sem garantias, `auto` levanta |
| `test_backend_degradacao_declarada_e_permitida` | `require_guarantees=False` é respeitado |
| `test_backend_com_garantias_e_aceito` | havendo Madhava, opera normalmente |

`tests/test_certmode.py` (14 testes) fixa o equivalente no certificado,
incluindo os controles negativo (config degradada → certificado vazio) e
positivo (rank pleno → prova >50%).
