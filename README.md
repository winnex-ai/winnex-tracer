# winnex-tracer

**The unified Winnex tracer family — one package, namespaced domains.**

Shared core (WORM storage, Ed25519 signing, AuditCommitment) plus the
gov/med/jus/gap domains, in a single pip package. Each domain lives under
its own namespace (`winnex_tracer.gov`, `winnex_tracer.med`, ...) so there
is **no module collision** between the old separate tracer-gov/med/jus/gap
packages (which all used top-level `core`/`persistence`/`api`).

```
winnex_tracer/
├── core/    — WORM, Signer (Ed25519/ICP), AuditLogTracker, RetentionPolicy, commitment
├── gov/     — TracerEngine, 9 jurisdictions, LGPD/LAI/TCU/CGU compliance
├── med/     — MedicalEngine, clinical triage, FHIR
├── jus/     — LegalEngine, e-Discovery, evidence chain
└── gap/     — GapEngine, SEC loader, gap analysis
```

## Install

```bash
pip install winnex-tracer                # core only (WORM, Signer, commitment)
pip install winnex-tracer[gov]           # + government domain + FastAPI
pip install winnex-tracer[med]           # + healthcare domain
pip install winnex-tracer[jus]           # + legal domain
pip install winnex-tracer[gap]           # + financial domain
pip install winnex-tracer[all]           # everything
```

The search engine (`winnex-madhava >= 1.9.2`) is an optional extra
(`winnex-tracer[madhava]`) — each domain works with a built-in fallback.

## The AuditCommitment (production audit trail)

The C++ motor returns a compact commitment (`total_excluded_count` +
`global_threshold` + a deterministic boundary sample) instead of the full
O(N) certificate (~2 MB at scale). `winnex_tracer.core` signs it with
**Ed25519** for non-repudiation, then stores the ~500-byte record in the
WORM.

```python
from winnex_tracer.core import make_worm_record, verify_record, public_key_hex
from winnex_tracer.persistence import WormStorage

record = make_worm_record(engine, query, k=10, max_sample=50)  # ~500 B
WormStorage(base_path="/var/lib/tracer/worm").append(record)

v = verify_record(record, public_key_hex())   # VALID / INVALID
```

## Regionalized government metadata (global / multilanguage)

The gov domain is **global**: each jurisdiction uses its own field names.

| Jurisdiction | Language | Required fields |
|---|---|---|
| `br-gv` | pt-BR | `orgao_requisitante`, `cpf`, `funcao`, `base_de_dados`, `sensibilidade`, `finalidade` |
| `pt-gv` | pt-PT | `orgao_requisitante`, `numero_identificacao`, `funcao`, ... |
| `us-gv` / `eu-gv` / `global` | EN | `requesting_agency`, `operator_id`, `role`, `source_database`, `sensitivity`, `purpose` |

Generic English field names are **auto-mapped** to the regional names for
Portuguese jurisdictions (e.g. `requesting_agency` → `orgao_requisitante`),
so one client works across jurisdictions:

```python
from winnex_tracer.gov.core import TracerEngine, Config

eng = TracerEngine(Config(jurisdiction="br-gv"))
eng.validate_metadata({"requesting_agency": "TCU", "cpf": "...", ...})  # []
```

## License

Business Source License 1.1 (BSL 1.1) | pay@winnex.ai |
Winnex Brasil Soluções Empresariais LTDA (CNPJ 58.364.637/0001-47)
