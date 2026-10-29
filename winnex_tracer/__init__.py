"""winnex-tracer — the unified Winnex tracer family (single package).

One pip package containing the shared core plus the domain tracers:

  winnex_tracer.core    — WORM storage, Signer, AuditLogTracker, RetentionPolicy,
                          AuditCommitment (Ed25519 non-repudiation)
  winnex_tracer.gov     — government domain (TracerEngine, jurisdictions, LGPD/LAI/TCU/CGU)
  winnex_tracer.med     — healthcare domain (MedicalEngine, clinical triage, FHIR)
  winnex_tracer.jus     — legal domain (LegalEngine, e-Discovery, evidence chain)
  winnex_tracer.gap     — financial domain (GapEngine, SEC loader, gap analysis)

Each domain is namespaced under winnex_tracer.<dom> so there is NO collision
between the `core`/`persistence`/`api` modules (the flaw of the old separate
tracer-gov/med/jus/gap packages). Install extras: winnex-tracer[gov], [med],
[jus], [gap], or [all].

Business Source License 1.1 (BSL 1.1) | pay@winnex.ai
"""
# Fonte ÚNICA da versão: pyproject.toml lê daqui (dynamic = ["version"]).
# Declarar em dois lugares permite que o wheel publique com uma versão
# diferente da que o código reporta em runtime — e o PyPI recusa republicar
# um número já usado, então a divergência só aparece depois.
#
# 1.1.1 (patch, não minor): `Signer(algorithm="Ed25519")` passou a LEVANTAR
# SignatureGuaranteeError quando PyNaCl falta, em vez de cair para HMAC em
# silêncio; e deixou de usar chave default. Isso é correção de segurança, não
# funcionalidade nova — e a API pública não mudou. Pela semver, correção que
# restaura o comportamento correto é patch.
__version__ = "1.1.2"
