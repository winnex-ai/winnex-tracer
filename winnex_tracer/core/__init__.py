"""winnex-tracer-core — the shared base for the Winnex tracer family.

Generic infrastructure reused by tracer-gov, tracer-med, tracer-jus and
tracer-gap: WORM storage, Ed25519/ICP signing, tamper-evident audit log,
retention policies and the AuditCommitment (non-repudiation).

ESCOLHA DO CERTIFICADO
----------------------
O Tracer SEMPRE certifica: `make_worm_record` sempre assina, e isso não é
opcional. O que é opcional é a **operação do motor** — use `open_engine`
com `certificate_mode` para escolher explicitamente entre
`"off"`, `"commitment"` e `"audited"`, e `coverage_report` para checar se o
certificado carrega prova antes de tratá-lo como resultado.

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
from .signer import Signer, SignatureGuaranteeError
from .audit_log import AuditLogTracker
from .retention import RetentionPolicy
from .commitment import (
    make_worm_record,
    verify_record,
    public_key_hex,
    commitment_to_payload,
    integrity_hash,
    sign_payload,
)
from .certmode import (
    CertificateMode,
    CertificateModeError,
    CoverageError,
    certificate_mode,
    open_engine,
    InstrumentedEngine,
    coverage_report,
)

__all__ = [
    "Signer",
    "SignatureGuaranteeError",
    "AuditLogTracker",
    "RetentionPolicy",
    "make_worm_record",
    "verify_record",
    "public_key_hex",
    "commitment_to_payload",
    "integrity_hash",
    "sign_payload",
    # modos de certificado
    "CertificateMode",
    "CertificateModeError",
    "CoverageError",
    "certificate_mode",
    "open_engine",
    "InstrumentedEngine",
    "coverage_report",
]
