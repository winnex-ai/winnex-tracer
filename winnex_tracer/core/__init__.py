"""winnex-tracer-core — the shared base for the Winnex tracer family.

Generic infrastructure reused by tracer-gov, tracer-med, tracer-jus and
tracer-gap: WORM storage, Ed25519/ICP signing, tamper-evident audit log,
retention policies and the AuditCommitment (non-repudiation).

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
from .signer import Signer
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

__all__ = [
    "Signer",
    "AuditLogTracker",
    "RetentionPolicy",
    "make_worm_record",
    "verify_record",
    "public_key_hex",
    "commitment_to_payload",
    "integrity_hash",
    "sign_payload",
]
