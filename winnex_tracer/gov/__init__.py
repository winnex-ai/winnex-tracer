"""winnex_tracer.gov — Government domain (was tracer-gov).

Exposes TracerEngine, Config, GovMetadata and the base primitives re-exported
from winnex_tracer.core (Signer, WORM, commitment) for backward compatibility.

Business Source License 1.1 (BSL 1.1) | pay@winnex.ai
"""
from .core import TracerEngine, Config, GovMetadata, GovAuditRecord, GovAuditResult
from .core import (  # re-export base for convenience
    Signer, AuditLogTracker, RetentionPolicy,
    make_worm_record, verify_record, public_key_hex,
)

__all__ = [
    "TracerEngine", "Config", "GovMetadata", "GovAuditRecord", "GovAuditResult",
    "Signer", "AuditLogTracker", "RetentionPolicy",
    "make_worm_record", "verify_record", "public_key_hex",
]
