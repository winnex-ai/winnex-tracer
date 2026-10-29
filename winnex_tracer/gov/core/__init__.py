"""tracer-gov: Public Audit with Mathematical Proof — Core Module.

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
from .tracer import (
    TracerEngine,
    Config,
    GovMetadata,
    GovAuditRecord,
    GovAuditResult,
    BackendGuaranteeError,
)
# The base infrastructure lives in winnex-tracer-core; re-export for
# backward compatibility (from core import Signer / AuditLogTracker / ...).
from winnex_tracer.core import (  # noqa: F401
    Signer,
    AuditLogTracker,
    RetentionPolicy,
    make_worm_record,
    verify_record,
    public_key_hex,
    commitment_to_payload,
    integrity_hash,
    sign_payload,
)
