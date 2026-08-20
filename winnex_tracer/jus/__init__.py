"""winnex_tracer.jus — Legal domain (was tracer-jus).

Exposes LegalEngine, DiscoveryEngine, DiscoveryResult, ExclusionProof,
EvidenceChain, CaseMetadata, LegalQuery.

Business Source License 1.1 (BSL 1.1) | pay@winnex.ai
"""
from .core import (
    LegalEngine, DiscoveryEngine, DiscoveryResult, ExclusionProof,
    EvidenceChain, CaseMetadata, LegalQuery, new_audit_id,
)

__all__ = [
    "LegalEngine", "DiscoveryEngine", "DiscoveryResult", "ExclusionProof",
    "EvidenceChain", "CaseMetadata", "LegalQuery", "new_audit_id",
]
