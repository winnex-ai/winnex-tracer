"""winnex_tracer.gap — Financial domain (was tracer-gap).

Exposes GapEngine, GapAnalysisEngine, GapResult, MetadataFilter,
EvidenceChain, FinancialMetadata, FinancialRecord, SecLoader.

Business Source License 1.1 (BSL 1.1) | pay@winnex.ai
"""
from .core import (
    GapEngine, GapAnalysisEngine, GapResult, MetadataFilter,
    EvidenceChain, FinancialMetadata, FinancialRecord, SecLoader,
    new_audit_id,
)

__all__ = [
    "GapEngine", "GapAnalysisEngine", "GapResult", "MetadataFilter",
    "EvidenceChain", "FinancialMetadata", "FinancialRecord", "SecLoader",
    "new_audit_id",
]
