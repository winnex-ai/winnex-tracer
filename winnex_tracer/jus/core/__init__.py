"""Tracer-JUS — Legal e-Discovery and Research with Mathematical Proof.

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
from .legal_engine import LegalEngine
from .discovery import DiscoveryEngine, DiscoveryResult, ExclusionProof
from .evidence import EvidenceChain
from .metadata import CaseMetadata, LegalQuery, new_audit_id

__all__ = [
    "LegalEngine",
    "DiscoveryEngine",
    "DiscoveryResult",
    "ExclusionProof",
    "EvidenceChain",
    "CaseMetadata",
    "LegalQuery",
    "new_audit_id",
]
