"""
Tracer-JUS — Legal Metadata
============================
Structured metadata for legal search and e-Discovery.

Carries the legal context of a query or case: court, docket number,
judge, parties, confidentiality, and purpose. This is what makes a search
auditable in a legal proceeding (chain of custody).

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
import hashlib, uuid
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone


@dataclass
class CaseMetadata:
    """Metadata describing a legal case or matter.

    Field names are jurisdiction-agnostic but map to the legal vocabulary
    of each country via the jurisdiction policies.

    Args:
        docket_number: Court docket / process number (e.g. 2026.01.00001-1)
        court: Court or tribunal (e.g. "STJ", "Court of Appeals")
        chamber: Chamber / vara (e.g. "1a Vara Civel")
        judge: Presiding judge
        plaintiff: Claimant / author
        defendant: Respondent / réu
        lawyers: Counsel involved
        action_type: Type of action (e.g. "civil_liability", "breach")
        confidentiality: public / restricted / secret
        purpose: Purpose of the search (e.g. "e-discovery triage")
        evidence_list: Optional list of evidence identifiers in scope
        extra: Any additional jurisdiction-specific fields
    """

    docket_number: str = ""
    court: str = ""
    chamber: str = ""
    judge: str = ""
    plaintiff: str = ""
    defendant: str = ""
    lawyers: List[str] = field(default_factory=list)
    action_type: str = ""
    confidentiality: str = "public"
    purpose: str = ""
    evidence_list: List[str] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a dict (suitable for WORM persistence)."""
        return {
            "docket_number": self.docket_number,
            "court": self.court,
            "chamber": self.chamber,
            "judge": self.judge,
            "plaintiff": self.plaintiff,
            "defendant": self.defendant,
            "lawyers": list(self.lawyers),
            "action_type": self.action_type,
            "confidentiality": self.confidentiality,
            "purpose": self.purpose,
            "evidence_list": list(self.evidence_list),
            "extra": dict(self.extra),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CaseMetadata":
        return cls(
            docket_number=data.get("docket_number", ""),
            court=data.get("court", ""),
            chamber=data.get("chamber", ""),
            judge=data.get("judge", ""),
            plaintiff=data.get("plaintiff", ""),
            defendant=data.get("defendant", ""),
            lawyers=list(data.get("lawyers", [])),
            action_type=data.get("action_type", ""),
            confidentiality=data.get("confidentiality", "public"),
            purpose=data.get("purpose", ""),
            evidence_list=list(data.get("evidence_list", [])),
            extra=dict(data.get("extra", {})),
        )


@dataclass
class LegalQuery:
    """A legal search query with its justification context."""

    text: str
    topic: str = ""          # e.g. "indemnification", "force majeure"
    question: str = ""       # the legal question being answered
    review_round: str = ""   # e-discovery review round / batch
    metadata: Optional[CaseMetadata] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "text": self.text,
            "topic": self.topic,
            "question": self.question,
            "review_round": self.review_round,
            "metadata": self.metadata.to_dict() if self.metadata else {},
        }


def new_audit_id() -> str:
    """Generate a fresh audit identifier (timestamp + uuid, sha3-256)."""
    raw = f"{datetime.now(timezone.utc).isoformat()}:{uuid.uuid4()}"
    return hashlib.sha3_256(raw.encode()).hexdigest()[:32]
