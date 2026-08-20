"""
Tracer-MED — Clinical Metadata
===============================
Structured metadata for clinical search and triage.

Goes beyond pure semantic search: clinical records carry structured
metadata (encounter date, anonymized patient ID, document type, author /
institution, CID-10 code) that enables filtering before or after the vector
search. Patient IDs are always pseudonymized — never identifiable.

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
import hashlib, uuid
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone


@dataclass
class ClinicalMetadata:
    """Metadata describing a clinical record or a triage context.

    Args:
        encounter_date: Date of encounter / article (ISO, e.g. 2024-03-15)
        patient_id: ANONYMIZED patient ID (e.g. PT-8f3a) — never identifiable
        document_type: prontuario / laudo / exame / diretriz / ...
        author: Author or institution
        institution: Institution (e.g. "Hospital das Clinicas")
        cid10: ICD-10 code (e.g. "I10" hypertension, "E11" diabetes)
        department: Clinical department (e.g. "Cardiology")
        confidentiality: public / restricted / secret
        purpose: Purpose of the search
        extra: Any jurisdiction-specific fields
    """

    encounter_date: str = ""
    patient_id: str = ""            # ANONYMIZED
    document_type: str = ""
    author: str = ""
    institution: str = ""
    cid10: str = ""
    department: str = ""
    confidentiality: str = "restricted"   # health data is sensitive by default
    purpose: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "encounter_date": self.encounter_date,
            "patient_id": self.patient_id,
            "document_type": self.document_type,
            "author": self.author,
            "institution": self.institution,
            "cid10": self.cid10,
            "department": self.department,
            "confidentiality": self.confidentiality,
            "purpose": self.purpose,
            "extra": dict(self.extra),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ClinicalMetadata":
        return cls(
            encounter_date=data.get("encounter_date", ""),
            patient_id=data.get("patient_id", ""),
            document_type=data.get("document_type", ""),
            author=data.get("author", ""),
            institution=data.get("institution", ""),
            cid10=data.get("cid10", ""),
            department=data.get("department", ""),
            confidentiality=data.get("confidentiality", "restricted"),
            purpose=data.get("purpose", ""),
            extra=dict(data.get("extra", {})),
        )

    @staticmethod
    def pseudonymize(raw_identifier: str) -> str:
        """Derive a stable, non-identifiable patient ID.

        Uses SHA3-256 of the raw identifier — irreversible, deterministic.
        Never store or expose the raw identifier.
        """
        h = hashlib.sha3_256(f"tracer-med:{raw_identifier}".encode())
        return f"PT-{h.hexdigest()[:8]}"


@dataclass
class ClinicalRecord:
    """A single clinical document with its structured metadata.

    Args:
        text: the document content (transcription, report, guideline)
        metadata: structured clinical metadata (CID-10, patient, type, ...)
        external_id: original record ID (for FHIR / legacy linkage)
    """

    text: str
    metadata: ClinicalMetadata = field(default_factory=ClinicalMetadata)
    external_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "text": self.text,
            "metadata": self.metadata.to_dict(),
            "external_id": self.external_id,
        }


def new_audit_id() -> str:
    """Generate a fresh audit identifier."""
    raw = f"{datetime.now(timezone.utc).isoformat()}:{uuid.uuid4()}"
    return hashlib.sha3_256(raw.encode()).hexdigest()[:32]
