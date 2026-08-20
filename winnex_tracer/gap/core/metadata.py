"""
Tracer-GAP — Financial Metadata
================================
Structured metadata for financial gap analysis.

Financial documents carry structured metadata: SEC CIK, sector, document /
instrument type, fiscal period, and risk category. This enables filtering
before or after the vector search — essential for gap identification.

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
import hashlib, uuid
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone


@dataclass
class FinancialMetadata:
    """Metadata describing a financial document or analysis context.

    Args:
        sector: sector (Banking, Insurance, Capital Markets, ...)
        instrument_type: document/instrument type (10-K, 10-Q, policy, ...)
        cik: SEC Central Index Key (company identifier)
        company: company name
        period: fiscal period (e.g. "FY2021")
        filing_date: filing date (ISO)
        risk_category: risk factor category (market, credit, liquidity, ...)
        confidentiality: public / restricted / secret
        purpose: purpose of the analysis
        extra: jurisdiction-specific fields
    """

    sector: str = ""
    instrument_type: str = ""
    cik: str = ""
    company: str = ""
    period: str = ""
    filing_date: str = ""
    risk_category: str = ""
    confidentiality: str = "restricted"
    purpose: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sector": self.sector,
            "instrument_type": self.instrument_type,
            "cik": self.cik,
            "company": self.company,
            "period": self.period,
            "filing_date": self.filing_date,
            "risk_category": self.risk_category,
            "confidentiality": self.confidentiality,
            "purpose": self.purpose,
            "extra": dict(self.extra),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FinancialMetadata":
        return cls(
            sector=data.get("sector", ""),
            instrument_type=data.get("instrument_type", ""),
            cik=data.get("cik", ""),
            company=data.get("company", ""),
            period=data.get("period", ""),
            filing_date=data.get("filing_date", ""),
            risk_category=data.get("risk_category", ""),
            confidentiality=data.get("confidentiality", "restricted"),
            purpose=data.get("purpose", ""),
            extra=dict(data.get("extra", {})),
        )


@dataclass
class FinancialRecord:
    """A single financial document with its structured metadata.

    Args:
        text: the document content (risk factor, MD&A, disclosure)
        metadata: structured financial metadata
        external_id: original record ID (e.g. SEC accession number)
    """

    text: str
    metadata: FinancialMetadata = field(default_factory=FinancialMetadata)
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
