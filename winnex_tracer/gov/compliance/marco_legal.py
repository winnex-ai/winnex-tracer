"""
Tracer-GOV — Marco Legal Gov Digital alignment check
======================================================
Brazilian Digital Government Legal Framework (Law 14.129/2021)
technical alignment checklist.

WARNING: This is a feature-gap checklist, not a compliance certification.

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
from typing import Dict, Any
from datetime import datetime, timezone


class MarcoLegalReport:
    """Marco Legal Gov Digital (Law 14.129/2021) technical alignment."""

    @staticmethod
    def generate(audit_record: dict) -> Dict[str, Any]:
        metadata = audit_record.get("metadata", {})
        return {
            "report_type": "MARCO_LEGAL_ALIGNMENT_CHECK",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "disclaimer": (
                "Technical feature checklist — not a regulatory certification. "
                "Law 14.129/2021 compliance requires institutional review."
            ),
            "framework": {
                "law": "14.129/2021",
                "principles": [
                    "digital_transformation",
                    "interoperability",
                    "data_transparency",
                    "open_government",
                ],
            },
            "request_data": {
                "agency": metadata.get("requesting_agency", ""),
                "purpose": metadata.get("purpose", ""),
                "source_database": metadata.get("source_database", ""),
            },
            "features_present": {
                "digital_signature": bool(
                    audit_record.get("signature", "")),
                "audit_trail_available": bool(
                    audit_record.get("audit", [])),
                "worm_storage": bool(
                    audit_record.get("worm_path", "")),
                "blockchain_backup": bool(
                    audit_record.get("blockchain_tx", "")),
            },
            "assessment": "technical alignment check — not certified",
        }

    @staticmethod
    def to_text(report: Dict[str, Any]) -> str:
        features = report["features_present"]
        lines = [
            "=" * 67,
            "  MARCO LEGAL GOV DIGITAL — Law 14.129/2021",
            "  Technical Alignment Check",
            "=" * 67,
            "",
            f"  Generated: {report['generated_at']}",
            f"  Agency: {report['request_data']['agency']}",
            "",
            "  Features present:",
            f"    Digital signature:     "
            f"{'YES' if features['digital_signature'] else 'NO'}",
            f"    Audit trail:           "
            f"{'YES' if features['audit_trail_available'] else 'NO'}",
            f"    WORM storage:          "
            f"{'YES' if features['worm_storage'] else 'NO'}",
            f"    Blockchain backup:     "
            f"{'YES' if features['blockchain_backup'] else 'NO'}",
            "",
            f"  Assessment: {report['assessment']}",
            "",
            "  DISCLAIMER:",
            f"  {report['disclaimer']}",
            "",
            "=" * 67,
            "  Winnex AI | licensing@winnex.ai | BSL 1.1",
        ]
        return "\n".join(lines)
