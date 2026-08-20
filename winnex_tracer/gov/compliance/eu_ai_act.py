"""
Tracer-GOV — EU AI Act preliminary mapping (Art. 13-15)
=========================================================
Exploratory assessment of how Tracer-GOV maps to EU AI Act
requirements. This is NOT a compliance certification.

WARNING: EU AI Act conformity requires official certification
by a notified body. This document is a technical self-assessment
template only.

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
from typing import Dict, Any
from datetime import datetime, timezone


class EuAiActReport:
    """EU AI Act preliminary assessment template.

    This is NOT a compliance report. It maps Tracer-GOV features
    to EU AI Act articles for discussion purposes only.
    """

    @staticmethod
    def generate(audit_record: dict) -> Dict[str, Any]:
        metadata = audit_record.get("metadata", {})
        return {
            "report_type": "EU_AI_ACT_PRELIMINARY_MAPPING",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "disclaimer": (
                "This is a preliminary technical mapping, not a compliance "
                "certification. EU AI Act conformity requires assessment "
                "by a notified body. No regulatory compliance is claimed."
            ),
            "articles": {
                "art_13_transparency": {
                    "mapping": "partial",
                    "note": (
                        "System is deterministic and generates per-document "
                        "upper bounds. Whether this satisfies Art. 13 "
                        "requires regulatory review."
                    ),
                },
                "art_14_human_oversight": {
                    "mapping": "partial",
                    "note": (
                        "Threshold adjustment is configurable. "
                        "Full human oversight requires a compliance dashboard "
                        "not yet implemented."
                    ),
                },
                "art_15_accuracy": {
                    "mapping": "partial",
                    "note": (
                        "Zero bound violations observed on SIFT-1M benchmark "
                        "(254M+ pairs). Real-world accuracy depends on "
                        "deployment data and configuration."
                    ),
                },
            },
            "system_info": {
                "system": "Tracer-GOV / Madhava",
                "algorithm": "Cauchy-Schwarz + QR-JL",
                "version": "2.0.0-dev",
                "deterministic": True,
                "audit_trail_available": True,
            },
            "request_context": {
                "agency": metadata.get("requesting_agency", ""),
                "sensitivity": metadata.get("sensitivity", ""),
                "purpose": metadata.get("purpose", ""),
            },
            "overall_mapping": "preliminary — no certification claimed",
        }

    @staticmethod
    def to_text(report: Dict[str, Any]) -> str:
        lines = [
            "=" * 67,
            "  EU AI ACT — PRELIMINARY MAPPING (NOT CERTIFIED)",
            "=" * 67,
            "",
            f"  Generated: {report['generated_at']}",
            "",
            "  DISCLAIMER:",
            f"  {report['disclaimer']}",
            "",
            "  Article 13 (Transparency):",
            f"    Mapping: {report['articles']['art_13_transparency']['mapping']}",
            f"    {report['articles']['art_13_transparency']['note']}",
            "",
            "  Article 14 (Human Oversight):",
            f"    Mapping: {report['articles']['art_14_human_oversight']['mapping']}",
            f"    {report['articles']['art_14_human_oversight']['note']}",
            "",
            "  Article 15 (Accuracy):",
            f"    Mapping: {report['articles']['art_15_accuracy']['mapping']}",
            f"    {report['articles']['art_15_accuracy']['note']}",
            "",
            f"  Overall: {report['overall_mapping']}",
            "",
            "=" * 67,
            "  Winnex AI | licensing@winnex.ai | BSL 1.1",
        ]
        return "\n".join(lines)
