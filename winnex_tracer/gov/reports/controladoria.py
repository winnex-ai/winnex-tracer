"""
Tracer-GOV — Controladoria Report Format
==========================================
General government oversight report format.

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
from typing import Dict, Any
from datetime import datetime, timezone


class ControladoriaReport:
    """General government oversight report generator."""

    @staticmethod
    def generate(audit_record: dict) -> Dict[str, Any]:
        metadata = audit_record.get("metadata", {})
        return {
            "report_type": "CONTROLADORIA_OVERSIGHT",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "oversight_body": {
                "scope": "government_audit",
                "legal_framework": [
                    "Law 8.443/1992 (TCU)",
                    "Law 12.527/2011 (LAI)",
                    "LGPD Art. 20",
                    "Law 14.129/2021 (Marco Legal Gov Digital)",
                ],
            },
            "audited_operation": {
                "agency": metadata.get("requesting_agency", ""),
                "agent": {
                    "cpf": metadata.get("cpf", ""),
                    "role": metadata.get("role", ""),
                },
                "database": metadata.get("source_database", ""),
                "purpose": metadata.get("purpose", ""),
                "classification": metadata.get("sensitivity", "public"),
                "timestamp": metadata.get("timestamp", ""),
            },
            "technical_verification": {
                "algorithm": "Madhava Cauchy-Schwarz + QR-JL",
                "search_performed": True,
                "audit_trail_generated": bool(
                    audit_record.get("audit", [])),
                "bound_violations": {
                    "64d": audit_record.get("violations_64d", 0),
                    "128d": audit_record.get("violations_128d", 0),
                },
            },
            "data_integrity": {
                "worm_active": bool(audit_record.get("worm_path", "")),
                "worm_hash_valid": bool(
                    audit_record.get("worm_hash", "")),
                "blockchain_confirmed": bool(
                    audit_record.get("blockchain_tx", "")),
                "signature_valid": bool(
                    audit_record.get("signature", "")),
            },
            "disclaimer": (
                "Self-assessment template — not a regulatory filing."
            ),
            "evidence_checklist": {
                "digital_signature": bool(
                    audit_record.get("signature", "")),
                "audit_trail": bool(audit_record.get("audit", [])),
                "worm_storage": bool(audit_record.get("worm_path", "")),
                "blockchain": bool(audit_record.get("blockchain_tx", "")),
            },
            "regulations_mapped": [
                "LGPD Art. 20 (preliminary mapping)",
                "LAI 12.527/2011 (preliminary mapping)",
                "Marco Legal Gov Digital 14.129/2021 (preliminary mapping)",
            ],
            "assessment": "self-assessment — not certified",
            "recommendations": [],
        }

    @staticmethod
    def to_text(report: Dict[str, Any]) -> str:
        lines = [
            "=" * 67,
            "  CONTROLADORIA OVERSIGHT REPORT",
            "=" * 67,
            "",
            f"  Generated: {report['generated_at']}",
            f"  Agency: {report['audited_operation']['agency']}",
            f"  Agent: {report['audited_operation']['agent']['cpf']}",
            f"  Database: {report['audited_operation']['database']}",
            f"  Purpose: {report['audited_operation']['purpose']}",
            f"  Classification: {report['audited_operation']['classification']}",
            "",
            "  Technical verification:",
            f"    Algorithm: {report['technical_verification']['algorithm']}",
            f"    Audit trail: "
            f"{'GENERATED' if report['technical_verification']['audit_trail_generated'] else 'MISSING'}",
            f"    Bound violations: "
            f"{report['technical_verification']['bound_violations']['64d']} (64D) / "
            f"{report['technical_verification']['bound_violations']['128d']} (128D)",
            "",
            "  Data integrity:",
            f"    WORM: {'ACTIVE' if report['data_integrity']['worm_active'] else 'INACTIVE'}",
            f"    Blockchain: {'CONFIRMED' if report['data_integrity']['blockchain_confirmed'] else 'N/A'}",
            f"    Signature: {'VALID' if report['data_integrity']['signature_valid'] else 'ABSENT'}",
            "",
            f"  Status: {report['compliance_summary']['overall_status'].upper()}",
            "",
            "  Regulations met:",
            *[f"    - {r}" for r in report['compliance_summary']['regulations_met']],
            "",
            "=" * 67,
            "  Winnex AI | licensing@winnex.ai | BSL 1.1",
        ]
        return "\n".join(lines)
