"""
Tracer-GOV — TCU Report Format
================================
Compatible with Tribunal de Contas da Uniao requirements.
Generates structured reports for accountability submissions.

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
from typing import Dict, Any
from datetime import datetime, timezone


class TcuReport:
    """TCU-compatible accountability report generator."""

    @staticmethod
    def generate(audit_record: dict) -> Dict[str, Any]:
        metadata = audit_record.get("metadata", {})
        return {
            "report_type": "TCU_ACCOUNTABILITY",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "tcu_metadata": {
                "format_version": "1.0",
                "submission_channel": "API",
                "protocol_id": audit_record.get("query_hash", "")[:16],
            },
            "responsible_party": {
                "agency": metadata.get("requesting_agency", ""),
                "agent_cpf": metadata.get("cpf", ""),
                "agent_role": metadata.get("role", ""),
                "contact": "licensing@winnex.ai",
            },
            "operation": {
                "type": "vector_search",
                "database": metadata.get("source_database", ""),
                "purpose": metadata.get("purpose", ""),
                "sensitivity": metadata.get("sensitivity", "public"),
                "timestamp": metadata.get("timestamp", ""),
            },
            "mathematical_proof": {
                "algorithm": "Cauchy-Schwarz + QR-JL",
                "dimensions": "128D -> 64D -> 128D",
                "bound_violations": {
                    "64d": audit_record.get("violations_64d", 0),
                    "128d": audit_record.get("violations_128d", 0),
                },
                "total_proved_exclusions": audit_record.get(
                    "total_excluded", 0),
            },
            "audit_trail_evidence": {
                "worm_path": audit_record.get("worm_path", ""),
                "worm_hash": audit_record.get("worm_hash", ""),
                "blockchain_tx": audit_record.get("blockchain_tx", ""),
                "signature_present": bool(
                    audit_record.get("signature", "")),
                "signature_algorithm": audit_record.get(
                    "signature_algorithm", ""),
            },
            "disclaimer": (
                "Technical report — not a regulatory filing. "
                "TCU accountability requires official submission "
                "through proper channels."
            ),
            "evidence_available": {
                "mathematical_proof": True,
                "worm_storage": bool(audit_record.get("worm_hash", "")),
                "blockchain": bool(audit_record.get("blockchain_tx", "")),
                "digital_signature": bool(
                    audit_record.get("signature", "")),
            },
        }

    @staticmethod
    def to_text(report: Dict[str, Any]) -> str:
        evidence = report["evidence_available"]
        lines = [
            "=" * 67,
            "  TCU ACCOUNTABILITY REPORT",
            "  Tribunal de Contas da Uniao",
            "=" * 67,
            "",
            f"  Protocol: {report['tcu_metadata']['protocol_id']}",
            f"  Generated: {report['generated_at']}",
            f"  Agency: {report['responsible_party']['agency']}",
            f"  Agent: {report['responsible_party']['agent_cpf']}",
            f"  Role: {report['responsible_party']['agent_role']}",
            "",
            f"  Database: {report['operation']['database']}",
            f"  Purpose: {report['operation']['purpose']}",
            f"  Classification: {report['operation']['sensitivity']}",
            "",
            f"  Algorithm: {report['mathematical_proof']['algorithm']}",
            f"  Bound violations: "
            f"{report['mathematical_proof']['bound_violations']['64d']} (64D) / "
            f"{report['mathematical_proof']['bound_violations']['128d']} (128D)",
            f"  Exclusions proved: "
            f"{report['mathematical_proof']['total_proved_exclusions']}",
            "",
            "  Evidence available:",
            f"    Mathematical proof:   {'YES' if evidence['mathematical_proof'] else 'NO'}",
            f"    WORM storage:         {'YES' if evidence['worm_storage'] else 'NO'}",
            f"    Blockchain:           {'YES' if evidence['blockchain'] else 'NO'}",
            f"    Digital signature:    {'YES' if evidence['digital_signature'] else 'NO'}",
            "",
            "  DISCLAIMER:",
            f"  {report['disclaimer']}",
            "",
            "=" * 67,
            "  Winnex AI | licensing@winnex.ai | BSL 1.1",
        ]
        return "\n".join(lines)
