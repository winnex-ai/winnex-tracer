"""
Tracer-GOV — CGU Report Format
================================
Compatible with Controladoria-Geral da Uniao requirements.

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
from typing import Dict, Any
from datetime import datetime, timezone


class CguReport:
    """CGU-compatible transparency report generator."""

    @staticmethod
    def generate(audit_record: dict) -> Dict[str, Any]:
        metadata = audit_record.get("metadata", {})
        return {
            "report_type": "CGU_TRANSPARENCY",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "cgu_metadata": {
                "format": "transparency_v1",
                "protocol": audit_record.get("query_hash", "")[:16],
            },
            "agency_info": {
                "name": metadata.get("requesting_agency", ""),
                "agent": {
                    "cpf": metadata.get("cpf", ""),
                    "role": metadata.get("role", ""),
                },
            },
            "query_info": {
                "database": metadata.get("source_database", ""),
                "purpose": metadata.get("purpose", ""),
                "classification": metadata.get("sensitivity", "public"),
                "timestamp": metadata.get("timestamp", ""),
            },
            "proof": {
                "algorithm": "Cauchy-Schwarz + QR-JL (Madhava)",
                "violations": {
                    "64d": audit_record.get("violations_64d", 0),
                    "128d": audit_record.get("violations_128d", 0),
                },
                "exclusion_count": audit_record.get("total_excluded", 0),
            },
            "audit_trail": {
                "worm_hash": audit_record.get("worm_hash", ""),
                "worm_path": audit_record.get("worm_path", ""),
                "signature": bool(audit_record.get("signature", "")),
                "signature_type": audit_record.get(
                    "signature_algorithm", ""),
            },
            "disclaimer": (
                "Technical report — not a regulatory filing. "
                "CGU transparency reporting requires submission "
                "through official channels."
            ),
            "evidence_available": {
                "worm_hash": bool(audit_record.get("worm_hash", "")),
                "digital_signature": bool(audit_record.get("signature", "")),
                "signature_type": audit_record.get("signature_algorithm", ""),
            },
            "assessment": "self-assessment — not certified",
        }

    @staticmethod
    def to_text(report: Dict[str, Any]) -> str:
        lines = [
            "=" * 67,
            "  CGU TRANSPARENCY REPORT",
            "  Controladoria-Geral da Uniao",
            "=" * 67,
            "",
            f"  Protocol: {report['cgu_metadata']['protocol']}",
            f"  Agency: {report['agency_info']['name']}",
            f"  Agent: {report['agency_info']['agent']['cpf']}",
            "",
            f"  Database: {report['query_info']['database']}",
            f"  Purpose: {report['query_info']['purpose']}",
            f"  Classification: {report['query_info']['classification']}",
            "",
            f"  Algorithm: {report['proof']['algorithm']}",
            f"  Bound violations: "
            f"{report['proof']['violations']['64d']} (64D) / "
            f"{report['proof']['violations']['128d']} (128D)",
            f"  Exclusions proved: "
            f"{report['proof']['exclusion_count']}",
            "",
            f"  WORM: {report['audit_trail']['worm_hash'][:16] if report['audit_trail']['worm_hash'] else 'N/A'}...",
            f"  Signature: {report['audit_trail']['signature_type']}",
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
