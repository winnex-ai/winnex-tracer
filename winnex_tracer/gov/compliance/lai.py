"""
Tracer-GOV — LAI self-assessment report (Lei de Acesso a Informacao)
====================================================================
Freedom of Information Law structured report template.

WARNING: Self-assessment template, not a regulatory certification.
LAI compliance requires review by the agency's information access
committee.

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
from typing import Dict, Any
from datetime import datetime, timezone


class LaiReport:
    """LAI (Law 12.527/2011) self-assessment report generator."""

    @staticmethod
    def generate(audit_record: dict) -> Dict[str, Any]:
        metadata = audit_record.get("metadata", {})
        return {
            "report_type": "LAI_12527_2011_SELF_ASSESSMENT",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "disclaimer": (
                "Self-assessment template — not a regulatory certification. "
                "LAI compliance requires agency-level review."
            ),
            "responsible_entity": {
                "name": "Winnex AI",
                "contact": "licensing@winnex.ai",
            },
            "request_information": {
                "requesting_agency": metadata.get("requesting_agency", ""),
                "agent_cpf": metadata.get("cpf", ""),
                "agent_role": metadata.get("role", ""),
                "purpose": metadata.get("purpose", ""),
            },
            "data_source": {
                "database": metadata.get("source_database", ""),
                "sensitivity": metadata.get("sensitivity", "public"),
            },
            "search_results": {
                "result_count": len(
                    audit_record.get("result", {}).get("indices", [])),
                "algorithm": "Madhava + Cauchy-Schwarz",
                "bound_violations_observed": {
                    "64d": audit_record.get("violations_64d", 0),
                    "128d": audit_record.get("violations_128d", 0),
                },
            },
            "classification": {
                "level": metadata.get("sensitivity", "public"),
                "legal_basis": LaiReport._get_basis(
                    metadata.get("sensitivity", "public")),
                "secrecy_period_years": LaiReport._get_secrecy(
                    metadata.get("sensitivity", "public")),
            },
            "assessment": {
                "regulation": "Lei 12.527/2011",
                "articles_mapped": ["Art. 3", "Art. 7", "Art. 10",
                                    "Art. 23"],
                "classification": "self-assessment — not certified",
                "evidence_provided": [
                    "Full audit trail with mathematical proof",
                    "WORM hash chain",
                    "Digital signature",
                ],
            },
            "audit_trail_summary": {
                "total_records": len(audit_record.get("audit", [])),
                "worm_path": audit_record.get("worm_path", ""),
                "worm_hash": audit_record.get("worm_hash", ""),
                "blockchain_tx": audit_record.get("blockchain_tx", ""),
            },
        }

    @staticmethod
    def _get_basis(sensitivity: str) -> str:
        basis = {
            "public": "Law 12.527/2011 Art. 3",
            "restricted": "Law 12.527/2011 Art. 23",
            "secret": "Law 12.527/2011 Art. 24",
        }
        return basis.get(sensitivity, "Law 12.527/2011")

    @staticmethod
    def _get_secrecy(sensitivity: str) -> int:
        return {"public": 0, "restricted": 5, "secret": 15}.get(
            sensitivity, 0)

    @staticmethod
    def to_text(report: Dict[str, Any]) -> str:
        lines = [
            "=" * 67,
            "  LAI SELF-ASSESSMENT — Law 12.527/2011",
            "  Freedom of Information Law",
            "=" * 67,
            "",
            f"  Generated: {report['generated_at']}",
            f"  Agency: {report['request_information']['requesting_agency']}",
            f"  Purpose: {report['request_information']['purpose']}",
            "",
            f"  Data source: {report['data_source']['database']}",
            f"  Classification: {report['data_source']['sensitivity']}",
            f"  Legal basis: {report['classification']['legal_basis']}",
            "",
            f"  Results: {report['search_results']['result_count']}",
            f"  Bound violations: "
            f"{report['search_results']['bound_violations_observed']['64d']} (64D) / "
            f"{report['search_results']['bound_violations_observed']['128d']} (128D)",
            "",
            f"  Classification: self-assessment — not certified",
            "",
            "  DISCLAIMER:",
            f"  {report['disclaimer']}",
            "",
            "=" * 67,
            "  Winnex AI | licensing@winnex.ai | BSL 1.1",
        ]
        return "\n".join(lines)
