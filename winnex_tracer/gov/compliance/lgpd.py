"""
Tracer-GOV — LGPD Art. 20 self-assessment report
=================================================
Right to review automated decisions — structured report template.

WARNING: This is a technical self-assessment template, not a
legal opinion or regulatory certification. LGPD compliance
requires data protection officer review.

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
import json
from typing import Dict, Any, Optional
from datetime import datetime, timezone


class LgpdReport:
    """LGPD Art. 20 self-assessment report generator.

    Generates a structured report explaining automated decisions,
    including the mathematical bound proof. This is a template
    for technical documentation — regulatory compliance requires
    independent verification.
    """

    @staticmethod
    def generate(audit_record: dict) -> Dict[str, Any]:
        """Generate LGPD Art. 20 self-assessment report."""
        metadata = audit_record.get("metadata", {})
        audit_trail = audit_record.get("audit", [])
        result = audit_record.get("result", {})

        return {
            "report_type": "LGPD_ART20_SELF_ASSESSMENT",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "disclaimer": (
                "Self-assessment template — not a regulatory certification. "
                "LGPD Art. 20 compliance requires review by a data "
                "protection officer (DPO)."
            ),
            "responsible_entity": {
                "name": "Winnex AI",
                "contact": "licensing@winnex.ai",
            },
            "automated_decision": {
                "system": "Tracer-GOV / Madhava Vector Search",
                "algorithm": "Cauchy-Schwarz + QR-JL",
                "purpose": metadata.get("purpose", ""),
                "scope": {
                    "total_documents_analyzed": audit_record.get(
                        "total_documents", 0),
                    "results_returned": len(result.get("indices", [])),
                    "documents_excluded": audit_record.get(
                        "total_excluded", 0),
                },
            },
            "mathematical_proof": {
                "method": "Cauchy-Schwarz upper bound verification",
                "bound_violations_observed": {
                    "64d": audit_record.get("violations_64d", 0),
                    "128d": audit_record.get("violations_128d", 0),
                },
                "note": (
                    "Bound violations indicate a bug or misconfiguration — "
                    "they should not occur if the projection is valid."
                ),
            },
            "explanations": [
                {
                    "document_id": r.get("doc_id"),
                    "cosine_similarity": r.get("true_cosine"),
                    "upper_bound": r.get("upper_bound"),
                    "threshold": r.get("threshold"),
                    "excluded": r.get("excluded"),
                    "reason": (
                        f"Upper bound ({r.get('upper_bound')}) < "
                        f"threshold ({r.get('threshold')}) — "
                        "document is mathematically provable outside "
                        "top-K results via Cauchy-Schwarz."
                    ) if r.get("excluded") else (
                        "Document passed all bound checks."
                    ),
                }
                for r in audit_trail[:500]
            ],
            "total_explanations": len(audit_trail),
            "assessment": {
                "regulation": "LGPD",
                "article": "Art. 20",
                "classification": "self-assessment — not certified",
                "evidence_provided": [
                    "Per-document mathematical bound proof",
                    "Audit trail with hash chain",
                    "Digital signature (algorithm: "
                    f"{audit_record.get('signature_algorithm', 'Ed25519')})",
                ],
                "signature_present": bool(
                    audit_record.get("signature", "")),
            },
        }

    @staticmethod
    def to_text(report: Dict[str, Any]) -> str:
        lines = [
            "=" * 67,
            "  LGPD SELF-ASSESSMENT REPORT — Art. 20",
            "  Right to Review Automated Decisions",
            "=" * 67,
            "",
            f"  Generated: {report['generated_at']}",
            f"  Purpose: {report['automated_decision']['purpose']}",
            "",
            f"  Documents analyzed: "
            f"{report['automated_decision']['scope']['total_documents_analyzed']}",
            f"  Results returned: "
            f"{report['automated_decision']['scope']['results_returned']}",
            f"  Documents excluded: "
            f"{report['automated_decision']['scope']['documents_excluded']}",
            "",
            f"  Bound violations (64D): "
            f"{report['mathematical_proof']['bound_violations_observed']['64d']}",
            f"  Bound violations (128D): "
            f"{report['mathematical_proof']['bound_violations_observed']['128d']}",
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
