"""
Tracer-MED — Healthcare Compliance Reports
===========================================
Generates compliance-ready reports for clinical triage.

Covers the health-data protection frameworks:
  - LGPD (Brazil) — health data is sensitive data (Art. 5 II, Art. 11)
  - GDPR (EU) — Art. 9 (special categories: health)
  - HIPAA (US) — Privacy Rule / audit

All reports are **self-assessment templates — not certifications**.

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
from typing import Dict, Any
from datetime import datetime, timezone


class MedicalComplianceReport:
    """Compliance report generator for clinical triage.

    Combines the mathematical proof (bound soundness), the evidence chain
    (WORM custody), the clinical metadata, and the health-data compliance
    mapping (LGPD / GDPR Art. 9 / HIPAA).
    """

    @staticmethod
    def generate(triage_result: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a healthcare compliance report from a TriageResult dict."""
        soundness = triage_result.get("soundness", {})
        context = triage_result.get("context", {})
        evidence = triage_result.get("evidence_chain", {})
        return {
            "report_type": "TRACER_MED_HEALTH_COMPLIANCE",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "disclaimer": (
                "Self-assessment template — not a regulatory certification "
                "or legal opinion. LGPD/GDPR/HIPAA compliance requires "
                "institutional and legal review."
            ),
            "clinical_context": {
                "department": context.get("department", ""),
                "purpose": context.get("purpose", ""),
                "confidentiality": context.get("confidentiality", "restricted"),
            },
            "triage": {
                "corpus_size": triage_result.get("corpus_size", 0),
                "num_queries": triage_result.get("num_queries", 0),
                "k": triage_result.get("k", 10),
                "engine": triage_result.get("engine_used", ""),
                "filter_applied": triage_result.get("filter_applied", {}),
            },
            "mathematical_proof": {
                "algorithm": "Cauchy-Schwarz + QR-JL (Madhava)",
                "bound_violations": soundness.get("bound_violations", 0),
                "bound_pairs": soundness.get("bound_pairs", 0),
                "sound": soundness.get("sound", False),
                "statement": soundness.get("statement", ""),
            },
            "evidence_chain": {
                "verified": evidence.get("verified", False),
                "receipt": evidence.get("receipt", {}),
            },
            "compliance_mapping": {
                "LGPD": {
                    "articles": ["Art. 5 II (sensitive)", "Art. 11 (health)"],
                    "note": "Health data is sensitive — requires specific "
                            "consent or legal basis. Self-assessment.",
                },
                "GDPR": {
                    "articles": ["Art. 9 (special categories: health)"],
                    "note": "Health data processing requires Art. 9 "
                            "condition. Self-assessment.",
                },
                "HIPAA": {
                    "rule": "Privacy Rule / Security Rule / Breach",
                    "note": "PHI handling and audit. Self-assessment.",
                },
            },
            "privacy_controls": {
                "patient_pseudonymization": True,
                "worm_immutability": evidence.get("verified", False),
                "digital_signature_recommended": "Ed25519 / ICP-Brasil",
            },
        }

    @staticmethod
    def to_text(report: Dict[str, Any]) -> str:
        proof = report["mathematical_proof"]
        ev = report["evidence_chain"]
        lines = [
            "=" * 67,
            "  TRACER-MED HEALTH COMPLIANCE REPORT",
            "  Self-assessment template",
            "=" * 67,
            "",
            f"  Generated: {report['generated_at']}",
            f"  Dept: {report['clinical_context']['department']}",
            f"  Purpose: {report['clinical_context']['purpose']}",
            "",
            f"  Corpus: {report['triage']['corpus_size']} records",
            f"  Queries: {report['triage']['num_queries']}",
            "",
            f"  Mathematical proof:",
            f"    Bound violations: {proof['bound_violations']}",
            f"    Bound pairs:      {proof['bound_pairs']}",
            f"    Sound:            {proof['sound']}",
            "",
            f"  Evidence chain (WORM):",
            f"    Verified: {ev['verified']}",
            "",
            "  Compliance mapping (self-assessment):",
            "    LGPD Art. 5 II / Art. 11 | GDPR Art. 9 | HIPAA",
            "",
            "  DISCLAIMER:",
            f"  {report['disclaimer']}",
            "",
            "=" * 67,
            "  Winnex AI | licensing@winnex.ai | BSL 1.1",
        ]
        return "\n".join(lines)
