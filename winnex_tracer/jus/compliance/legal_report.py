"""
Tracer-JUS — Legal Compliance Reports
======================================
Generates compliance-ready reports for legal searches and e-Discovery.

Reuses the Tracer-GOV compliance mapping (LGPD, LAI, TCU, CGU) and adds
the legal-e-Discovery context: proof report, evidence chain, and case
metadata. All reports are **self-assessment templates — not certifications**.

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
from typing import Dict, Any
from datetime import datetime, timezone


class LegalComplianceReport:
    """Compliance report generator for legal searches and e-Discovery.

    Combines:
      - the mathematical proof (bound soundness),
      - the evidence chain (WORM custody),
      - the legal metadata (case, court, purpose),
      - the Tracer-GOV compliance mapping (LGPD/LAI/TCU/CGU).
    """

    @staticmethod
    def generate(discovery_result: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a legal compliance report from a DiscoveryResult dict."""
        soundness = discovery_result.get("soundness", {})
        case = discovery_result.get("case", {})
        evidence = discovery_result.get("evidence_chain", {})
        return {
            "report_type": "TRACER_JUS_LEGAL_COMPLIANCE",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "disclaimer": (
                "Self-assessment template — not a regulatory certification "
                "or legal opinion. LGPD/LAI/TCU/CGU compliance requires "
                "institutional review."
            ),
            "case": {
                "docket_number": case.get("docket_number", ""),
                "court": case.get("court", ""),
                "chamber": case.get("chamber", ""),
                "action_type": case.get("action_type", ""),
                "purpose": case.get("purpose", ""),
                "confidentiality": case.get("confidentiality", "public"),
            },
            "discovery": {
                "corpus_size": discovery_result.get("corpus_size", 0),
                "num_queries": discovery_result.get("num_queries", 0),
                "k": discovery_result.get("k", 10),
                "engine": discovery_result.get("engine_used", ""),
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
                "LGPD_Art20": "Right to review automated decisions — "
                              "self-assessment template",
                "LAI_12527": "Freedom of information — self-assessment",
                "TCU": "Accountability — self-assessment",
                "CGU": "Transparency — self-assessment",
            },
            "signature_required": {
                "recommended": "Ed25519",
                "restricted_or_secret": "ICP-Brasil (A1/A3)",
            },
        }

    @staticmethod
    def to_text(report: Dict[str, Any]) -> str:
        proof = report["mathematical_proof"]
        ev = report["evidence_chain"]
        case = report["case"]
        lines = [
            "=" * 67,
            "  TRACER-JUS LEGAL COMPLIANCE REPORT",
            "  Self-assessment template",
            "=" * 67,
            "",
            f"  Generated: {report['generated_at']}",
            f"  Case: {case.get('docket_number')} | {case.get('court')}",
            f"  Purpose: {case.get('purpose')}",
            "",
            f"  Corpus: {report['discovery']['corpus_size']} docs",
            f"  Queries: {report['discovery']['num_queries']}",
            "",
            f"  Mathematical proof:",
            f"    Bound violations: {proof['bound_violations']}",
            f"    Bound pairs:      {proof['bound_pairs']}",
            f"    Sound:            {proof['sound']}",
            f"    {proof['statement']}",
            "",
            f"  Evidence chain (WORM):",
            f"    Verified: {ev['verified']}",
            f"    Receipt:  {ev['receipt'].get('worm_hash', '')[:16]}...",
            "",
            "  Compliance mapping (self-assessment):",
            "    LGPD Art. 20 | LAI 12.527/2011 | TCU | CGU",
            "",
            "  DISCLAIMER:",
            f"  {report['disclaimer']}",
            "",
            "=" * 67,
            "  Winnex AI | licensing@winnex.ai | BSL 1.1",
        ]
        return "\n".join(lines)
