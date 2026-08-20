"""
Tracer-GAP — Financial Compliance Reports
===========================================
Generates compliance-ready reports for financial gap analysis.

Covers the financial regulatory frameworks:
  - SOX (US) — Sarbanes-Oxley internal controls
  - SEC (US) — disclosure and reporting
  - CVM (Brazil) — securities regulator
  - LGPD (Brazil) / GDPR (EU) — financial data protection

All reports are **self-assessment templates — not certifications**.

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
from typing import Dict, Any
from datetime import datetime, timezone


class FinancialComplianceReport:
    """Compliance report generator for financial gap analysis.

    Combines the mathematical proof (bound soundness), the evidence chain
    (WORM custody), the financial metadata, and the regulatory mapping
    (SOX / SEC / CVM / LGPD / GDPR).
    """

    @staticmethod
    def generate(gap_result: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a financial compliance report from a GapResult dict."""
        soundness = gap_result.get("soundness", {})
        context = gap_result.get("context", {})
        evidence = gap_result.get("evidence_chain", {})
        return {
            "report_type": "TRACER_GAP_FINANCIAL_COMPLIANCE",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "disclaimer": (
                "Self-assessment template — not a regulatory certification "
                "or legal opinion. SOX/SEC/CVM/LGPD/GDPR compliance requires "
                "institutional and legal review."
            ),
            "financial_context": {
                "sector": context.get("sector", ""),
                "instrument_type": context.get("instrument_type", ""),
                "cik": context.get("cik", ""),
                "company": context.get("company", ""),
                "period": context.get("period", ""),
                "purpose": context.get("purpose", ""),
            },
            "gap_analysis": {
                "corpus_size": gap_result.get("corpus_size", 0),
                "num_queries": gap_result.get("num_queries", 0),
                "k": gap_result.get("k", 10),
                "engine": gap_result.get("engine_used", ""),
                "filter_applied": gap_result.get("filter_applied", {}),
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
            "regulatory_mapping": {
                "SOX": {
                    "scope": "Internal controls over financial reporting",
                    "note": "Gap analysis supports control identification. "
                            "Self-assessment.",
                },
                "SEC": {
                    "scope": "Disclosure and reporting (10-K, 10-Q)",
                    "note": "Search over real filings supports disclosure "
                            "review. Self-assessment.",
                },
                "CVM": {
                    "scope": "Brazilian securities regulation",
                    "note": "Gap identification for BR issuers. "
                            "Self-assessment.",
                },
                "LGPD": {
                    "scope": "Brazilian data protection (financial data)",
                    "note": "Financial data handling. Self-assessment.",
                },
                "GDPR": {
                    "scope": "EU data protection (financial data)",
                    "note": "Financial data handling. Self-assessment.",
                },
            },
        }

    @staticmethod
    def to_text(report: Dict[str, Any]) -> str:
        proof = report["mathematical_proof"]
        ev = report["evidence_chain"]
        ctx = report["financial_context"]
        lines = [
            "=" * 67,
            "  TRACER-GAP FINANCIAL COMPLIANCE REPORT",
            "  Self-assessment template",
            "=" * 67,
            "",
            f"  Generated: {report['generated_at']}",
            f"  Sector: {ctx['sector']} | Instrument: {ctx['instrument_type']}",
            f"  Company: {ctx['company']} | Period: {ctx['period']}",
            "",
            f"  Corpus: {report['gap_analysis']['corpus_size']} records",
            f"  Queries: {report['gap_analysis']['num_queries']}",
            "",
            f"  Mathematical proof:",
            f"    Bound violations: {proof['bound_violations']}",
            f"    Bound pairs:      {proof['bound_pairs']}",
            f"    Sound:            {proof['sound']}",
            "",
            f"  Evidence chain (WORM):",
            f"    Verified: {ev['verified']}",
            "",
            "  Regulatory mapping (self-assessment):",
            "    SOX | SEC | CVM | LGPD | GDPR",
            "",
            "  DISCLAIMER:",
            f"  {report['disclaimer']}",
            "",
            "=" * 67,
            "  Winnex AI | licensing@winnex.ai | BSL 1.1",
        ]
        return "\n".join(lines)
