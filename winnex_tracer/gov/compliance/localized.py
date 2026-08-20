"""
Tracer-GOV — Localized Compliance Reports
===========================================
Generates compliance reports using the active jurisdiction's language
and legal framework.

Each jurisdiction carries:
  - policies.json        → legal basis, sensitivity, retention, agencies
  - strings.<lang>.json  → localized report strings

The report language is the jurisdiction's language (meta.json):
  br-gv → pt-BR, us-gv → en-US, eu-gv → en, pt-gv → pt-PT,
  es-gv → es, fr-gv → fr, de-gv → de, it-gv → it.

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional


class LocalizedReport:
    """A compliance report localized for a jurisdiction.

    Args:
        jurisdiction_code: e.g. "br-gv", "eu-gv", "us-gv", ...
        record: the audit record (metadata, violations, signatures, ...)
    """

    def __init__(self, jurisdiction_code: str, record: Dict[str, Any]):
        from winnex_tracer.gov.core.jurisdiction import get_jurisdiction
        self.jurisdiction = get_jurisdiction(jurisdiction_code)
        self.record = record
        # Strings: prefer the jurisdiction's language, fall back to 'en'
        lang = self.jurisdiction.language
        self.strings = self.jurisdiction.strings.get(
            lang, self.jurisdiction.strings.get("en", {}))
        self.metadata = record.get("metadata", {})

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def s(self, section: str, key: str, default: str = "") -> str:
        """Get a localized string from the report section."""
        return self.strings.get(section, {}).get(key, default)

    def _common(self) -> Dict[str, Any]:
        return {
            "jurisdiction": self.jurisdiction.code,
            "jurisdiction_name": self.jurisdiction.name,
            "language": self.jurisdiction.language,
            "generated_at": self.record.get("generated_at", ""),
            "contact": "licensing@winnex.ai",
            "disclaimer": (
                self.s("report", "self_assessment")
                or "self-assessment — not certified"
            ),
        }

    def _proof(self) -> Dict[str, Any]:
        return {
            "algorithm": "Cauchy-Schwarz + QR-JL (Madhava)",
            "bound_violations": {
                "64d": self.record.get("violations_64d", 0),
                "128d": self.record.get("violations_128d", 0),
            },
            "total_excluded": self.record.get("total_excluded", 0),
            "explanations": [
                {
                    "doc_id": r.get("doc_id"),
                    "true_cosine": r.get("true_cosine"),
                    "upper_bound": r.get("upper_bound"),
                    "threshold": r.get("threshold"),
                    "excluded": r.get("excluded"),
                    "reason": (
                        self.s("report", "proved_exclusion")
                        if r.get("excluded")
                        else self.s("report", "survived")
                    ),
                }
                for r in self.record.get("audit", [])[:500]
            ],
        }

    def _evidence(self) -> Dict[str, Any]:
        return {
            "mathematical_proof": True,
            "worm_storage": bool(self.record.get("worm_hash", "")),
            "worm_hash": self.record.get("worm_hash", ""),
            "blockchain": bool(self.record.get("blockchain_tx", "")),
            "blockchain_tx": self.record.get("blockchain_tx", ""),
            "digital_signature": bool(self.record.get("signature", "")),
            "signature_type": self.record.get("signature_algorithm", ""),
        }

    # ------------------------------------------------------------------
    # Framework-specific report generators
    # ------------------------------------------------------------------
    def generate(self) -> Dict[str, Any]:
        """Generate a report for the active jurisdiction's framework."""
        code = self.jurisdiction.code
        frameworks = self.jurisdiction.policies.get(
            "compliance_frameworks", [])
        fw = " ".join(frameworks).lower()

        if code == "br-gv":
            return self._brazil_report()
        if code == "us-gv":
            return self._usa_report()
        # EU member states: use their localized GDPR/RGPD strings
        if code in ("eu-gv", "pt-gv", "fr-gv", "it-gv", "es-gv", "de-gv") \
                or "gdpr" in fw or "rgpd" in fw:
            return self._gdpr_report()
        if "foia" in fw or "hipaa" in fw:
            return self._usa_report()
        return self._generic_report()

    def _brazil_report(self) -> Dict[str, Any]:
        return {
            "report_type": f"{self.jurisdiction.code.upper()}_COMPLIANCE",
            "title": self.s("lgpd", "title") or self.s("lai", "title"),
            "subtitle": self.s("lgpd", "subtitle") or "",
            "regulation": self.s("lgpd", "regulation"),
            "articles_mapped": self.strings.get("lgpd", {}).get(
                "articles_mapped", []),
            **self._common(),
            "request": {
                "agency": self.metadata.get(
                    "requesting_agency",
                    self.metadata.get("orgao_requisitante", "")),
                "operator": self.metadata.get(
                    "operator_id", self.metadata.get("cpf", "")),
                "role": self.metadata.get(
                    "role", self.metadata.get("funcao", "")),
                "purpose": self.metadata.get(
                    "purpose", self.metadata.get("finalidade", "")),
            },
            "data_source": {
                "database": self.metadata.get(
                    "source_database",
                    self.metadata.get("base_de_dados", "")),
                "sensitivity": self.metadata.get("sensitivity", "public"),
                "legal_basis": self._sensitivity_basis(),
            },
            "proof": self._proof(),
            "evidence": self._evidence(),
        }

    def _gdpr_report(self) -> Dict[str, Any]:
        code = self.jurisdiction.code
        # Prefer country-specific strings (rgpd for pt, dsgvo for de, gdpr otherwise)
        gdpr_strings = (
            self.strings.get("rgpd", {})
            or self.strings.get("dsgvo", {})
            or self.strings.get("gdpr", {})
        )
        reg = gdpr_strings.get(
            "regulation", "GDPR" if code != "de-gv" else "DSGVO")
        return {
            "report_type": f"{self.jurisdiction.code.upper()}_GDPR",
            "title": gdpr_strings.get("title", "GDPR REPORT — Art. 22"),
            "subtitle": gdpr_strings.get("subtitle", ""),
            "regulation": reg,
            "articles_mapped": gdpr_strings.get("articles_mapped", []),
            **self._common(),
            "request": {
                "agency": self.metadata.get(
                    "requesting_agency",
                    self.metadata.get("orgao_requisitante",
                                      self.metadata.get("organismo_solicitante", ""))),
                "operator": self.metadata.get("operator_id", ""),
                "role": self.metadata.get("role", ""),
                "purpose": self.metadata.get("purpose", ""),
            },
            "data_source": {
                "database": self.metadata.get("source_database", ""),
                "sensitivity": self.metadata.get("sensitivity", "public"),
                "legal_basis": self._sensitivity_basis(),
            },
            "proof": self._proof(),
            "evidence": self._evidence(),
        }

    def _usa_report(self) -> Dict[str, Any]:
        us_strings = self.strings.get("foia", {}) or self.strings.get("hipaa", {})
        return {
            "report_type": f"{self.jurisdiction.code.upper()}_COMPLIANCE",
            "title": us_strings.get("title", "US GOVERNMENT COMPLIANCE"),
            "subtitle": us_strings.get("subtitle", ""),
            "regulation": us_strings.get("regulation", ""),
            "articles_mapped": us_strings.get("articles_mapped", []),
            **self._common(),
            "request": {
                "agency": self.metadata.get("requesting_agency", ""),
                "operator": self.metadata.get("operator_id", ""),
                "role": self.metadata.get("role", ""),
                "purpose": self.metadata.get("purpose", ""),
            },
            "data_source": {
                "database": self.metadata.get("source_database", ""),
                "sensitivity": self.metadata.get("sensitivity", "public"),
                "legal_basis": self._sensitivity_basis(),
            },
            "proof": self._proof(),
            "evidence": self._evidence(),
        }

    def _generic_report(self) -> Dict[str, Any]:
        return {
            "report_type": f"{self.jurisdiction.code.upper()}_COMPLIANCE",
            "title": self.jurisdiction.name,
            "subtitle": self.jurisdiction.description,
            "regulation": " | ".join(
                self.jurisdiction.policies.get("compliance_frameworks", [])),
            "articles_mapped": [],
            **self._common(),
            "request": {
                "agency": self.metadata.get("requesting_agency", ""),
                "operator": self.metadata.get("operator_id", ""),
                "role": self.metadata.get("role", ""),
                "purpose": self.metadata.get("purpose", ""),
            },
            "data_source": {
                "database": self.metadata.get("source_database", ""),
                "sensitivity": self.metadata.get("sensitivity", "public"),
                "legal_basis": self._sensitivity_basis(),
            },
            "proof": self._proof(),
            "evidence": self._evidence(),
        }

    def _sensitivity_basis(self) -> str:
        sens = self.metadata.get("sensitivity", "public")
        cfg = self.jurisdiction.get_sensitivity(sens)
        return cfg.get("legal_basis", "")


def generate_localized_report(jurisdiction_code: str,
                              record: Dict[str, Any]) -> Dict[str, Any]:
    """Generate a compliance report localized for a jurisdiction."""
    return LocalizedReport(jurisdiction_code, record).generate()
