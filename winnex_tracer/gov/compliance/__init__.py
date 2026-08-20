"""Tracer-GOV — Compliance reports (jurisdiction-localized).

Country-specific modules:
  - LGPD / LAI / Marco Legal (Brazil)
  - EU AI Act (European Union)
  - LocalizedReport — generates reports in each jurisdiction's language.

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
from .lgpd import LgpdReport
from .lai import LaiReport
from .marco_legal import MarcoLegalReport
from .eu_ai_act import EuAiActReport
from .localized import LocalizedReport, generate_localized_report

__all__ = [
    "LgpdReport",
    "LaiReport",
    "MarcoLegalReport",
    "EuAiActReport",
    "LocalizedReport",
    "generate_localized_report",
]
