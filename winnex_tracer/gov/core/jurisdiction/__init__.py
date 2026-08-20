"""
Tracer-GOV — Jurisdiction System (Global)
==========================================
Multi-jurisdiction configuration with hierarchical inheritance.

Jurisdiction codes follow a 2-tier scheme:
  - Country/region codes:  "br-gv", "us-gv", "eu-gv", "pt-gv", "es-gv", ...
  - "global"               — the base defaults every jurisdiction inherits

Inheritance order (least → most specific):
  global  →  <region/eu>  →  <country>   (e.g. global → eu-gv → pt-gv)

Each jurisdiction directory contains:
  - policies.json         — legal/retention/signature/agency configuration
  - strings.<lang>.json   — localized report strings (language of the country)

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai | github.com/winnex-ai/tracer-gov
"""
from .loader import (
    JurisdictionRegistry,
    Jurisdiction,
    get_jurisdiction,
    list_jurisdictions,
    resolve_jurisdiction_code,
    reload_jurisdictions,
)

__all__ = [
    "JurisdictionRegistry",
    "Jurisdiction",
    "get_jurisdiction",
    "list_jurisdictions",
    "resolve_jurisdiction_code",
    "reload_jurisdictions",
]
