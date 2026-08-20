"""
Tracer-GOV — Jurisdiction Loader
==================================
Loads jurisdiction policies with hierarchical inheritance.

Hierarchy (least → most specific):
  global  →  <region>  →  <country>

Examples:
  - "br-gv" inherits from "global"
  - "pt-gv" inherits from "global" → "eu-gv" → "pt-gv"
  - "fr-gv" inherits from "global" → "eu-gv" → "fr-gv"

A jurisdiction is defined by a directory under config/jurisdictions/<code>/.
Each directory may contain:
  - policies.json     — mandatory: legal, retention, signature, agencies
  - strings.<lang>.json — optional: localized UI/report strings

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

# Root of the package (tracer-gov/)
_ROOT = Path(__file__).resolve().parent.parent.parent
_JURISDICTIONS_DIR = _ROOT / "config" / "jurisdictions"


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merge override into base.

    - dicts merge recursively (override wins at leaf level)
    - lists: "required_fields" is replaced by the more specific list
      (a country defines its own schema); other lists concatenate
      (base first, then override) and de-duplicate.
    - scalars/None from override replace base
    """
    merged = dict(base)
    for key, value in override.items():
        if (
            key in merged
            and isinstance(merged[key], dict)
            and isinstance(value, dict)
        ):
            merged[key] = _deep_merge(merged[key], value)
        elif (
            key == "required_fields"
            and isinstance(value, list)
        ):
            # A country/region defines its own required-fields schema;
            # the more specific list replaces any inherited one.
            merged[key] = value
        elif (
            key in merged
            and isinstance(merged[key], list)
            and isinstance(value, list)
        ):
            merged[key] = list(dict.fromkeys(list(merged[key]) + list(value)))
        else:
            merged[key] = value
    return merged


@dataclass
class Jurisdiction:
    """A single jurisdiction with its merged (inherited) policies."""

    code: str                       # e.g. "br-gv", "pt-gv"
    name: str                       # e.g. "Brazil Government"
    language: str                   # e.g. "pt-BR", "en-US", "fr"
    region: Optional[str]           # e.g. "eu-gv" (None for global)
    parent: Optional[str]           # immediate parent code (None for global)
    policies: Dict[str, Any] = field(default_factory=dict)
    strings: Dict[str, Any] = field(default_factory=dict)
    description: str = ""

    @property
    def is_country(self) -> bool:
        return self.code != "global"

    def get_policy(self, key: str, default: Any = None) -> Any:
        return self.policies.get(key, default)

    def get_sensitivity(self, classification: str) -> Dict[str, Any]:
        sens = self.policies.get("sensitivity", {})
        return sens.get(classification, sens.get("default", {}))

    def get_agency(self, agency: str) -> Dict[str, Any]:
        agencies = self.policies.get("agencies", {})
        return agencies.get(agency, agencies.get("default", {}))

    def get_retention_years(self, agency: str = "", sensitivity: str = "") -> int:
        """Resolve retention with precedence:
        1. exact 'agency:sensitivity' key
        2. sensitivity config
        3. agency config
        4. retention map
        5. default
        """
        retention = self.policies.get("retention", {})
        agencies = self.policies.get("agencies", {})

        key = f"{agency}:{sensitivity}"
        if key in retention:
            return int(retention[key])

        sens = self.policies.get("sensitivity", {})
        if sensitivity in sens:
            return int(sens[sensitivity].get("retention_years", 5))

        if agency in agencies:
            return int(agencies[agency].get("retention_years", 5))

        if agency in retention:
            return int(retention[agency])
        if sensitivity in retention:
            return int(retention[sensitivity])

        return int(retention.get("default", 5))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "name": self.name,
            "language": self.language,
            "region": self.region,
            "parent": self.parent,
            "description": self.description,
            "policies": self.policies,
        }


def _load_jurisdiction_file(path: Path) -> Dict[str, Any]:
    """Load a JSON file, returning {} on missing/parse error."""
    if not path.exists():
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


class JurisdictionRegistry:
    """Registry of all jurisdictions with inheritance resolution."""

    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = Path(base_dir) if base_dir else _JURISDICTIONS_DIR
        self._jurisdictions: Dict[str, Jurisdiction] = {}
        self._load()

    def _load(self) -> None:
        """Discover jurisdiction directories and build the inheritance graph."""
        if not self.base_dir.exists():
            return

        raw: Dict[str, Dict[str, Any]] = {}

        for child in sorted(self.base_dir.iterdir()):
            if not child.is_dir():
                continue
            code = child.name
            meta = _load_jurisdiction_file(child / "meta.json")
            policies = _load_jurisdiction_file(child / "policies.json")

            # Discover localized strings files: strings.<lang>.json
            strings: Dict[str, Any] = {}
            for sf in sorted(child.glob("strings.*.json")):
                lang = sf.name.replace("strings.", "").replace(".json", "")
                strings[lang] = _load_jurisdiction_file(sf)

            if not policies and code != "global":
                # Skip jurisdictions with no policies (not yet implemented)
                continue

            raw[code] = {
                "meta": meta,
                "policies": policies,
                "strings": strings,
            }

        # Build inheritance graph — parents must resolve to existing codes
        for code, data in raw.items():
            parent = data["meta"].get("parent")
            if parent and parent not in raw:
                # Try uppercase/lowercase variants (eu-gv vs EU-GV)
                variants = [parent, parent.upper(), parent.lower(),
                            parent.replace("-", "_")]
                parent = next((v for v in variants if v in raw), None)

            name = data["meta"].get("name", code.upper())
            language = data["meta"].get("language", "en")
            region = data["meta"].get("region")
            description = data["meta"].get("description", "")

            self._jurisdictions[code] = Jurisdiction(
                code=code,
                name=name,
                language=language,
                region=region,
                parent=parent,
                description=description,
            )

        # Resolve merged policies via inheritance (global → region → country)
        for code, jur in self._jurisdictions.items():
            chain: List[str] = []
            node: Optional[str] = code
            while node is not None and node not in chain:
                chain.append(node)
                node = self._jurisdictions[node].parent if node in self._jurisdictions else None
            chain.reverse()  # global → ... → country

            merged_policies: Dict[str, Any] = {}
            merged_strings: Dict[str, Any] = {}
            for c in chain:
                data = raw[c]
                merged_policies = _deep_merge(merged_policies, data["policies"])
                for lang, s in data["strings"].items():
                    merged_strings[lang] = _deep_merge(
                        merged_strings.get(lang, {}), s)

            jur.policies = merged_policies
            jur.strings = merged_strings

    def get(self, code: str) -> Jurisdiction:
        """Get a jurisdiction (normalizing code). Case-insensitive."""
        norm = resolve_jurisdiction_code(code)
        if norm not in self._jurisdictions:
            raise KeyError(
                f"Unknown jurisdiction '{code}'. Available: {list(self._jurisdictions)}"
            )
        return self._jurisdictions[norm]

    def get_or_default(self, code: str) -> Jurisdiction:
        """Get a jurisdiction, falling back to global."""
        try:
            return self.get(code)
        except KeyError:
            return self._jurisdictions.get("global")

    def list(self) -> List[Jurisdiction]:
        return sorted(self._jurisdictions.values(), key=lambda j: j.code)

    def has(self, code: str) -> bool:
        return resolve_jurisdiction_code(code) in self._jurisdictions

    def resolve_policy(self, code: str, key: str, default: Any = None) -> Any:
        """Get a policy value from a jurisdiction (inheritance already applied)."""
        jur = self.get_or_default(code)
        return jur.policies.get(key, default)


# Module-level default registry (singleton-ish, built lazily)
_registry: Optional[JurisdictionRegistry] = None


def _get_registry() -> JurisdictionRegistry:
    global _registry
    if _registry is None:
        _registry = JurisdictionRegistry()
    return _registry


def get_jurisdiction(code: str) -> Jurisdiction:
    """Get a jurisdiction by code."""
    return _get_registry().get(code)


def list_jurisdictions() -> List[str]:
    """List all available jurisdiction codes."""
    return [j.code for j in _get_registry().list()]


def resolve_jurisdiction_code(code: str) -> str:
    """Normalize a jurisdiction code (case-insensitive, strip)."""
    return code.strip().lower()


def reload_jurisdictions() -> None:
    """Force reload of the jurisdiction registry (for tests)."""
    global _registry
    _registry = JurisdictionRegistry()
    return _registry
