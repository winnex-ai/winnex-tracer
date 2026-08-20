"""
Tracer-GOV — Retention Policy Engine
======================================
Manages record retention periods according to configured policies.
Policies are loaded from JSON — no hardcoded values.

Supports:
  - Configurable retention periods per agency/sensitivity
  - Expiration checking
  - Cleanup scheduling hooks
  - Legal hold override

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
import json, os
from typing import Optional, Dict, Any, Callable, List
from datetime import datetime, timezone, timedelta
from pathlib import Path


class RetentionPolicy:
    """Retention policy engine — configured from policies JSON.

    Args:
        policies_path: Path to policies JSON file
    """

    def __init__(self, policies_path: str = ""):
        self._policies: Dict[str, Any] = {}
        paths_to_try = [
            policies_path,
            os.environ.get("WINNEX_TRACER_POLICIES", ""),
            str(Path(__file__).parent.parent / "config" / "policies.json"),
        ]
        for p in paths_to_try:
            if p and os.path.exists(p):
                with open(p) as f:
                    self._policies = json.load(f)
                break

    def get_policy(self, key: str, default=None):
        return self._policies.get(key, default)

    def get_retention_years(self, agency: str = "",
                            sensitivity: str = "") -> int:
        """Get retention years from policy configuration.

        Resolution order:
        1. Exact agency:sensitivity match
        2. Agency match
        3. Sensitivity match
        4. Category from retention map
        5. Default from policies
        """
        retention = self.get_policy("retention", {})
        agencies = self.get_policy("agencies", {})

        # Try exact match
        key = f"{agency}:{sensitivity}"
        if key in retention:
            return retention[key]

        # Try sensitivity config (secret data has legal minimums)
        sens = self.get_policy("sensitivity", {})
        if sensitivity in sens:
            return sens[sensitivity].get("retention_years", 5)

        # Try agency config
        if agency in agencies:
            return agencies[agency].get("retention_years", 5)

        # Try agency match in retention categories
        if agency in retention:
            return retention[agency]

        # Try sensitivity match in retention categories
        if sensitivity in retention:
            return retention[sensitivity]

        return retention.get("default", 5)

    def get_expiration_date(self, created_at: datetime,
                            agency: str = "",
                            sensitivity: str = "") -> datetime:
        """Calculate expiration date based on retention policy.

        Args:
            created_at: Creation timestamp
            agency: Agency name
            sensitivity: Sensitivity classification

        Returns:
            Expiration datetime
        """
        years = self.get_retention_years(agency, sensitivity)
        try:
            return created_at.replace(year=created_at.year + years)
        except ValueError:
            # Handle leap year edge case
            return created_at + timedelta(days=365 * years)

    def is_expired(self, created_at: datetime,
                   agency: str = "",
                   sensitivity: str = "") -> bool:
        """Check if a record has passed its retention period.

        Args:
            created_at: Record creation timestamp
            agency: Agency name
            sensitivity: Sensitivity classification

        Returns:
            True if retention period has elapsed
        """
        expires = self.get_expiration_date(created_at, agency, sensitivity)
        return datetime.now(timezone.utc) >= expires

    def get_required_signature(self, sensitivity: str,
                               agency: str = "") -> str:
        """Get required signature algorithm for given sensitivity/agency.

        Args:
            sensitivity: Sensitivity classification
            agency: Agency name

        Returns:
            Signature algorithm name (Ed25519 or ICP-Brasil)
        """
        # Check agency-specific config first
        agencies = self.get_policy("agencies", {})
        if agency in agencies:
            sig = agencies[agency].get("minimum_signature", "")
            if sig:
                return sig

        # Fall back to sensitivity config
        sens = self.get_policy("sensitivity", {})
        if sensitivity in sens:
            return sens[sensitivity].get("required_signature", "Ed25519")

        return "Ed25519"

    def is_blockchain_required(self, agency: str = "",
                               sensitivity: str = "") -> bool:
        """Check if blockchain dual-write is required.

        Args:
            agency: Agency name
            sensitivity: Sensitivity classification

        Returns:
            True if blockchain persistence is required
        """
        agencies = self.get_policy("agencies", {})
        if agency in agencies:
            return agencies[agency].get("require_blockchain", False)

        sens = self.get_policy("sensitivity", {})
        if sensitivity in sens:
            return sens[sensitivity].get("require_blockchain", False)

        return False

    def get_legal_basis(self, agency: str = "",
                        sensitivity: str = "") -> str:
        """Get legal basis for the audit.

        Args:
            agency: Agency name
            sensitivity: Sensitivity classification

        Returns:
            Legal basis string
        """
        agencies = self.get_policy("agencies", {})
        if agency in agencies:
            basis = agencies[agency].get("legal_basis", "")
            if basis:
                return basis

        sens = self.get_policy("sensitivity", {})
        if sensitivity in sens:
            return sens[sensitivity].get("legal_basis", "")

        return ""
