"""
Tracer-GAP — SEC EDGAR 10-K Loader
===================================
Loads the real SEC EDGAR 10-K filings dataset into FinancialRecords.

Each filing JSON (from the Kaggle dataset
`pranjalverma08/sec-edgar-annual-financial-filings-2021`) contains
structured fields including Risk Factors (item_1A) and MD&A (item_7) —
the natural source for gap identification.

The loader extracts:
  - company (from `company`)
  - CIK (from `cik`)
  - sector (mapped from SIC code)
  - period (from `period_of_report`)
  - risk text (item_1A) and MD&A text (item_7)

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
import json, logging, os, glob
from typing import Dict, Any, List, Optional

from winnex_tracer.gap.core.metadata import FinancialMetadata, FinancialRecord

logger = logging.getLogger("tracer-gap.sec")

# SIC range -> broad sector mapping (for gap filtering)
SIC_SECTORS = {
    (6000, 6199): "Finance",
    (6200, 6299): "Securities",
    (6300, 6499): "Insurance",
    (6500, 6999): "Real Estate",
    (2000, 3999): "Manufacturing",
    (1000, 1799): "Mining/Construction",
    (7000, 8999): "Services",
    (4900, 4999): "Utilities",
}


def _sic_to_sector(sic: Any) -> str:
    try:
        sic_int = int(sic)
    except (TypeError, ValueError):
        return ""
    for (lo, hi), sector in SIC_SECTORS.items():
        if lo <= sic_int <= hi:
            return sector
    return ""


class SecLoader:
    """Load SEC 10-K filing JSONs into FinancialRecords."""

    @staticmethod
    def load_dir(directory: str, limit: int = 0) -> List[FinancialRecord]:
        """Load all 10-K filing JSONs from a directory.

        Args:
            directory: path to the `extracted` folder of the Kaggle dataset
            limit: max number of filings to load (0 = all)
        """
        files = sorted(glob.glob(os.path.join(directory, "*.json")))
        if limit > 0:
            files = files[:limit]
        records = []
        for f in files:
            rec = SecLoader.load_file(f)
            if rec is not None:
                records.append(rec)
        logger.info("SecLoader: loaded %d filings from %s", len(records), directory)
        return records

    @staticmethod
    def load_file(path: str) -> Optional[FinancialRecord]:
        """Load a single 10-K filing JSON as a FinancialRecord.

        Returns the Risk Factors (item_1A) as the primary text, or the MD&A
        (item_7) if risk factors are absent.
        """
        try:
            with open(path) as f:
                d = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("SecLoader: skip %s (%s)", path, e)
            return None

        risk_text = (d.get("item_1A") or "").strip()
        mda_text = (d.get("item_7") or "").strip()
        text = risk_text or mda_text
        if not text:
            return None

        metadata = FinancialMetadata(
            sector=_sic_to_sector(d.get("sic")),
            instrument_type="10-K",
            cik=str(d.get("cik", "")),
            company=str(d.get("company", "")),
            period=str(d.get("period_of_report", "")),
            filing_date=str(d.get("filing_date", "")),
            risk_category="risk_factors" if risk_text else "mda",
            purpose="gap_identification",
        )

        return FinancialRecord(
            text=text[:8000],       # bound text length for embedding
            metadata=metadata,
            external_id=str(d.get("filename", "")),
        )
