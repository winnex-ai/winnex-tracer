"""
Tracer-MED — HL7 FHIR Interoperability
=======================================
Speaks HL7 FHIR (Fast Healthcare Interoperability Resources) for
integration with hospital systems (Síntese, MV, Tasy, etc.).

Maps FHIR resources to the internal clinical corpus so legacy systems can
be searched without migration:

  Patient        -> pseudonymized patient ID
  Observation    -> clinical observation (vitals, labs)
  DocumentReference -> clinical document (prontuario, laudo, exame)
  Condition      -> diagnosis (with ICD-10 / CID-10 code)
  Encounter      -> encounter date, department

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
import json, logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from winnex_tracer.med.core.metadata import ClinicalMetadata, ClinicalRecord

logger = logging.getLogger("tracer-med.fhir")


class FhirResourceMapper:
    """Maps FHIR resources to Tracer-MED clinical records.

    This is a reference implementation. For a real deployment it should be
    extended to the FHIR version in use (R4 / US Core / BR Core) and to the
    specific fields of each hospital system.
    """

    # Document types in Portuguese medical vocabulary
    DOCUMENT_TYPES = {
        "DocumentReference": "documento",
        "DiagnosticReport": "laudo",
        "Observation": "exame",
        "Condition": "diagnostico",
        "ClinicalImpression": "avaliacao_clinica",
    }

    @staticmethod
    def _safe(fhir_resource: Dict[str, Any], *keys: str, default: str = "") -> str:
        """Navigate a FHIR resource safely, returning default on missing."""
        node = fhir_resource
        for k in keys:
            if not isinstance(node, dict) or k not in node:
                return default
            node = node[k]
        return node if isinstance(node, (str, int, float)) else str(node)

    @staticmethod
    def _extract_text(fhir_resource: Dict[str, Any]) -> str:
        """Extract human-readable text from a FHIR resource."""
        parts = []
        text = fhir_resource.get("text", {}).get("div", "")
        if text:
            # Strip basic HTML tags
            import re
            text = re.sub(r"<[^>]+>", " ", text)
            parts.append(text.strip())
        for field in ("code", "valueString", "valueCodeableConcept", "display"):
            v = fhir_resource.get(field)
            if isinstance(v, dict):
                parts.append(v.get("text", "") or v.get("display", ""))
            elif v:
                parts.append(str(v))
        # Coding display (e.g. from code: {coding:[{display:...}]})
        coding = fhir_resource.get("code", {}).get("coding", [])
        for c in coding:
            if c.get("display"):
                parts.append(c["display"])
        return " ".join(p for p in parts if p).strip()

    @classmethod
    def map_resource(cls, resource: Dict[str, Any]) -> Optional[ClinicalRecord]:
        """Map a single FHIR resource to a ClinicalRecord.

        Returns None for resource types not yet mapped.
        """
        rtype = resource.get("resourceType", "")
        if rtype not in cls.DOCUMENT_TYPES:
            logger.debug("FHIR resource type %s not mapped", rtype)
            return None

        # Patient pseudonymization: use the patient reference (already an ID)
        patient_ref = cls._safe(resource, "subject", "reference",
                                default=cls._safe(resource, "patient", "reference"))
        if patient_ref:
            patient_id = ClinicalMetadata.pseudonymize(patient_ref)
        else:
            patient_id = ""

        cid10 = ""
        # Condition.code or Observation.code coding system 2.16.840.1.113883.6.3 (ICD-10)
        for code_field in ("code", "diagnosis"):
            coding = resource.get(code_field, {}).get("coding", [])
            for c in coding:
                sys_ = c.get("system", "")
                if "icd" in sys_.lower() or "2.16.840.1.113883.6.3" in sys_:
                    cid10 = c.get("code", "")
                    break
            if cid10:
                break

        metadata = ClinicalMetadata(
            encounter_date=cls._safe(resource, "date", default="")
            or cls._safe(resource, "issued", default=""),
            patient_id=patient_id,
            document_type=cls.DOCUMENT_TYPES.get(rtype, rtype),
            author=cls._safe(resource, "author", "display")
            or cls._safe(resource, "performer", "display"),
            institution=cls._safe(resource, "custodian", "display"),
            cid10=cid10,
            department=cls._safe(resource, "encounter", "display"),
            purpose="fhir_ingestion",
        )

        text = cls._extract_text(resource)
        if not text:
            return None

        return ClinicalRecord(
            text=text,
            metadata=metadata,
            external_id=resource.get("id", ""),
        )

    @staticmethod
    def build_bundle(records: List[ClinicalRecord]) -> Dict[str, Any]:
        """Build a FHIR Bundle from clinical records (for export)."""
        entries = []
        for i, rec in enumerate(records):
            entries.append({
                "fullUrl": f"urn:uuid:{i}",
                "resource": {
                    "resourceType": "DocumentReference",
                    "id": rec.external_id or f"tj-{i}",
                    "content": [{"attachment": {"title": rec.metadata.document_type,
                                                "data": rec.text}}],
                    "context": {
                        "period": {"start": rec.metadata.encounter_date},
                        "encounter": {"display": rec.metadata.department},
                    },
                    "subject": {"reference": f"Patient/{rec.metadata.patient_id}"},
                },
            })
        return {
            "resourceType": "Bundle",
            "type": "collection",
            "total": len(records),
            "entry": entries,
        }
