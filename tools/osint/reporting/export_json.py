#!/usr/bin/env python3
"""
export_json.py — JSON Export Module for Catherine OSINT Platform
===================================================================
Export intelligence data ke format JSON dengan schema standard,
pretty printing, dan support untuk multiple JSON standards
(STIX 2.1, OpenIOC, MISP, custom Catherine schema).

Author: Catherine Team
Version: 4.0.0
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger("Catherine.Reporting.JSON")


class JSONSchema(Enum):
    """Supported JSON output schemas."""
    CATHERINE = "catherine"           # Native Catherine schema
    STIX_2_1 = "stix_2_1"             # STIX 2.1 (threat intelligence standard)
    OPENIOC = "openioc"               # OpenIOC format
    MISP = "misp"                     # MISP event format
    RAW = "raw"                       # Raw unmodified data
    PRETTY = "pretty"                 # Pretty-printed native


@dataclass
class JSONExportConfig:
    """Konfigurasi export JSON."""
    schema: JSONSchema = JSONSchema.CATHERINE
    indent: int = 2
    sort_keys: bool = True
    ensure_ascii: bool = False
    include_metadata: bool = True
    include_nulls: bool = False
    datetime_format: str = "iso"  # "iso", "unix", "string"
    compression: Optional[str] = None  # None, "gzip", "bz2"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema.value,
            "indent": self.indent,
            "sort_keys": self.sort_keys,
            "ensure_ascii": self.ensure_ascii,
            "include_metadata": self.include_metadata,
        }


class JSONExporter:
    """
    JSON Exporter untuk Catherine OSINT Platform.

    Features:
    - Multiple schema support (Catherine native, STIX 2.1, MISP, OpenIOC)
    - Pretty printing dengan custom indent
    - Metadata injection
    - Compression support (gzip, bz2)
    - Streaming export untuk large datasets
    - Schema validation hints
    """

    def __init__(self, config: Optional[JSONExportConfig] = None):
        self.config = config or JSONExportConfig()
        logger.info(f"JSONExporter initialized with schema: {self.config.schema.value}")

    def export(
        self,
        data: Any,
        output_path: Optional[Union[str, Path]] = None,
        schema: Optional[JSONSchema] = None,
    ) -> Union[str, Path]:
        """
        Export data ke JSON.

        Args:
            data: Data untuk di-export (dict, list, atau object)
            output_path: Output file path (optional)
            schema: Override schema (optional)

        Returns:
            File path atau JSON string
        """
        schema = schema or self.config.schema

        # Transform data sesuai schema
        transformed = self._transform_data(data, schema)

        # Add metadata
        if self.config.include_metadata:
            transformed = self._add_metadata(transformed, schema)

        # Serialize
        json_str = json.dumps(
            transformed,
            indent=self.config.indent,
            sort_keys=self.config.sort_keys,
            ensure_ascii=self.config.ensure_ascii,
            default=self._json_serializer,
        )

        if output_path:
            path = Path(output_path)
            path.parent.mkdir(parents=True, exist_ok=True)

            if self.config.compression == "gzip":
                import gzip
                with gzip.open(path, "wt", encoding="utf-8") as f:
                    f.write(json_str)
            elif self.config.compression == "bz2":
                import bz2
                with bz2.open(path, "wt", encoding="utf-8") as f:
                    f.write(json_str)
            else:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(json_str)

            logger.info(f"JSON exported to {path} (schema: {schema.value})")
            return path

        return json_str

    def export_intelligence_product(
        self,
        product: Dict[str, Any],
        output_path: Union[str, Path],
        schema: JSONSchema = JSONSchema.CATHERINE,
    ) -> Path:
        """
        Export complete intelligence product ke JSON.

        Args:
            product: Intelligence product dictionary
            output_path: Output file path
            schema: JSON schema

        Returns:
            Output file path
        """
        return self.export(product, output_path=output_path, schema=schema)

    def export_entities(
        self,
        entities: List[Dict[str, Any]],
        output_path: Union[str, Path],
    ) -> Path:
        """Export entities ke JSON."""
        return self.export({"entities": entities}, output_path=output_path)

    def export_stix_bundle(
        self,
        data: Dict[str, Any],
        output_path: Union[str, Path],
    ) -> Path:
        """
        Export ke STIX 2.1 Bundle format.

        STIX 2.1 adalah standard untuk threat intelligence sharing.
        Reference: https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html
        """
        stix_bundle = self._to_stix_bundle(data)
        return self.export(stix_bundle, output_path=output_path, schema=JSONSchema.STIX_2_1)

    def _transform_data(self, data: Any, schema: JSONSchema) -> Any:
        """Transform data sesuai schema."""
        if schema == JSONSchema.RAW:
            return data

        if schema == JSONSchema.CATHERINE:
            return self._to_catherine_schema(data)

        if schema == JSONSchema.STIX_2_1:
            return self._to_stix_bundle(data)

        if schema == JSONSchema.MISP:
            return self._to_misp_event(data)

        if schema == JSONSchema.OPENIOC:
            return self._to_openioc(data)

        return data

    def _to_catherine_schema(self, data: Any) -> Dict[str, Any]:
        """Convert ke Catherine native schema."""
        if isinstance(data, dict) and "product_id" in data:
            # Already in Catherine format
            return data

        # Wrap raw data
        return {
            "catherine_version": "4.0.0",
            "schema_version": "1.0",
            "export_timestamp": datetime.utcnow().isoformat(),
            "data": data,
        }

    def _to_stix_bundle(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert Catherine data ke STIX 2.1 Bundle.

        STIX Objects yang di-generate:
        - identity: untuk entities (person, organization, etc.)
        - indicator: untuk anomalies dan findings
        - observed-data: untuk raw observations
        - relationship: untuk connections
        - threat-actor: untuk suspicious entities
        - report: untuk intelligence product
        """
        bundle_id = f"bundle--{self._generate_uuid()}"
        objects = []

        # Add identity objects dari entities
        for entity in data.get("entities", []):
            stix_identity = {
                "type": "identity",
                "spec_version": "2.1",
                "id": f"identity--{entity.get('id', self._generate_uuid())}",
                "name": entity.get("name", entity.get("label", "Unknown")),
                "identity_class": self._map_entity_type_to_identity_class(
                    entity.get("type", "unknown")
                ),
                "created": entity.get("created_at", datetime.utcnow().isoformat()),
                "modified": entity.get("updated_at", datetime.utcnow().isoformat()),
                "description": entity.get("description", ""),
            }

            # Add custom properties
            if "properties" in entity:
                stix_identity["x_catherine_properties"] = entity["properties"]
            if "confidence" in entity:
                stix_identity["x_catherine_confidence"] = entity["confidence"]

            objects.append(stix_identity)

        # Add indicator objects dari anomalies
        for anomaly in data.get("anomalies", []):
            indicator = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{anomaly.get('id', self._generate_uuid())}",
                "created": anomaly.get("detected_at", datetime.utcnow().isoformat()),
                "modified": anomaly.get("detected_at", datetime.utcnow().isoformat()),
                "name": f"Anomaly: {anomaly.get('anomaly_type', 'Unknown')}",
                "description": anomaly.get("description", ""),
                "indicator_types": ["anomalous-activity"],
                "pattern": f"[x_catherine:anomaly_type = '{anomaly.get('anomaly_type', '')}']",
                "pattern_type": "stix",
                "valid_from": datetime.utcnow().isoformat(),
                "x_catherine_score": anomaly.get("score", 0),
            }
            objects.append(indicator)

        # Add relationship objects
        for rel in data.get("relationships", []):
            relationship = {
                "type": "relationship",
                "spec_version": "2.1",
                "id": f"relationship--{rel.get('id', self._generate_uuid())}",
                "relationship_type": rel.get("type", "related-to"),
                "source_ref": f"identity--{rel.get('source_id', '')}",
                "target_ref": f"identity--{rel.get('target_id', '')}",
                "created": datetime.utcnow().isoformat(),
                "modified": datetime.utcnow().isoformat(),
                "x_catherine_confidence": rel.get("confidence", 0),
            }
            objects.append(relationship)

        # Add report object untuk intelligence product
        report = {
            "type": "report",
            "spec_version": "2.1",
            "id": f"report--{data.get('product_id', self._generate_uuid())}",
            "created": data.get("created_at", datetime.utcnow().isoformat()),
            "modified": data.get("completed_at", datetime.utcnow().isoformat()),
            "name": data.get("title", "Catherine Intelligence Report"),
            "description": f"Intelligence product for case {data.get('case_id', 'unknown')}",
            "report_types": ["threat-report", "intelligence-report"],
            "published": datetime.utcnow().isoformat(),
            "object_refs": [obj["id"] for obj in objects],
        }
        objects.append(report)

        return {
            "type": "bundle",
            "id": bundle_id,
            "spec_version": "2.1",
            "objects": objects,
        }

    def _to_misp_event(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert ke MISP Event format.

        MISP (Malware Information Sharing Platform) adalah standard
        untuk sharing threat intelligence.
        """
        event = {
            "Event": {
                "info": data.get("title", "Catherine Intelligence Export"),
                "threat_level_id": "3",  # Low by default
                "analysis": "2",  # Completed
                "distribution": "3",  # All communities
                "timestamp": int(datetime.utcnow().timestamp()),
                "date": datetime.utcnow().strftime("%Y-%m-%d"),
                "Attribute": [],
                "Object": [],
                "Tag": [
                    {"name": "catherine:osint"},
                    {"name": f"catherine:case-{data.get('case_id', 'unknown')}"},
                ],
            }
        }

        # Add entities sebagai MISP Attributes
        for entity in data.get("entities", []):
            attr = {
                "type": self._map_entity_to_misp_type(entity.get("type", "unknown")),
                "category": "External analysis",
                "to_ids": False,
                "value": entity.get("name", entity.get("label", "unknown")),
                "comment": f"Entity ID: {entity.get('id', '')}",
                "Tag": [{"name": f"entity-type:{entity.get('type', 'unknown')}"}],
            }
            event["Event"]["Attribute"].append(attr)

        # Add anomalies sebagai indicators
        for anomaly in data.get("anomalies", []):
            attr = {
                "type": "text",
                "category": "Artifacts dropped",
                "to_ids": True,
                "value": anomaly.get("description", ""),
                "comment": f"Anomaly: {anomaly.get('anomaly_type', '')} (Score: {anomaly.get('score', 0)})",
                "Tag": [{"name": "anomaly:detected"}],
            }
            event["Event"]["Attribute"].append(attr)

        return event

    def _to_openioc(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert ke OpenIOC format.

        OpenIOC adalah format open standard untuk sharing threat
        intelligence indicators.
        """
        ioc = {
            "ioc": {
                "@id": self._generate_uuid(),
                "@last-modified": datetime.utcnow().isoformat(),
                "short_description": data.get("title", "Catherine IOC Export"),
                "description": f"Intelligence product for case {data.get('case_id', '')}",
                "authored_by": "Catherine OSINT Platform",
                "authored_date": datetime.utcnow().isoformat(),
                "links": [],
                "definition": {
                    "Indicator": {
                        "@operator": "OR",
                        "IndicatorItem": [],
                    }
                },
            }
        }

        # Add entities sebagai IndicatorItems
        for entity in data.get("entities", []):
            item = {
                "@id": self._generate_uuid(),
                "@condition": "contains",
                "Context": {
                    "@document": entity.get("type", "Unknown"),
                    "@search": entity.get("type", "Unknown"),
                    "@type": "mir",
                },
                "Content": {
                    "@type": "string",
                    "#text": entity.get("name", entity.get("label", "")),
                },
            }
            ioc["ioc"]["definition"]["Indicator"]["IndicatorItem"].append(item)

        return ioc

    def _add_metadata(self, data: Any, schema: JSONSchema) -> Dict[str, Any]:
        """Add export metadata."""
        if isinstance(data, dict) and schema != JSONSchema.STIX_2_1:
            # Don't add metadata ke STIX (sudah strict schema)
            metadata = {
                "_export_metadata": {
                    "tool": "Catherine OSINT Platform",
                    "version": "4.0.0",
                    "schema": schema.value,
                    "exported_at": datetime.utcnow().isoformat(),
                    "exporter": "export_json.py",
                }
            }
            # Merge tanpa overwrite existing keys
            return {**metadata, **data}
        return data

    def _json_serializer(self, obj: Any) -> Any:
        """Custom JSON serializer untuk types yang tidak serializable."""
        if isinstance(obj, datetime):
            if self.config.datetime_format == "iso":
                return obj.isoformat()
            elif self.config.datetime_format == "unix":
                return int(obj.timestamp())
            else:
                return obj.strftime(self.config.datetime_format)

        if hasattr(obj, "to_dict"):
            return obj.to_dict()

        if hasattr(obj, "__dict__"):
            return obj.__dict__

        raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")

    def _generate_uuid(self) -> str:
        """Generate UUID untuk STIX objects."""
        import uuid
        return str(uuid.uuid4())

    def _map_entity_type_to_identity_class(self, entity_type: str) -> str:
        """Map Catherine entity type ke STIX identity class."""
        mapping = {
            "person": "individual",
            "organization": "organization",
            "company": "organization",
            "group": "group",
            "location": "class",
            "ip": "class",
            "domain": "class",
            "email": "individual",
        }
        return mapping.get(entity_type.lower(), "unknown")

    def _map_entity_to_misp_type(self, entity_type: str) -> str:
        """Map Catherine entity type ke MISP attribute type."""
        mapping = {
            "ip": "ip-dst",
            "ipv4": "ip-dst",
            "ipv6": "ip-dst",
            "domain": "domain",
            "email": "email-src",
            "url": "url",
            "hash": "sha256",
            "file": "filename",
            "person": "text",
            "organization": "text",
            "username": "text",
        }
        return mapping.get(entity_type.lower(), "text")


# ============================================================================
# Convenience Functions
# ============================================================================

def export_to_json(
    data: Any,
    output_path: Union[str, Path],
    **kwargs,
) -> Path:
    """Quick export ke JSON."""
    exporter = JSONExporter(config=JSONExportConfig(**kwargs))
    return exporter.export(data, output_path=output_path)


def export_to_stix(
    data: Dict[str, Any],
    output_path: Union[str, Path],
) -> Path:
    """Quick export ke STIX 2.1."""
    exporter = JSONExporter(config=JSONExportConfig(schema=JSONSchema.STIX_2_1))
    return exporter.export(data, output_path=output_path, schema=JSONSchema.STIX_2_1)


def export_to_misp(
    data: Dict[str, Any],
    output_path: Union[str, Path],
) -> Path:
    """Quick export ke MISP format."""
    exporter = JSONExporter(config=JSONExportConfig(schema=JSONSchema.MISP))
    return exporter.export(data, output_path=output_path, schema=JSONSchema.MISP)