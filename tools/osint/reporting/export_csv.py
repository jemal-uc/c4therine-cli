#!/usr/bin/env python3
"""
export_csv.py — CSV Export Module for Catherine OSINT Platform
================================================================
Export intelligence data ke format CSV untuk analisis external,
spreadsheet processing, dan sharing dengan tools lain.

Author: Catherine Team
Version: 4.0.0
"""

from __future__ import annotations

import csv
import io
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union, Iterator

logger = logging.getLogger("Catherine.Reporting.CSV")


class CSVExportMode(Enum):
    """Mode export CSV."""
    ENTITIES = "entities"
    RELATIONSHIPS = "relationships"
    TIMELINE = "timeline"
    ANOMALIES = "anomalies"
    HYPOTHESES = "hypotheses"
    FULL = "full"
    CUSTOM = "custom"


@dataclass
class CSVExportConfig:
    """Konfigurasi export CSV."""
    delimiter: str = ","
    quotechar: str = '"'
    encoding: str = "utf-8-sig"  # BOM for Excel compatibility
    include_header: bool = True
    flatten_nested: bool = True
    nested_separator: str = "."
    datetime_format: str = "%Y-%m-%d %H:%M:%S"
    max_nested_depth: int = 3
    custom_headers: Optional[List[str]] = None
    field_mapping: Optional[Dict[str, str]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "delimiter": self.delimiter,
            "quotechar": self.quotechar,
            "encoding": self.encoding,
            "include_header": self.include_header,
            "flatten_nested": self.flatten_nested,
            "nested_separator": self.nested_separator,
            "datetime_format": self.datetime_format,
            "max_nested_depth": self.max_nested_depth,
        }


class CSVExporter:
    """
    CSV Exporter untuk Catherine OSINT Platform.

    Features:
    - Export entities, relationships, timeline, anomalies, hypotheses
    - Flatten nested JSON structures
    - Custom field mapping
    - Streaming export untuk large datasets
    - Excel-compatible output (UTF-8 BOM)
    """

    # Default field schemas per mode
    DEFAULT_SCHEMAS = {
        CSVExportMode.ENTITIES: [
            "id", "type", "name", "label", "confidence", 
            "source", "created_at", "properties"
        ],
        CSVExportMode.RELATIONSHIPS: [
            "id", "source_id", "target_id", "type", 
            "confidence", "direction", "properties"
        ],
        CSVExportMode.TIMELINE: [
            "timestamp", "event_type", "entity_id", "description", "source"
        ],
        CSVExportMode.ANOMALIES: [
            "id", "anomaly_type", "score", "description", 
            "entities_involved", "detected_at"
        ],
        CSVExportMode.HYPOTHESES: [
            "id", "title", "priority", "confidence", 
            "description", "evidence_count", "generated_at"
        ],
    }

    def __init__(self, config: Optional[CSVExportConfig] = None):
        self.config = config or CSVExportConfig()
        logger.info("CSVExporter initialized")

    def export(
        self,
        data: List[Dict[str, Any]],
        mode: CSVExportMode = CSVExportMode.CUSTOM,
        output_path: Optional[Union[str, Path]] = None,
        custom_fields: Optional[List[str]] = None,
    ) -> Union[str, Path]:
        """
        Export data ke CSV.

        Args:
            data: List of dictionaries
            mode: Export mode
            output_path: Output file path (optional, returns string if None)
            custom_fields: Custom field list (overrides schema)

        Returns:
            File path jika output_path diberikan, else CSV string
        """
        if not data:
            logger.warning("Empty data provided for CSV export")
            return "" if output_path is None else output_path

        # Determine fields
        fields = custom_fields or self._get_fields(data, mode)

        # Flatten data
        flattened = [self._flatten_record(record) for record in data]

        # Build CSV
        output = io.StringIO()
        writer = csv.DictWriter(
            output,
            fieldnames=fields,
            delimiter=self.config.delimiter,
            quotechar=self.config.quotechar,
            extrasaction="ignore",
        )

        if self.config.include_header:
            writer.writeheader()

        for record in flattened:
            # Apply field mapping if configured
            if self.config.field_mapping:
                record = self._apply_field_mapping(record)

            # Format values
            formatted = self._format_values(record, fields)
            writer.writerow(formatted)

        csv_content = output.getvalue()

        if output_path:
            path = Path(output_path)
            path.parent.mkdir(parents=True, exist_ok=True)

            # Write with BOM for Excel compatibility
            with open(path, "w", encoding=self.config.encoding, newline="") as f:
                f.write(csv_content)

            logger.info(f"CSV exported to {path}")
            return path

        return csv_content

    def export_streaming(
        self,
        data_iterator: Iterator[Dict[str, Any]],
        mode: CSVExportMode = CSVExportMode.CUSTOM,
        output_path: Union[str, Path] = "output.csv",
        custom_fields: Optional[List[str]] = None,
    ) -> Path:
        """
        Streaming export untuk large datasets (memory efficient).

        Args:
            data_iterator: Iterator of dictionaries
            mode: Export mode
            output_path: Output file path
            custom_fields: Custom field list

        Returns:
            Output file path
        """
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        # First pass: determine fields from first record
        first_record = next(data_iterator, None)
        if first_record is None:
            logger.warning("Empty iterator for streaming export")
            return path

        fields = custom_fields or self._get_fields([first_record], mode)

        with open(path, "w", encoding=self.config.encoding, newline="") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=fields,
                delimiter=self.config.delimiter,
                quotechar=self.config.quotechar,
                extrasaction="ignore",
            )

            if self.config.include_header:
                writer.writeheader()

            # Write first record
            flattened = self._flatten_record(first_record)
            formatted = self._format_values(flattened, fields)
            writer.writerow(formatted)

            # Write remaining records
            record_count = 1
            for record in data_iterator:
                flattened = self._flatten_record(record)
                formatted = self._format_values(flattened, fields)
                writer.writerow(formatted)
                record_count += 1

                if record_count % 1000 == 0:
                    logger.debug(f"Exported {record_count} records...")

        logger.info(f"Streaming CSV export complete: {record_count} records to {path}")
        return path

    def export_intelligence_product(
        self,
        product: Dict[str, Any],
        output_dir: Union[str, Path],
        prefix: str = "catherine",
    ) -> Dict[str, Path]:
        """
        Export complete intelligence product ke multiple CSV files.

        Args:
            product: Intelligence product dictionary
            output_dir: Output directory
            prefix: File prefix

        Returns:
            Dictionary mapping mode -> file path
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        exports = {}
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

        # Export entities
        if "entities" in product and product["entities"]:
            path = output_dir / f"{prefix}_entities_{timestamp}.csv"
            self.export(product["entities"], CSVExportMode.ENTITIES, path)
            exports["entities"] = path

        # Export relationships
        if "relationships" in product and product["relationships"]:
            path = output_dir / f"{prefix}_relationships_{timestamp}.csv"
            self.export(product["relationships"], CSVExportMode.RELATIONSHIPS, path)
            exports["relationships"] = path

        # Export timeline
        if "timeline" in product and product["timeline"]:
            path = output_dir / f"{prefix}_timeline_{timestamp}.csv"
            self.export(product["timeline"], CSVExportMode.TIMELINE, path)
            exports["timeline"] = path

        # Export anomalies
        if "anomalies" in product and product["anomalies"]:
            path = output_dir / f"{prefix}_anomalies_{timestamp}.csv"
            self.export(product["anomalies"], CSVExportMode.ANOMALIES, path)
            exports["anomalies"] = path

        # Export hypotheses
        if "hypotheses" in product and product["hypotheses"]:
            path = output_dir / f"{prefix}_hypotheses_{timestamp}.csv"
            self.export(product["hypotheses"], CSVExportMode.HYPOTHESES, path)
            exports["hypotheses"] = path

        logger.info(f"Intelligence product exported to {len(exports)} CSV files")
        return exports

    def _get_fields(
        self,
        data: List[Dict[str, Any]],
        mode: CSVExportMode,
    ) -> List[str]:
        """Determine fields dari data dan mode."""
        if mode in self.DEFAULT_SCHEMAS:
            return self.DEFAULT_SCHEMAS[mode]

        # Auto-detect dari data
        if data:
            first = self._flatten_record(data[0])
            return list(first.keys())

        return []

    def _flatten_record(
        self,
        record: Dict[str, Any],
        parent_key: str = "",
        depth: int = 0,
    ) -> Dict[str, Any]:
        """Flatten nested dictionary."""
        if not self.config.flatten_nested or depth >= self.config.max_nested_depth:
            return {parent_key: str(record)} if parent_key else record

        items = {}
        for key, value in record.items():
            new_key = f"{parent_key}{self.config.nested_separator}{key}" if parent_key else key

            if isinstance(value, dict):
                items.update(self._flatten_record(value, new_key, depth + 1))
            elif isinstance(value, list):
                if value and isinstance(value[0], dict):
                    # List of dicts -> JSON string
                    items[new_key] = str(value)
                else:
                    # Simple list -> comma-separated
                    items[new_key] = ", ".join(str(v) for v in value)
            else:
                items[new_key] = value

        return items

    def _format_values(
        self,
        record: Dict[str, Any],
        fields: List[str],
    ) -> Dict[str, Any]:
        """Format values untuk CSV output."""
        formatted = {}
        for field in fields:
            value = record.get(field, "")

            if isinstance(value, datetime):
                value = value.strftime(self.config.datetime_format)
            elif isinstance(value, (list, dict)):
                value = str(value)
            elif value is None:
                value = ""

            formatted[field] = value

        return formatted

    def _apply_field_mapping(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Apply custom field mapping."""
        mapped = {}
        for old_key, new_key in self.config.field_mapping.items():
            if old_key in record:
                mapped[new_key] = record[old_key]
        # Keep unmapped fields
        for key, value in record.items():
            if key not in self.config.field_mapping:
                mapped[key] = value
        return mapped


# ============================================================================
# Convenience Functions
# ============================================================================

def export_to_csv(
    data: List[Dict[str, Any]],
    output_path: Union[str, Path],
    **kwargs,
) -> Path:
    """Quick export ke CSV."""
    exporter = CSVExporter()
    return exporter.export(data, output_path=output_path, **kwargs)


def export_entities_to_csv(
    entities: List[Dict[str, Any]],
    output_path: Union[str, Path],
) -> Path:
    """Quick export entities ke CSV."""
    exporter = CSVExporter()
    return exporter.export(entities, CSVExportMode.ENTITIES, output_path)


def export_relationships_to_csv(
    relationships: List[Dict[str, Any]],
    output_path: Union[str, Path],
) -> Path:
    """Quick export relationships ke CSV."""
    exporter = CSVExporter()
    return exporter.export(relationships, CSVExportMode.RELATIONSHIPS, output_path)