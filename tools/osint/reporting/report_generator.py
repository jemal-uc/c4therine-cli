#!/usr/bin/env python3
"""
report_generator.py — Report Generation Coordinator for Catherine OSINT
=======================================================================
Coordinator module yang mengorkestrasi semua export modules:
- export_csv.py
- export_html.py
- export_json.py
- maltego_export.py (dari graph/)
- narrative_report.py (dari graph/)

Menyediakan unified interface untuk generate reports dalam
berbagai format dari intelligence product.

Author: Catherine Team
Version: 4.0.0
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger("Catherine.Reporting")


class ReportFormat(Enum):
    """Supported report formats."""
    MARKDOWN = "markdown"
    HTML = "html"
    JSON = "json"
    CSV = "csv"
    PDF = "pdf"
    MALTEGO = "maltego"
    STIX = "stix"
    MISP = "misp"


class ReportType(Enum):
    """Types of reports."""
    FULL_INTELLIGENCE = auto()
    EXECUTIVE_SUMMARY = auto()
    TECHNICAL_DETAILS = auto()
    ENTITY_PROFILES = auto()
    TIMELINE_ANALYSIS = auto()
    ANOMALY_REPORT = auto()
    HYPOTHESIS_BRIEF = auto()
    CUSTOM = auto()


@dataclass
class ReportRequest:
    """Request untuk generate report."""
    product: Dict[str, Any]
    report_type: ReportType = ReportType.FULL_INTELLIGENCE
    formats: List[ReportFormat] = field(default_factory=lambda: [ReportFormat.MARKDOWN])
    output_dir: Union[str, Path] = "./reports"
    filename_prefix: str = "catherine_report"
    include_raw_data: bool = False
    classification: str = "UNCLASSIFIED"
    custom_metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_type": self.report_type.name,
            "formats": [f.value for f in self.formats],
            "output_dir": str(self.output_dir),
            "filename_prefix": self.filename_prefix,
            "classification": self.classification,
        }


@dataclass
class ReportResult:
    """Hasil report generation."""
    request: ReportRequest
    success: bool
    generated_files: Dict[ReportFormat, Path] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    generation_time_ms: float = 0.0
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "generated_files": {k.value: str(v) for k, v in self.generated_files.items()},
            "errors": self.errors,
            "warnings": self.warnings,
            "generation_time_ms": self.generation_time_ms,
            "timestamp": self.timestamp.isoformat(),
        }


class ReportGenerator:
    """
    Report Generation Coordinator untuk Catherine OSINT.

    Unified interface untuk generate reports dalam berbagai format.
    Mengorkestrasi sub-modules:
    - export_csv.py untuk CSV output
    - export_html.py untuk HTML reports
    - export_json.py untuk JSON/STIX/MISP
    - narrative_report.py untuk narrative reports
    - maltego_export.py untuk Maltego export

    Usage:
        generator = ReportGenerator()
        request = ReportRequest(
            product=intelligence_product,
            formats=[ReportFormat.MARKDOWN, ReportFormat.HTML, ReportFormat.JSON],
        )
        result = generator.generate(request)
    """

    def __init__(self):
        self._exporters: Dict[ReportFormat, Any] = {}
        self._initialize_exporters()
        logger.info("ReportGenerator initialized")

    def _initialize_exporters(self) -> None:
        """Initialize semua available exporters."""
        # Lazy import untuk avoid circular dependencies
        try:
            from .export_csv import CSVExporter
            self._exporters[ReportFormat.CSV] = CSVExporter()
            logger.debug("CSVExporter loaded")
        except ImportError as e:
            logger.warning(f"CSVExporter not available: {e}")

        try:
            from .export_html import HTMLExporter
            self._exporters[ReportFormat.HTML] = HTMLExporter()
            logger.debug("HTMLExporter loaded")
        except ImportError as e:
            logger.warning(f"HTMLExporter not available: {e}")

        try:
            from .export_json import JSONExporter, JSONSchema
            self._exporters[ReportFormat.JSON] = JSONExporter()
            self._exporters[ReportFormat.STIX] = JSONExporter(
                config=JSONExporter.__dataclass_fields__["config"].type(schema=JSONSchema.STIX_2_1)
            )
            self._exporters[ReportFormat.MISP] = JSONExporter(
                config=JSONExporter.__dataclass_fields__["config"].type(schema=JSONSchema.MISP)
            )
            logger.debug("JSONExporter loaded")
        except ImportError as e:
            logger.warning(f"JSONExporter not available: {e}")

        try:
            from ..graph.maltego_export import MaltegoExporter
            self._exporters[ReportFormat.MALTEGO] = MaltegoExporter()
            logger.debug("MaltegoExporter loaded")
        except ImportError as e:
            logger.warning(f"MaltegoExporter not available: {e}")

        try:
            from ..graph.narrative_report import NarrativeReportGenerator
            self._exporters[ReportFormat.MARKDOWN] = NarrativeReportGenerator()
            logger.debug("NarrativeReportGenerator loaded")
        except ImportError as e:
            logger.warning(f"NarrativeReportGenerator not available: {e}")

    def generate(self, request: ReportRequest) -> ReportResult:
        """
        Generate report(s) sesuai request.

        Args:
            request: ReportRequest dengan konfigurasi

        Returns:
            ReportResult dengan generated files atau errors
        """
        import time
        start_time = time.time()

        result = ReportResult(request=request, success=True)
        output_dir = Path(request.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        prefix = request.filename_prefix

        # Prepare data sesuai report type
        prepared_data = self._prepare_data(request)

        # Generate untuk setiap requested format
        for fmt in request.formats:
            if fmt not in self._exporters:
                result.warnings.append(f"Format {fmt.value} not available")
                continue

            try:
                file_path = self._generate_format(
                    fmt=fmt,
                    data=prepared_data,
                    output_dir=output_dir,
                    prefix=prefix,
                    timestamp=timestamp,
                    request=request,
                )

                if file_path:
                    result.generated_files[fmt] = file_path
                    logger.info(f"Generated {fmt.value}: {file_path}")

            except Exception as e:
                result.errors.append(f"Failed to generate {fmt.value}: {str(e)}")
                logger.error(f"Error generating {fmt.value}: {e}")

        # Determine overall success
        result.success = len(result.generated_files) > 0 and len(result.errors) == 0
        result.generation_time_ms = (time.time() - start_time) * 1000

        if result.success:
            logger.info(f"Report generation complete: {len(result.generated_files)} formats")
        else:
            logger.warning(f"Report generation partial: {len(result.generated_files)} success, {len(result.errors)} errors")

        return result

    def _prepare_data(self, request: ReportRequest) -> Dict[str, Any]:
        """Prepare data sesuai report type."""
        product = request.product.copy()

        # Add metadata
        product["_report_metadata"] = {
            "report_type": request.report_type.name,
            "generated_at": datetime.utcnow().isoformat(),
            "classification": request.classification,
            **request.custom_metadata,
        }

        # Filter data sesuai report type
        if request.report_type == ReportType.EXECUTIVE_SUMMARY:
            # Hanya include high-level summary
            product = self._filter_executive_summary(product)

        elif request.report_type == ReportType.ENTITY_PROFILES:
            # Focus pada entities
            product = {k: v for k, v in product.items() if k in ["entities", "case_id", "title"]}

        elif request.report_type == ReportType.ANOMALY_REPORT:
            # Focus pada anomalies
            product = {k: v for k, v in product.items() if k in ["anomalies", "entities", "case_id", "title"]}

        elif request.report_type == ReportType.HYPOTHESIS_BRIEF:
            # Focus pada hypotheses
            product = {k: v for k, v in product.items() if k in ["hypotheses", "confidence_scores", "case_id", "title"]}

        # Include raw data jika diminta
        if not request.include_raw_data and "raw_data" in product:
            del product["raw_data"]

        return product

    def _filter_executive_summary(self, product: Dict[str, Any]) -> Dict[str, Any]:
        """Filter product untuk executive summary."""
        return {
            "case_id": product.get("case_id"),
            "title": product.get("title"),
            "classification": product.get("classification"),
            "created_at": product.get("created_at"),
            "entity_count": len(product.get("entities", [])),
            "relationship_count": len(product.get("relationships", [])),
            "anomaly_count": len(product.get("anomalies", [])),
            "hypothesis_count": len(product.get("hypotheses", [])),
            "confidence_scores": product.get("confidence_scores", {}),
            "top_hypotheses": product.get("hypotheses", [])[:3],
            "critical_anomalies": [
                a for a in product.get("anomalies", [])
                if a.get("score", 0) >= 0.8
            ][:5],
        }

    def _generate_format(
        self,
        fmt: ReportFormat,
        data: Dict[str, Any],
        output_dir: Path,
        prefix: str,
        timestamp: str,
        request: ReportRequest,
    ) -> Optional[Path]:
        """Generate file untuk specific format."""
        exporter = self._exporters[fmt]

        if fmt == ReportFormat.MARKDOWN:
            path = output_dir / f"{prefix}_{timestamp}.md"
            # NarrativeReportGenerator.generate_full_report returns report object
            report = exporter.generate_full_report(data)
            md_content = exporter.export_markdown(report) if hasattr(exporter, 'export_markdown') else str(report)
            with open(path, "w", encoding="utf-8") as f:
                f.write(md_content)
            return path

        elif fmt == ReportFormat.HTML:
            path = output_dir / f"{prefix}_{timestamp}.html"
            from .export_html import HTMLExportConfig
            config = HTMLExportConfig(
                title=data.get("title", "Catherine Report"),
                classification_banner=request.classification,
            )
            exporter = HTMLExporter(config=config)
            exporter.export(data, output_path=path)
            return path

        elif fmt == ReportFormat.JSON:
            path = output_dir / f"{prefix}_{timestamp}.json"
            exporter.export(data, output_path=path)
            return path

        elif fmt == ReportFormat.CSV:
            path = output_dir / f"{prefix}_{timestamp}.csv"
            # Export entities sebagai default CSV
            entities = data.get("entities", [])
            if entities:
                exporter.export(entities, output_path=path)
            else:
                # Export full data sebagai single CSV dengan flattening
                from .export_csv import CSVExportMode
                exporter.export([data], mode=CSVExportMode.CUSTOM, output_path=path)
            return path

        elif fmt == ReportFormat.STIX:
            path = output_dir / f"{prefix}_stix_{timestamp}.json"
            exporter.export_stix_bundle(data, output_path=path)
            return path

        elif fmt == ReportFormat.MISP:
            path = output_dir / f"{prefix}_misp_{timestamp}.json"
            exporter.export(data, output_path=path, schema=exporter.config.schema)
            return path

        elif fmt == ReportFormat.MALTEGO:
            path = output_dir / f"{prefix}_{timestamp}.mtgx"
            exporter.export(path)
            return path

        return None

    def get_available_formats(self) -> List[ReportFormat]:
        """Get list of available export formats."""
        return list(self._exporters.keys())

    def get_format_status(self) -> Dict[str, bool]:
        """Get status (available or not) untuk setiap format."""
        return {fmt.value: fmt in self._exporters for fmt in ReportFormat}


# ============================================================================
# Convenience Functions
# ============================================================================

def generate_report(
    product: Dict[str, Any],
    formats: Optional[List[Union[str, ReportFormat]]] = None,
    output_dir: Union[str, Path] = "./reports",
    **kwargs,
) -> ReportResult:
    """
    Quick function untuk generate report.

    Args:
        product: Intelligence product dictionary
        formats: List of format strings atau ReportFormat enums
        output_dir: Output directory
        **kwargs: Additional ReportRequest parameters

    Returns:
        ReportResult
    """
    # Parse formats
    if formats is None:
        format_enums = [ReportFormat.MARKDOWN]
    else:
        format_enums = []
        for f in formats:
            if isinstance(f, str):
                format_enums.append(ReportFormat(f.lower()))
            else:
                format_enums.append(f)

    request = ReportRequest(
        product=product,
        formats=format_enums,
        output_dir=output_dir,
        **kwargs,
    )

    generator = ReportGenerator()
    return generator.generate(request)


def quick_export(
    product: Dict[str, Any],
    fmt: str = "json",
    output_path: Optional[Union[str, Path]] = None,
) -> Union[str, Path]:
    """
    Quick single-format export.

    Args:
        product: Intelligence product
        fmt: Format string (json, html, csv, markdown, stix, misp)
        output_path: Output path (optional)

    Returns:
        File path atau content string
    """
    fmt_enum = ReportFormat(fmt.lower())

    request = ReportRequest(
        product=product,
        formats=[fmt_enum],
        output_dir=Path(output_path).parent if output_path else "./reports",
        filename_prefix=Path(output_path).stem if output_path else "export",
    )

    generator = ReportGenerator()
    result = generator.generate(request)

    if result.success and fmt_enum in result.generated_files:
        return result.generated_files[fmt_enum]

    raise RuntimeError(f"Export failed: {result.errors}")