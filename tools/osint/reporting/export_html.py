#!/usr/bin/env python3
"""
export_html.py — HTML Export Module for Catherine OSINT Platform
===================================================================
Export intelligence data ke format HTML dengan styling profesional,
dark theme, interactive tables, dan responsive design.

Author: Catherine Team
Version: 4.0.0
"""

from __future__ import annotations

import html
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger("Catherine.Reporting.HTML")


class HTMLTheme(Enum):
    """Available HTML themes."""
    DARK = "dark"
    LIGHT = "light"
    MINIMAL = "minimal"
    INTELLIGENCE = "intelligence"  # OSINT-specific styling


@dataclass
class HTMLExportConfig:
    """Konfigurasi export HTML."""
    theme: HTMLTheme = HTMLTheme.INTELLIGENCE
    title: str = "Catherine Intelligence Report"
    include_css: bool = True
    include_js: bool = True
    include_timeline: bool = True
    include_graph_viz: bool = False
    include_search: bool = True
    page_size: str = "A4"
    responsive: bool = True
    custom_css: Optional[str] = None
    custom_header: Optional[str] = None
    custom_footer: Optional[str] = None
    classification_banner: Optional[str] = None  # e.g., "UNCLASSIFIED"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "theme": self.theme.value,
            "title": self.title,
            "include_css": self.include_css,
            "include_js": self.include_js,
            "include_timeline": self.include_timeline,
            "include_graph_viz": self.include_graph_viz,
            "classification_banner": self.classification_banner,
        }


class HTMLExporter:
    """
    HTML Exporter untuk Catherine OSINT Platform.

    Features:
    - Professional dark theme (OSINT-style)
    - Interactive sortable tables
    - Classification banners
    - Responsive design
    - Timeline visualization
    - Entity cards
    - Export ke single self-contained HTML file
    """

    # CSS Templates
    CSS_DARK = """
    :root {
        --bg-primary: #0d1117;
        --bg-secondary: #161b22;
        --bg-tertiary: #21262d;
        --text-primary: #c9d1d9;
        --text-secondary: #8b949e;
        --accent: #58a6ff;
        --accent-hover: #79b8ff;
        --border: #30363d;
        --success: #238636;
        --warning: #d29922;
        --danger: #da3633;
        --info: #1f6feb;
    }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
        background: var(--bg-primary);
        color: var(--text-primary);
        line-height: 1.6;
        padding: 0;
    }
    .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
    .classification-banner {
        background: var(--warning);
        color: #000;
        text-align: center;
        padding: 8px;
        font-weight: bold;
        font-size: 14px;
        letter-spacing: 2px;
        text-transform: uppercase;
    }
    header {
        background: var(--bg-secondary);
        border-bottom: 1px solid var(--border);
        padding: 30px 20px;
        margin-bottom: 30px;
    }
    h1 { font-size: 2em; color: var(--accent); margin-bottom: 10px; }
    h2 { font-size: 1.5em; color: var(--text-primary); margin: 30px 0 15px; padding-bottom: 10px; border-bottom: 1px solid var(--border); }
    h3 { font-size: 1.2em; color: var(--text-secondary); margin: 20px 0 10px; }
    .meta { color: var(--text-secondary); font-size: 0.9em; }
    .meta span { margin-right: 20px; }
    .badge {
        display: inline-block;
        padding: 4px 12px;
        border-radius: 12px;
        font-size: 0.75em;
        font-weight: 600;
        text-transform: uppercase;
    }
    .badge-critical { background: var(--danger); color: #fff; }
    .badge-high { background: #da3633; color: #fff; }
    .badge-medium { background: var(--warning); color: #000; }
    .badge-low { background: var(--success); color: #fff; }
    .badge-info { background: var(--info); color: #fff; }
    table {
        width: 100%;
        border-collapse: collapse;
        margin: 20px 0;
        background: var(--bg-secondary);
        border-radius: 8px;
        overflow: hidden;
    }
    th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid var(--border); }
    th {
        background: var(--bg-tertiary);
        color: var(--text-primary);
        font-weight: 600;
        text-transform: uppercase;
        font-size: 0.8em;
        letter-spacing: 0.5px;
        cursor: pointer;
        user-select: none;
    }
    th:hover { background: #30363d; }
    tr:hover { background: rgba(88, 166, 255, 0.05); }
    .entity-card {
        background: var(--bg-secondary);
        border: 1px solid var(--border);
        border-radius: 8px;
        padding: 20px;
        margin: 15px 0;
        transition: border-color 0.2s;
    }
    .entity-card:hover { border-color: var(--accent); }
    .entity-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }
    .entity-title { font-size: 1.3em; color: var(--accent); }
    .entity-type { font-size: 0.8em; color: var(--text-secondary); text-transform: uppercase; }
    .properties { display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 10px; margin-top: 15px; }
    .property { background: var(--bg-tertiary); padding: 10px; border-radius: 6px; }
    .property-key { font-size: 0.75em; color: var(--text-secondary); text-transform: uppercase; }
    .property-value { font-size: 0.95em; color: var(--text-primary); word-break: break-word; }
    .timeline { position: relative; padding-left: 30px; }
    .timeline::before {
        content: '';
        position: absolute;
        left: 8px;
        top: 0;
        bottom: 0;
        width: 2px;
        background: var(--accent);
    }
    .timeline-item { position: relative; margin-bottom: 25px; }
    .timeline-item::before {
        content: '';
        position: absolute;
        left: -26px;
        top: 5px;
        width: 12px;
        height: 12px;
        border-radius: 50%;
        background: var(--accent);
        border: 2px solid var(--bg-primary);
    }
    .timeline-time { font-size: 0.85em; color: var(--accent); font-weight: 600; }
    .timeline-content { margin-top: 5px; }
    .stats-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 15px;
        margin: 20px 0;
    }
    .stat-card {
        background: var(--bg-secondary);
        border: 1px solid var(--border);
        border-radius: 8px;
        padding: 20px;
        text-align: center;
    }
    .stat-value { font-size: 2em; font-weight: bold; color: var(--accent); }
    .stat-label { font-size: 0.85em; color: var(--text-secondary); margin-top: 5px; }
    .search-box {
        width: 100%;
        padding: 12px 15px;
        background: var(--bg-secondary);
        border: 1px solid var(--border);
        border-radius: 8px;
        color: var(--text-primary);
        font-size: 1em;
        margin-bottom: 20px;
    }
    .search-box:focus { outline: none; border-color: var(--accent); }
    footer {
        margin-top: 50px;
        padding: 20px;
        text-align: center;
        color: var(--text-secondary);
        font-size: 0.85em;
        border-top: 1px solid var(--border);
    }
    @media print {
        body { background: #fff; color: #000; }
        .classification-banner { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    }
    @media (max-width: 768px) {
        .container { padding: 10px; }
        table { font-size: 0.85em; }
        th, td { padding: 8px; }
        .properties { grid-template-columns: 1fr; }
    }
    """

    JS_INTERACTIVE = """
    document.addEventListener('DOMContentLoaded', function() {
        // Table sorting
        document.querySelectorAll('th').forEach(th => {
            th.addEventListener('click', function() {
                const table = th.closest('table');
                const tbody = table.querySelector('tbody');
                const rows = Array.from(tbody.querySelectorAll('tr'));
                const index = Array.from(th.parentNode.children).indexOf(th);
                const isAsc = !th.classList.contains('asc');

                rows.sort((a, b) => {
                    const aVal = a.children[index].textContent.trim();
                    const bVal = b.children[index].textContent.trim();
                    return isAsc ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
                });

                rows.forEach(row => tbody.appendChild(row));
                th.classList.toggle('asc', isAsc);
            });
        });

        // Search functionality
        const searchBox = document.getElementById('searchBox');
        if (searchBox) {
            searchBox.addEventListener('input', function(e) {
                const term = e.target.value.toLowerCase();
                document.querySelectorAll('.entity-card, .timeline-item, table tbody tr').forEach(el => {
                    const text = el.textContent.toLowerCase();
                    el.style.display = text.includes(term) ? '' : 'none';
                });
            });
        }
    });
    """

    def __init__(self, config: Optional[HTMLExportConfig] = None):
        self.config = config or HTMLExportConfig()
        logger.info("HTMLExporter initialized")

    def export(
        self,
        data: Dict[str, Any],
        output_path: Optional[Union[str, Path]] = None,
    ) -> Union[str, Path]:
        """
        Export intelligence data ke HTML.

        Args:
            data: Intelligence product dictionary
            output_path: Output file path (optional)

        Returns:
            File path atau HTML string
        """
        html_content = self._build_html(data)

        if output_path:
            path = Path(output_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write(html_content)
            logger.info(f"HTML exported to {path}")
            return path

        return html_content

    def _build_html(self, data: Dict[str, Any]) -> str:
        """Build complete HTML document."""
        parts = [
            self._build_head(),
            self._build_body(data),
        ]
        return "\n".join(parts)

    def _build_head(self) -> str:
        """Build HTML head section."""
        css = self.CSS_DARK
        if self.config.custom_css:
            css += f"\n{self.config.custom_css}"

        js = self.JS_INTERACTIVE if self.config.include_js else ""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html.escape(self.config.title)}</title>
    <style>{css}</style>
    {f"<script>{js}</script>" if js else ""}
</head>"""

    def _build_body(self, data: Dict[str, Any]) -> str:
        """Build HTML body section."""
        sections = []

        # Classification banner
        if self.config.classification_banner:
            sections.append(
                f'<div class="classification-banner">{html.escape(self.config.classification_banner)}</div>'
            )

        # Header
        sections.append(self._build_header(data))

        # Search
        if self.config.include_search:
            sections.append('<input type="text" class="search-box" id="searchBox" placeholder="🔍 Search report...">')

        # Stats overview
        sections.append(self._build_stats(data))

        # Entities
        if data.get("entities"):
            sections.append(self._build_entities_section(data["entities"]))

        # Relationships
        if data.get("relationships"):
            sections.append(self._build_relationships_section(data["relationships"]))

        # Timeline
        if self.config.include_timeline and data.get("timeline"):
            sections.append(self._build_timeline_section(data["timeline"]))

        # Anomalies
        if data.get("anomalies"):
            sections.append(self._build_anomalies_section(data["anomalies"]))

        # Hypotheses
        if data.get("hypotheses"):
            sections.append(self._build_hypotheses_section(data["hypotheses"]))

        # Raw data (collapsible)
        sections.append(self._build_raw_data_section(data))

        # Footer
        sections.append(self._build_footer())

        # Classification banner bottom
        if self.config.classification_banner:
            sections.append(
                f'<div class="classification-banner">{html.escape(self.config.classification_banner)}</div>'
            )

        return f"<body>\n<div class=\"container\">\n" + "\n".join(sections) + "\n</div>\n</body>\n</html>"

    def _build_header(self, data: Dict[str, Any]) -> str:
        """Build report header."""
        title = data.get("title", self.config.title)
        case_id = data.get("case_id", "N/A")
        created = data.get("created_at", datetime.utcnow().isoformat())

        return f"""
<header>
    <h1>🎯 {html.escape(title)}</h1>
    <div class="meta">
        <span>📁 Case: <strong>{html.escape(str(case_id))}</strong></span>
        <span>📅 Generated: <strong>{html.escape(str(created))}</strong></span>
        <span>🔧 Catherine OSINT v4.0</span>
    </div>
</header>"""

    def _build_stats(self, data: Dict[str, Any]) -> str:
        """Build statistics overview."""
        stats = [
            ("Entities", len(data.get("entities", [])), "👤"),
            ("Relationships", len(data.get("relationships", [])), "🔗"),
            ("Anomalies", len(data.get("anomalies", [])), "⚠️"),
            ("Hypotheses", len(data.get("hypotheses", [])), "💡"),
        ]

        cards = "\n".join([
            f"""
            <div class=\"stat-card\">
                <div class=\"stat-value\">{icon} {count}</div>
                <div class=\"stat-label\">{label}</div>
            </div>"""
            for label, count, icon in stats
        ])

        return f"<div class=\"stats-grid\">{cards}</div>"

    def _build_entities_section(self, entities: List[Dict[str, Any]]) -> str:
        """Build entities section dengan cards."""
        cards = []
        for entity in entities:
            entity_id = html.escape(str(entity.get("id", "Unknown")))
            name = html.escape(str(entity.get("name", entity.get("label", "Unnamed"))))
            entity_type = html.escape(str(entity.get("type", "unknown")))
            confidence = entity.get("confidence", 0)

            # Confidence badge
            if confidence >= 0.8:
                badge_class = "badge badge-success"
            elif confidence >= 0.5:
                badge_class = "badge badge-medium"
            else:
                badge_class = "badge badge-danger"

            # Properties
            props = entity.get("properties", {})
            prop_html = ""
            if props:
                prop_items = "\n".join([
                    f"""
                    <div class="property">
                        <div class="property-key">{html.escape(str(k))}</div>
                        <div class="property-value">{html.escape(str(v))}</div>
                    </div>"""
                    for k, v in list(props.items())[:8]  # Limit properties
                ])
                prop_html = f'<div class="properties">{prop_items}</div>'

            cards.append(f"""
            <div class="entity-card">
                <div class="entity-header">
                    <div>
                        <div class="entity-title">{name}</div>
                        <div class="entity-type">{entity_type} • ID: {entity_id}</div>
                    </div>
                    <span class="{badge_class}">Confidence: {confidence:.0%}</span>
                </div>
                {prop_html}
            </div>""")

        return f"<h2>👤 Entities</h2>\n" + "\n".join(cards)

    def _build_relationships_section(self, relationships: List[Dict[str, Any]]) -> str:
        """Build relationships table."""
        rows = []
        for rel in relationships:
            rows.append(f"""
            <tr>
                <td>{html.escape(str(rel.get("source_id", "")))}</td>
                <td>{html.escape(str(rel.get("type", "")))}</td>
                <td>{html.escape(str(rel.get("target_id", "")))}</td>
                <td><span class="badge badge-info">{rel.get("confidence", 0):.0%}</span></td>
            </tr>""")

        return f"""
<h2>🔗 Relationships</h2>
<table>
    <thead>
        <tr>
            <th>Source</th>
            <th>Type</th>
            <th>Target</th>
            <th>Confidence</th>
        </tr>
    </thead>
    <tbody>
        {''.join(rows)}
    </tbody>
</table>"""

    def _build_timeline_section(self, timeline: List[Dict[str, Any]]) -> str:
        """Build timeline section."""
        items = []
        for event in timeline:
            time = html.escape(str(event.get("timestamp", "Unknown")))
            event_type = html.escape(str(event.get("event_type", "Event")))
            desc = html.escape(str(event.get("description", "")))

            items.append(f"""
            <div class="timeline-item">
                <div class="timeline-time">{time}</div>
                <div class="timeline-content">
                    <strong>{event_type}</strong>: {desc}
                </div>
            </div>""")

        return f'<h2>📅 Timeline</h2>\n<div class="timeline">\n' + "\n".join(items) + "\n</div>"

    def _build_anomalies_section(self, anomalies: List[Dict[str, Any]]) -> str:
        """Build anomalies section."""
        rows = []
        for anomaly in anomalies:
            score = anomaly.get("score", 0)
            if score >= 0.8:
                badge = "badge-critical"
            elif score >= 0.5:
                badge = "badge-high"
            else:
                badge = "badge-medium"

            rows.append(f"""
            <tr>
                <td><span class="badge {badge}">{html.escape(str(anomaly.get("anomaly_type", "")))}</span></td>
                <td>{html.escape(str(anomaly.get("description", "")))}</td>
                <td>{score:.2f}</td>
                <td>{html.escape(str(anomaly.get("detected_at", "")))}</td>
            </tr>""")

        return f"""
<h2>⚠️ Anomalies</h2>
<table>
    <thead>
        <tr><th>Type</th><th>Description</th><th>Score</th><th>Detected</th></tr>
    </thead>
    <tbody>{''.join(rows)}</tbody>
</table>"""

    def _build_hypotheses_section(self, hypotheses: List[Dict[str, Any]]) -> str:
        """Build hypotheses section."""
        rows = []
        for hyp in hypotheses:
            priority = str(hyp.get("priority", "medium")).lower()
            badge_map = {
                "critical": "badge-critical",
                "high": "badge-high",
                "medium": "badge-medium",
                "low": "badge-low",
            }
            badge = badge_map.get(priority, "badge-info")

            rows.append(f"""
            <tr>
                <td><span class="badge {badge}">{html.escape(str(hyp.get("priority", "")))}</span></td>
                <td><strong>{html.escape(str(hyp.get("title", "")))}</strong></td>
                <td>{html.escape(str(hyp.get("description", "")))[:200]}...</td>
                <td>{hyp.get("confidence", 0):.0%}</td>
            </tr>""")

        return f"""
<h2>💡 Hypotheses</h2>
<table>
    <thead>
        <tr><th>Priority</th><th>Title</th><th>Description</th><th>Confidence</th></tr>
    </thead>
    <tbody>{''.join(rows)}</tbody>
</table>"""

    def _build_raw_data_section(self, data: Dict[str, Any]) -> str:
        """Build collapsible raw data section."""
        json_data = json.dumps(data, indent=2, default=str)
        escaped = html.escape(json_data)

        return f"""
<h2>📋 Raw Data</h2>
<details>
    <summary>Click to expand raw JSON data</summary>
    <pre style="background: var(--bg-secondary); padding: 20px; border-radius: 8px; overflow-x: auto; font-size: 0.85em;"><code>{escaped}</code></pre>
</details>"""

    def _build_footer(self) -> str:
        """Build footer."""
        custom = f"<p>{html.escape(self.config.custom_footer)}</p>" if self.config.custom_footer else ""

        return f"""
<footer>
    <p>🛡️ Generated by Catherine OSINT Intelligence Platform v4.0</p>
    <p>{datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")}</p>
    {custom}
</footer>"""


# ============================================================================
# Convenience Functions
# ============================================================================

def export_to_html(
    data: Dict[str, Any],
    output_path: Union[str, Path],
    **kwargs,
) -> Path:
    """Quick export to HTML."""
    exporter = HTMLExporter(config=HTMLExportConfig(**kwargs))
    return exporter.export(data, output_path=output_path)