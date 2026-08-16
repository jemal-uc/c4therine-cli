"""
narrative_report.py - Narrative Report Generation Module
Part of OSINT Intelligence Platform v4

Menghasilkan laporan investigasi dalam bentuk narasi yang mudah dibaca,
dengan struktur profesional, storytelling, dan visualisasi terintegrasi.

Features:
- Executive summary generation
- Timeline narrative
- Entity profiles dengan storytelling
- Relationship narratives
- Threat assessment narratives
- Evidence presentation
- Recommendation narratives
- Multi-format export (Markdown, HTML, PDF, DOCX)
- Template-based customization
"""

import os
import re
import json
import logging
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from collections import defaultdict, Counter

logger = logging.getLogger("osint.narrative_report")


class ReportSection(Enum):
    """Standard report sections."""
    EXECUTIVE_SUMMARY = "executive_summary"
    INTRODUCTION = "introduction"
    METHODOLOGY = "methodology"
    FINDINGS = "findings"
    ENTITY_PROFILES = "entity_profiles"
    TIMELINE = "timeline"
    RELATIONSHIPS = "relationships"
    THREAT_ASSESSMENT = "threat_assessment"
    EVIDENCE = "evidence"
    HYPOTHESES = "hypotheses"
    ANOMALIES = "anomalies"
    RECOMMENDATIONS = "recommendations"
    APPENDIX = "appendix"


class ReportTone(Enum):
    """Report writing tones."""
    FORMAL = "formal"
    TECHNICAL = "technical"
    INVESTIGATIVE = "investigative"
    EXECUTIVE = "executive"


@dataclass
class ReportConfig:
    """Configuration untuk report generation."""
    title: str = "OSINT Investigation Report"
    subtitle: str = ""
    author: str = "OSINT Intelligence Platform"
    classification: str = "UNCLASSIFIED"
    tone: ReportTone = ReportTone.INVESTIGATIVE
    include_sections: List[ReportSection] = field(default_factory=lambda: [
        ReportSection.EXECUTIVE_SUMMARY,
        ReportSection.INTRODUCTION,
        ReportSection.METHODOLOGY,
        ReportSection.FINDINGS,
        ReportSection.ENTITY_PROFILES,
        ReportSection.TIMELINE,
        ReportSection.RELATIONSHIPS,
        ReportSection.THREAT_ASSESSMENT,
        ReportSection.EVIDENCE,
        ReportSection.RECOMMENDATIONS,
    ])
    max_entity_profiles: int = 10
    max_timeline_events: int = 50
    max_evidence_items: int = 30
    include_confidence_scores: bool = True
    include_raw_data: bool = False


@dataclass
class EntityProfile:
    """Profile narrative untuk sebuah entity."""
    entity_id: str
    entity_type: str
    name: str
    narrative: str
    key_attributes: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0
    related_entities: List[str] = field(default_factory=list)
    risk_indicators: List[str] = field(default_factory=list)


@dataclass
class TimelineEvent:
    """Timeline event dengan narrative."""
    timestamp: str
    event_type: str
    narrative: str
    entities_involved: List[str] = field(default_factory=list)
    evidence_refs: List[str] = field(default_factory=list)
    significance: str = "medium"  # low, medium, high, critical


@dataclass
class RelationshipNarrative:
    """Narrative untuk sebuah relationship."""
    source_name: str
    target_name: str
    rel_type: str
    narrative: str
    strength: str = "unknown"  # weak, moderate, strong
    evidence_count: int = 0
    confidence: float = 0.0


class NarrativeReportGenerator:
    """
    Generate professional narrative reports dari OSINT investigation data.
    """

    # Narrative templates
    TEMPLATES = {
        "entity_intro": "{name} is a {type} identified during the investigation. ",
        "entity_confidence_high": "This identification is supported by strong evidence with a confidence score of {confidence:.0%}. ",
        "entity_confidence_medium": "This identification is supported by moderate evidence with a confidence score of {confidence:.0%}. ",
        "entity_confidence_low": "This identification is tentative with a confidence score of {confidence:.0%} and requires further verification. ",
        "relationship_strong": "There is a strong {rel_type} relationship between {source} and {target}. ",
        "relationship_moderate": "There is evidence suggesting a {rel_type} relationship between {source} and {target}. ",
        "relationship_weak": "A potential {rel_type} relationship between {source} and {target} has been identified but requires further confirmation. ",
        "threat_critical": "CRITICAL: {description} Immediate action is recommended. ",
        "threat_high": "HIGH: {description} Prompt attention is advised. ",
        "threat_medium": "MEDIUM: {description} Continued monitoring is recommended. ",
        "threat_low": "LOW: {description} Standard procedures apply. ",
    }

    def __init__(self, config: Optional[ReportConfig] = None):
        """
        Initialize narrative report generator.

        Args:
            config: ReportConfig instance
        """
        self.config = config or ReportConfig()
        self._sections: Dict[ReportSection, str] = {}

        logger.info("[NarrativeReportGenerator] Initialized")

    # ==================== SECTION GENERATORS ====================

    def generate_executive_summary(self,
                                    investigation_summary: Dict[str, Any],
                                    key_findings: List[Dict],
                                    threat_level: str = "unknown") -> str:
        """
        Generate executive summary narrative.

        Args:
            investigation_summary: Summary dictionary
            key_findings: List of key finding dictionaries
            threat_level: Overall threat level

        Returns:
            Executive summary text
        """
        target = investigation_summary.get("target", "Unknown")
        duration = investigation_summary.get("duration", "N/A")
        entity_count = investigation_summary.get("entity_count", 0)

        narrative = f"""# Executive Summary

## Overview

This report presents the findings of an Open Source Intelligence (OSINT) investigation targeting **{target}**. The investigation was conducted over {duration} and identified {entity_count} distinct entities requiring analysis.

## Key Findings

"""

        for i, finding in enumerate(key_findings[:5], 1):
            narrative += f"{i}. **{finding.get('title', 'Finding')}**: {finding.get('description', 'No description')}\n"
            if self.config.include_confidence_scores and 'confidence' in finding:
                narrative += f"   - Confidence: {finding['confidence']:.0%}\n"

        narrative += f"\n## Threat Assessment\n\n"

        threat_narratives = {
            "critical": "The investigation has identified **CRITICAL** level concerns that require immediate attention and potential escalation to appropriate authorities.",
            "high": "The investigation has identified **HIGH** level concerns that warrant prompt action and continued monitoring.",
            "medium": "The investigation has identified **MEDIUM** level concerns that should be monitored and periodically reassessed.",
            "low": "The investigation has identified **LOW** level concerns that are within normal parameters but should be documented.",
            "unknown": "The threat level could not be definitively determined based on available information. Further investigation is recommended.",
        }

        narrative += threat_narratives.get(threat_level.lower(), threat_narratives["unknown"])

        narrative += "\n\n## Recommendations\n\n"
        narrative += "Based on the findings of this investigation, the following actions are recommended:\n\n"
        narrative += "1. Continue monitoring the subject's digital footprint\n"
        narrative += "2. Verify critical findings through additional sources\n"
        narrative += "3. Document all evidence dengan proper chain of custody\n"

        self._sections[ReportSection.EXECUTIVE_SUMMARY] = narrative
        return narrative

    def generate_entity_profiles(self,
                                  entities: List[Dict[str, Any]],
                                  relationships: List[Dict[str, Any]]) -> str:
        """
        Generate entity profile narratives.

        Args:
            entities: List of entity dictionaries
            relationships: List of relationship dictionaries

        Returns:
            Entity profiles text
        """
        narrative = "# Entity Profiles\n\n"

        # Sort by confidence
        sorted_entities = sorted(
            entities,
            key=lambda e: e.get("properties", {}).get("confidence_score", 0),
            reverse=True
        )[:self.config.max_entity_profiles]

        for entity in sorted_entities:
            entity_id = entity.get("id", "unknown")
            label = entity.get("label", "Unknown")
            props = entity.get("properties", {})
            name = props.get("name", props.get("username", props.get("email", entity_id)))
            confidence = props.get("confidence_score", 0.5)

            # Get related entities
            related = [
                r for r in relationships
                if r.get("from") == entity_id or r.get("to") == entity_id
            ]

            narrative += f"## {name}\n\n"
            narrative += f"**Type:** {label} | **ID:** {entity_id}\n\n"

            # Confidence narrative
            if confidence >= 0.8:
                narrative += self.TEMPLATES["entity_confidence_high"].format(confidence=confidence)
            elif confidence >= 0.5:
                narrative += self.TEMPLATES["entity_confidence_medium"].format(confidence=confidence)
            else:
                narrative += self.TEMPLATES["entity_confidence_low"].format(confidence=confidence)

            narrative += "\n"

            # Key attributes
            if props:
                narrative += "### Key Attributes\n\n"
                for key, value in props.items():
                    if key not in ["confidence_score", "timestamp"] and value:
                        narrative += f"- **{key.replace('_', ' ').title()}:** {value}\n"
                narrative += "\n"

            # Relationships
            if related:
                narrative += "### Connections\n\n"
                for rel in related[:5]:
                    rel_type = rel.get("type", "UNKNOWN")
                    if rel.get("from") == entity_id:
                        target = rel.get("to", "unknown")
                        narrative += f"- {rel_type} → {target}\n"
                    else:
                        source = rel.get("from", "unknown")
                        narrative += f"- ← {rel_type} {source}\n"
                narrative += "\n"

            narrative += "---\n\n"

        self._sections[ReportSection.ENTITY_PROFILES] = narrative
        return narrative

    def generate_timeline_narrative(self,
                                     events: List[Dict[str, Any]]) -> str:
        """
        Generate timeline narrative.

        Args:
            events: List of event dictionaries

        Returns:
            Timeline narrative text
        """
        narrative = "# Investigation Timeline\n\n"

        if not events:
            narrative += "No temporal events were recorded during this investigation.\n"
            self._sections[ReportSection.TIMELINE] = narrative
            return narrative

        # Sort events
        sorted_events = sorted(events, key=lambda e: e.get("timestamp", ""))

        narrative += "The following timeline presents key events identified during the investigation, listed in chronological order:\n\n"

        current_date = None
        for event in sorted_events[:self.config.max_timeline_events]:
            ts = event.get("timestamp", "Unknown")
            event_type = event.get("type", "Event")
            description = event.get("description", "No description")

            # Extract date
            try:
                date_part = ts.split("T")[0] if "T" in ts else ts
                if date_part != current_date:
                    narrative += f"\n## {date_part}\n\n"
                    current_date = date_part
            except:
                pass

            time_part = ""
            try:
                time_part = ts.split("T")[1][:5] if "T" in ts else ""
            except:
                pass

            significance = event.get("significance", "medium")
            sig_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(significance, "⚪")

            narrative += f"{sig_emoji} **{time_part}** - {event_type}: {description}\n"

            if "entities" in event:
                narrative += f"   _Entities: {', '.join(event['entities'])}_\n"

            narrative += "\n"

        self._sections[ReportSection.TIMELINE] = narrative
        return narrative

    def generate_relationship_narrative(self,
                                         relationships: List[Dict[str, Any]],
                                         nodes: List[Dict[str, Any]]) -> str:
        """
        Generate relationship narrative.

        Args:
            relationships: List of relationship dictionaries
            nodes: List of node dictionaries

        Returns:
            Relationship narrative text
        """
        narrative = "# Relationship Analysis\n\n"

        if not relationships:
            narrative += "No relationships were identified during this investigation.\n"
            self._sections[ReportSection.RELATIONSHIPS] = narrative
            return narrative

        # Build node lookup
        node_lookup = {n.get("id"): n for n in nodes}

        # Group by relationship type
        rel_by_type = defaultdict(list)
        for rel in relationships:
            rel_by_type[rel.get("type", "UNKNOWN")].append(rel)

        narrative += f"The investigation identified **{len(relationships)}** relationships across **{len(rel_by_type)}** distinct types. The following analysis presents these relationships dalam narrative form.\n\n"

        for rel_type, rels in rel_by_type.items():
            narrative += f"## {rel_type} Relationships\n\n"

            for rel in rels[:10]:  # Limit per type
                source_id = rel.get("from", "unknown")
                target_id = rel.get("to", "unknown")

                source_node = node_lookup.get(source_id, {})
                target_node = node_lookup.get(target_id, {})

                source_name = source_node.get("properties", {}).get("name", source_id)
                target_name = target_node.get("properties", {}).get("name", target_id)

                rel_props = rel.get("properties", {})
                confidence = rel_props.get("confidence", 0.5)

                # Generate narrative based on confidence
                if confidence >= 0.7:
                    narrative += self.TEMPLATES["relationship_strong"].format(
                        rel_type=rel_type, source=source_name, target=target_name
                    )
                elif confidence >= 0.4:
                    narrative += self.TEMPLATES["relationship_moderate"].format(
                        rel_type=rel_type, source=source_name, target=target_name
                    )
                else:
                    narrative += self.TEMPLATES["relationship_weak"].format(
                        rel_type=rel_type, source=source_name, target=target_name
                    )

                # Add properties narrative
                if rel_props:
                    prop_texts = []
                    for key, value in rel_props.items():
                        if key != "confidence" and value:
                            prop_texts.append(f"{key}: {value}")
                    if prop_texts:
                        narrative += f"Additional details: {', '.join(prop_texts)}. "

                narrative += "\n\n"

            if len(rels) > 10:
                narrative += f"_... and {len(rels) - 10} more {rel_type} relationships_\n\n"

        self._sections[ReportSection.RELATIONSHIPS] = narrative
        return narrative

    def generate_threat_narrative(self,
                                   threat_assessment: Dict[str, Any],
                                   anomalies: Optional[List[Dict]] = None) -> str:
        """
        Generate threat assessment narrative.

        Args:
            threat_assessment: Threat assessment dictionary
            anomalies: Optional list of anomaly dictionaries

        Returns:
            Threat narrative text
        """
        narrative = "# Threat Assessment\n\n"

        level = threat_assessment.get("level", "unknown")
        risk_score = threat_assessment.get("risk_score", 0)
        concerns = threat_assessment.get("key_concerns", [])

        narrative += f"## Overall Threat Level: {level.upper()}\n\n"
        narrative += f"**Risk Score:** {risk_score:.2f}/1.00\n\n"

        # Threat narrative
        if level.lower() == "critical":
            narrative += self.TEMPLATES["threat_critical"].format(
                description="The investigation has uncovered critical indicators that pose significant risk."
            )
        elif level.lower() == "high":
            narrative += self.TEMPLATES["threat_high"].format(
                description="Several high-risk indicators have been identified."
            )
        elif level.lower() == "medium":
            narrative += self.TEMPLATES["threat_medium"].format(
                description="Some indicators of concern have been noted."
            )
        elif level.lower() == "low":
            narrative += self.TEMPLATES["threat_low"].format(
                description="Few risk indicators were identified."
            )
        else:
            narrative += "The threat level could not be determined.\n"

        narrative += "\n"

        # Key concerns
        if concerns:
            narrative += "## Key Concerns\n\n"
            for concern in concerns:
                narrative += f"- {concern}\n"
            narrative += "\n"

        # Anomalies
        if anomalies:
            narrative += "## Detected Anomalies\n\n"

            critical_anomalies = [a for a in anomalies if a.get("severity") == "critical"]
            high_anomalies = [a for a in anomalies if a.get("severity") == "high"]

            if critical_anomalies:
                narrative += "### Critical Anomalies\n\n"
                for a in critical_anomalies[:5]:
                    narrative += f"- **{a.get('entity_id', 'Unknown')}**: {a.get('description', 'No description')}\n"
                narrative += "\n"

            if high_anomalies:
                narrative += "### High Severity Anomalies\n\n"
                for a in high_anomalies[:5]:
                    narrative += f"- **{a.get('entity_id', 'Unknown')}**: {a.get('description', 'No description')}\n"
                narrative += "\n"

        self._sections[ReportSection.THREAT_ASSESSMENT] = narrative
        return narrative

    def generate_evidence_narrative(self,
                                     evidence_items: List[Dict[str, Any]]) -> str:
        """
        Generate evidence presentation narrative.

        Args:
            evidence_items: List of evidence dictionaries

        Returns:
            Evidence narrative text
        """
        narrative = "# Evidence Summary\n\n"

        if not evidence_items:
            narrative += "No evidence items were collected during this investigation.\n"
            self._sections[ReportSection.EVIDENCE] = narrative
            return narrative

        narrative += f"This section presents **{len(evidence_items)}** pieces of evidence collected during the investigation.\n\n"

        # Group by source
        by_source = defaultdict(list)
        for item in evidence_items:
            source = item.get("source", "Unknown")
            by_source[source].append(item)

        for source, items in by_source.items():
            narrative += f"## Evidence from {source}\n\n"

            for i, item in enumerate(items[:10], 1):
                narrative += f"### {i}. {item.get('type', 'Evidence')}\n\n"
                narrative += f"**Content:** {item.get('content', 'No content')}\n\n"

                if self.config.include_confidence_scores:
                    confidence = item.get("confidence", 0)
                    narrative += f"**Confidence:** {confidence:.0%}\n\n"

                if "metadata" in item:
                    narrative += "**Metadata:**\n"
                    for key, value in item["metadata"].items():
                        narrative += f"- {key}: {value}\n"
                    narrative += "\n"

                narrative += "---\n\n"

            if len(items) > 10:
                narrative += f"_... and {len(items) - 10} more items from {source}_\n\n"

        self._sections[ReportSection.EVIDENCE] = narrative
        return narrative

    def generate_recommendations_narrative(self,
                                            recommendations: List[str],
                                            hypotheses: Optional[List[Dict]] = None) -> str:
        """
        Generate recommendations narrative.

        Args:
            recommendations: List of recommendation strings
            hypotheses: Optional list of hypothesis dictionaries

        Returns:
            Recommendations narrative text
        """
        narrative = "# Recommendations\n\n"

        narrative += "Based on the findings presented dalam this report, the following recommendations are made:\n\n"

        # Priority recommendations
        narrative += "## Priority Actions\n\n"
        for i, rec in enumerate(recommendations[:10], 1):
            narrative += f"{i}. {rec}\n"
        narrative += "\n"

        # Follow-up investigations
        if hypotheses:
            untested = [h for h in hypotheses if h.get("status") == "untested"]
            if untested:
                narrative += "## Suggested Follow-up Investigations\n\n"
                narrative += "The following hypotheses remain untested and warrant further investigation:\n\n"

                for h in untested[:5]:
                    narrative += f"- **{h.get('statement', 'Hypothesis')}** (confidence: {h.get('confidence', 0):.0%})\n"
                narrative += "\n"

        # Monitoring recommendations
        narrative += "## Monitoring Recommendations\n\n"
        narrative += "- Continue periodic monitoring of the subject's digital footprint\n"
        narrative += "- Set up alerts untuk new mentions atau account creations\n"
        narrative += "- Reassess threat level dalam 30 days atau upon new significant findings\n"

        self._sections[ReportSection.RECOMMENDATIONS] = narrative
        return narrative

    # ==================== FULL REPORT GENERATION ====================

    def generate_full_report(self,
                              investigation_data: Dict[str, Any]) -> str:
        """
        Generate complete narrative report.

        Args:
            investigation_data: Dictionary dengan semua investigation data

        Returns:
            Complete report text (Markdown)
        """
        report_parts = []

        # Header
        header = f"""# {self.config.title}

**Classification:** {self.config.classification}  
**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M")}  
**Author:** {self.config.author}

---

"""
        report_parts.append(header)

        # Generate requested sections
        if ReportSection.EXECUTIVE_SUMMARY in self.config.include_sections:
            exec_sum = self.generate_executive_summary(
                investigation_data.get("summary", {}),
                investigation_data.get("key_findings", []),
                investigation_data.get("threat_level", "unknown")
            )
            report_parts.append(exec_sum)
            report_parts.append("\n\n---\n\n")

        if ReportSection.ENTITY_PROFILES in self.config.include_sections:
            profiles = self.generate_entity_profiles(
                investigation_data.get("nodes", []),
                investigation_data.get("relationships", [])
            )
            report_parts.append(profiles)
            report_parts.append("\n\n---\n\n")

        if ReportSection.TIMELINE in self.config.include_sections:
            timeline = self.generate_timeline_narrative(
                investigation_data.get("events", [])
            )
            report_parts.append(timeline)
            report_parts.append("\n\n---\n\n")

        if ReportSection.RELATIONSHIPS in self.config.include_sections:
            rels = self.generate_relationship_narrative(
                investigation_data.get("relationships", []),
                investigation_data.get("nodes", [])
            )
            report_parts.append(rels)
            report_parts.append("\n\n---\n\n")

        if ReportSection.THREAT_ASSESSMENT in self.config.include_sections:
            threat = self.generate_threat_narrative(
                investigation_data.get("threat_assessment", {}),
                investigation_data.get("anomalies", [])
            )
            report_parts.append(threat)
            report_parts.append("\n\n---\n\n")

        if ReportSection.EVIDENCE in self.config.include_sections:
            evidence = self.generate_evidence_narrative(
                investigation_data.get("evidence", [])
            )
            report_parts.append(evidence)
            report_parts.append("\n\n---\n\n")

        if ReportSection.RECOMMENDATIONS in self.config.include_sections:
            recs = self.generate_recommendations_narrative(
                investigation_data.get("recommendations", []),
                investigation_data.get("hypotheses", [])
            )
            report_parts.append(recs)

        # Footer
        footer = f"""

---

*This report was generated by the OSINT Intelligence Platform v4.0*  
*All findings should be independently verified before taking action*
"""
        report_parts.append(footer)

        return "\n".join(report_parts)

    # ==================== EXPORT FUNCTIONS ====================

    def export_markdown(self, report_text: str, output_path: str) -> str:
        """Export report ke Markdown file."""
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report_text)
        logger.info(f"[NarrativeReportGenerator] Exported Markdown to {output_path}")
        return output_path

    def export_html(self, report_text: str, output_path: str, 
                    title: Optional[str] = None) -> str:
        """
        Export report ke HTML file dengan styling.

        Args:
            report_text: Markdown report text
            output_path: Output file path
            title: HTML page title

        Returns:
            File path
        """
        title = title or self.config.title

        # Simple Markdown to HTML conversion
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        :root {{
            --bg-color: #0f0f1a;
            --text-color: #e0e0e0;
            --heading-color: #e94560;
            --accent-color: #16213e;
            --border-color: #333;
        }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: var(--bg-color);
            color: var(--text-color);
            max-width: 900px;
            margin: 0 auto;
            padding: 40px 20px;
            line-height: 1.6;
        }}
        h1 {{
            color: var(--heading-color);
            border-bottom: 3px solid var(--heading-color);
            padding-bottom: 15px;
            font-size: 2rem;
        }}
        h2 {{
            color: #fff;
            margin-top: 40px;
            border-left: 4px solid var(--heading-color);
            padding-left: 15px;
        }}
        h3 {{
            color: #ccc;
            margin-top: 25px;
        }}
        hr {{
            border: none;
            border-top: 1px solid var(--border-color);
            margin: 30px 0;
        }}
        strong {{
            color: #fff;
        }}
        blockquote {{
            border-left: 4px solid var(--heading-color);
            margin: 20px 0;
            padding: 15px 20px;
            background: var(--accent-color);
            border-radius: 5px;
        }}
        ul {{
            padding-left: 25px;
        }}
        li {{
            margin: 8px 0;
        }}
        .classification {{
            display: inline-block;
            background: var(--heading-color);
            color: white;
            padding: 5px 15px;
            border-radius: 5px;
            font-weight: bold;
            font-size: 0.85rem;
        }}
        footer {{
            margin-top: 50px;
            padding-top: 20px;
            border-top: 1px solid var(--border-color);
            font-size: 0.8rem;
            color: #888;
            text-align: center;
        }}
    </style>
</head>
<body>
"""

        # Convert markdown to HTML (simple)
        lines = report_text.split("\n")
        in_list = False

        for line in lines:
            stripped = line.strip()

            # Headers
            if stripped.startswith("# "):
                html_content += f"<h1>{stripped[2:]}</h1>\n"
            elif stripped.startswith("## "):
                html_content += f"<h2>{stripped[3:]}</h2>\n"
            elif stripped.startswith("### "):
                html_content += f"<h3>{stripped[4:]}</h3>\n"
            # Horizontal rule
            elif stripped == "---":
                html_content += "<hr>\n"
            # List items
            elif stripped.startswith("- "):
                if not in_list:
                    html_content += "<ul>\n"
                    in_list = True
                html_content += f"<li>{stripped[2:]}</li>\n"
            elif stripped.startswith("1. ") or stripped.startswith("2. ") or stripped.startswith("3. "):
                if not in_list:
                    html_content += "<ol>\n"
                    in_list = True
                html_content += f"<li>{stripped[3:]}</li>\n"
            # Empty line ends list
            elif stripped == "" and in_list:
                html_content += "</ul>\n" if "<ul>" in html_content.split("<li>")[-1] else "</ol>\n"
                in_list = False
                html_content += "<br>\n"
            # Bold text
            elif "**" in stripped:
                html_content += f"<p>{self._markdown_bold_to_html(stripped)}</p>\n"
            # Regular paragraph
            elif stripped:
                html_content += f"<p>{stripped}</p>\n"
            else:
                html_content += "<br>\n"

        if in_list:
            html_content += "</ul>\n"

        html_content += """
    <footer>
        <p>Generated by OSINT Intelligence Platform v4.0</p>
        <p>All findings should be independently verified</p>
    </footer>
</body>
</html>"""

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        logger.info(f"[NarrativeReportGenerator] Exported HTML to {output_path}")
        return output_path

    def _markdown_bold_to_html(self, text: str) -> str:
        """Convert **bold** markdown ke HTML."""
        import re
        return re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', text)

    def export_json(self, investigation_data: Dict, output_path: str) -> str:
        """Export investigation data ke JSON."""
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(investigation_data, f, indent=2, ensure_ascii=False, default=str)
        logger.info(f"[NarrativeReportGenerator] Exported JSON to {output_path}")
        return output_path


# ============== CONVENIENCE FUNCTIONS ==============

def quick_report(investigation_data: Dict[str, Any], 
                 output_path: str,
                 title: str = "OSINT Investigation Report") -> str:
    """Quick generate dan export report."""
    config = ReportConfig(title=title)
    generator = NarrativeReportGenerator(config)
    report = generator.generate_full_report(investigation_data)

    if output_path.endswith(".html"):
        return generator.export_html(report, output_path)
    else:
        return generator.export_markdown(report, output_path)


# ============== MAIN ==============

if __name__ == "__main__":
    print("=" * 70)
    print("Narrative Report Generation Module")
    print("=" * 70)

    # Demo data
    investigation_data = {
        "summary": {
            "target": "John Doe",
            "duration": "14 days",
            "entity_count": 12
        },
        "threat_level": "medium",
        "key_findings": [
            {"title": "Multiple Online Identities", "description": "Subject maintains 5+ usernames across platforms", "confidence": 0.85},
            {"title": "Breach Exposure", "description": "Email found dalam 2 known breaches", "confidence": 0.95},
            {"title": "Domain Ownership", "description": "Owns example.com domain", "confidence": 0.75},
        ],
        "nodes": [
            {"id": "person_1", "label": "Person", "properties": {"name": "John Doe", "confidence_score": 0.9}},
            {"id": "email_1", "label": "Email", "properties": {"email": "john@example.com", "confidence_score": 0.95}},
            {"id": "username_1", "label": "Username", "properties": {"username": "johndoe", "platform": "twitter", "confidence_score": 0.85}},
        ],
        "relationships": [
            {"from": "person_1", "to": "email_1", "type": "HAS_EMAIL", "properties": {"confidence": 0.95}},
            {"from": "person_1", "to": "username_1", "type": "USES", "properties": {"confidence": 0.85}},
        ],
        "events": [
            {"timestamp": "2024-01-01T10:00:00", "type": "Account Creation", "description": "Twitter account created", "significance": "medium"},
            {"timestamp": "2024-01-15T14:30:00", "type": "Breach", "description": "Email found dalam breach database", "significance": "high"},
        ],
        "threat_assessment": {
            "level": "medium",
            "risk_score": 0.55,
            "key_concerns": ["Breach exposure", "Multiple identities"]
        },
        "anomalies": [
            {"entity_id": "username_1", "severity": "medium", "description": "Unusual posting pattern detected"}
        ],
        "evidence": [
            {"source": "Twitter API", "type": "Profile Data", "content": "Username: johndoe, Followers: 1500", "confidence": 0.9},
            {"source": "HaveIBeenPwned", "type": "Breach Data", "content": "Email found dalam ExampleLeak2023", "confidence": 0.95},
        ],
        "recommendations": [
            "Continue monitoring subject's social media activity",
            "Verify breach data impact",
            "Investigate domain ownership history"
        ],
        "hypotheses": [
            {"statement": "Subject has additional undiscovered accounts", "status": "untested", "confidence": 0.7}
        ]
    }

    print("\n[*] Generating narrative report...")
    generator = NarrativeReportGenerator()
    report = generator.generate_full_report(investigation_data)

    print(f"[+] Report generated: {len(report)} characters")

    print("\n[*] Exporting to Markdown...")
    generator.export_markdown(report, "/mnt/agents/output/narrative_report.md")
    print("[+] Saved: /mnt/agents/output/narrative_report.md")

    print("\n[*] Exporting to HTML...")
    generator.export_html(report, "/mnt/agents/output/narrative_report.html")
    print("[+] Saved: /mnt/agents/output/narrative_report.html")

    print("\n[*] Exporting to JSON...")
    generator.export_json(investigation_data, "/mnt/agents/output/investigation_data.json")
    print("[+] Saved: /mnt/agents/output/investigation_data.json")

    print("\n[*] Report preview (first 500 chars):")
    print(report[:500])

    print("\n" + "=" * 70)
    print("Narrative Report Demo Complete!")
    print("=" * 70)