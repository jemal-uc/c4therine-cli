"""
maltego_export.py - Maltego Export Module
Part of OSINT Intelligence Platform v4

Export OSINT graph ke format Maltego:
- .mtz (Maltego Archive - compressed XML)
- .mtgl (Maltego Graph)
- .csv (Maltego Entities CSV)

Features:
- Map OSINT entities ke Maltego entity types
- Preserve relationships
- Include entity properties
- Compatible dengan Maltego Classic & Maltego XL
"""

import os
import json
import csv
import logging
import zipfile
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
from io import BytesIO, StringIO

from ..graph.neo4j_connector import Neo4jConnector

logger = logging.getLogger("osint.maltego_export")


class MaltegoEntityMapper:
    """
    Map OSINT entity types ke Maltego entity types.
    """

    # Mapping: OSINT label -> Maltego entity type
    ENTITY_MAPPING = {
        "Person": "maltego.Person",
        "Username": "maltego.Alias",
        "Email": "maltego.EmailAddress",
        "Domain": "maltego.Domain",
        "Website": "maltego.URL",
        "Organization": "maltego.Company",
        "Location": "maltego.Location",
        "Phone": "maltego.PhoneNumber",
        "IPAddress": "maltego.IPv4Address",
        "Certificate": "maltego.X509Certificate",
        "Subdomain": "maltego.DNSName",
        "Breach": "maltego.Breach",
        "GitHubRepo": "maltego.GitHubRepository",
        "GitHubUser": "maltego.GitHubUser",
        "Face": "maltego.Image",
        "Image": "maltego.Image",
    }

    # Maltego entity colors
    ENTITY_COLORS = {
        "maltego.Person": "#FF6B6B",
        "maltego.Alias": "#4ECDC4",
        "maltego.EmailAddress": "#45B7D1",
        "maltego.Domain": "#96CEB4",
        "maltego.URL": "#FFEAA7",
        "maltego.Company": "#DDA0DD",
        "maltego.Location": "#98D8C8",
        "maltego.PhoneNumber": "#F7DC6F",
        "maltego.IPv4Address": "#BB8FCE",
        "maltego.DNSName": "#85C1E9",
        "maltego.Image": "#F8C471",
    }

    @classmethod
    def get_maltego_type(cls, osint_label: str) -> str:
        """Get Maltego entity type dari OSINT label."""
        return cls.ENTITY_MAPPING.get(osint_label, "maltego.Phrase")

    @classmethod
    def get_entity_color(cls, maltego_type: str) -> str:
        """Get color untuk Maltego entity type."""
        return cls.ENTITY_COLORS.get(maltego_type, "#BDC3C7")

    @classmethod
    def get_display_name(cls, node: Dict[str, Any]) -> str:
        """Get display name untuk entity."""
        props = node.get("properties", {})
        return (
            props.get("name") or
            props.get("username") or
            props.get("email") or
            props.get("url") or
            props.get("address") or
            props.get("number") or
            node.get("id", "Unknown")
        )


class MaltegoExporter:
    """
    Export OSINT graph ke Maltego formats.
    """

    def __init__(self, connector: Neo4jConnector):
        """
        Initialize Maltego exporter.

        Args:
            connector: Neo4jConnector instance
        """
        self.connector = connector
        self.mapper = MaltegoEntityMapper()

    def export_mtz(self, filepath: str, graph_name: str = "OSINT Investigation") -> str:
        """
        Export graph ke Maltego .mtz (archive) format.

        Args:
            filepath: Output file path (.mtz)
            graph_name: Name of the graph

        Returns:
            Filepath
        """
        data = self._get_graph_data()

        # Create MTZ archive (ZIP dengan struktur khusus)
        with zipfile.ZipFile(filepath, 'w', zipfile.ZIP_DEFLATED) as zf:
            # 1. Graph XML
            graph_xml = self._generate_graph_xml(data, graph_name)
            zf.writestr("Graphs/graph.xml", graph_xml)

            # 2. Entities XML
            entities_xml = self._generate_entities_xml(data)
            zf.writestr("Entities/entities.xml", entities_xml)

            # 3. Properties XML
            properties_xml = self._generate_properties_xml()
            zf.writestr("properties.xml", properties_xml)

            # 4. Manifest
            manifest = self._generate_manifest(graph_name)
            zf.writestr("manifest.xml", manifest)

        logger.info(f"[MaltegoExporter] Exported MTZ to {filepath}")
        return filepath

    def export_mtgl(self, filepath: str, graph_name: str = "OSINT Investigation") -> str:
        """
        Export graph ke Maltego .mtgl (graph) format.

        Args:
            filepath: Output file path (.mtgl)
            graph_name: Name of the graph

        Returns:
            Filepath
        """
        data = self._get_graph_data()
        graph_xml = self._generate_graph_xml(data, graph_name)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(graph_xml)

        logger.info(f"[MaltegoExporter] Exported MTGL to {filepath}")
        return filepath

    def export_csv(self, filepath: str) -> str:
        """
        Export entities ke CSV format untuk import ke Maltego.

        Args:
            filepath: Output file path (.csv)

        Returns:
            Filepath
        """
        data = self._get_graph_data()

        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)

            # Header
            writer.writerow([
                "Entity Type", "Entity Value", "Parent Entity Type",
                "Parent Entity Value", "Relationship Type", "Relationship Direction"
            ])

            # Write entities
            for node in data["nodes"]:
                maltego_type = self.mapper.get_maltego_type(node["label"])
                display_name = self.mapper.get_display_name(node)

                writer.writerow([
                    maltego_type,
                    display_name,
                    "", "", "", ""
                ])

            # Write relationships
            for rel in data["relationships"]:
                source = next((n for n in data["nodes"] if n["id"] == rel["from"]), None)
                target = next((n for n in data["nodes"] if n["id"] == rel["to"]), None)

                if source and target:
                    writer.writerow([
                        self.mapper.get_maltego_type(target["label"]),
                        self.mapper.get_display_name(target),
                        self.mapper.get_maltego_type(source["label"]),
                        self.mapper.get_display_name(source),
                        rel["type"],
                        "to"
                    ])

        logger.info(f"[MaltegoExporter] Exported CSV to {filepath}")
        return filepath

    def export_entity_list(self, filepath: str) -> str:
        """
        Export flat entity list ke JSON untuk Maltego.

        Args:
            filepath: Output file path (.json)

        Returns:
            Filepath
        """
        data = self._get_graph_data()

        entities = []
        for node in data["nodes"]:
            maltego_type = self.mapper.get_maltego_type(node["label"])
            display_name = self.mapper.get_display_name(node)

            entities.append({
                "type": maltego_type,
                "value": display_name,
                "osint_label": node["label"],
                "osint_id": node["id"],
                "properties": node["properties"],
                "color": self.mapper.get_entity_color(maltego_type)
            })

        relationships = []
        for rel in data["relationships"]:
            relationships.append({
                "source": rel["from"],
                "target": rel["to"],
                "type": rel["type"],
                "properties": rel.get("properties", {})
            })

        output = {
            "version": "1.0",
            "generated": datetime.now().isoformat(),
            "tool": "OSINT Intelligence Platform v4",
            "entity_count": len(entities),
            "relationship_count": len(relationships),
            "entities": entities,
            "relationships": relationships
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2, ensure_ascii=False)

        logger.info(f"[MaltegoExporter] Exported entity list to {filepath}")
        return filepath

    def _generate_graph_xml(self, data: Dict[str, List], graph_name: str) -> str:
        """
        Generate Maltego Graph XML.

        Args:
            data: Graph data dengan nodes dan relationships
            graph_name: Name of the graph

        Returns:
            XML string
        """
        # Create root element
        root = ET.Element("MaltegoGraph")
        root.set("version", "1.0")
        root.set("name", graph_name)

        # Graph metadata
        metadata = ET.SubElement(root, "Metadata")
        ET.SubElement(metadata, "Created").text = datetime.now().isoformat()
        ET.SubElement(metadata, "Tool").text = "OSINT Intelligence Platform v4"
        ET.SubElement(metadata, "NodeCount").text = str(len(data["nodes"]))
        ET.SubElement(metadata, "EdgeCount").text = str(len(data["relationships"]))

        # Entities section
        entities_elem = ET.SubElement(root, "Entities")

        # Position counter untuk layout
        positions = self._calculate_layout(len(data["nodes"]))

        for i, node in enumerate(data["nodes"]):
            entity_elem = ET.SubElement(entities_elem, "Entity")

            maltego_type = self.mapper.get_maltego_type(node["label"])
            display_name = self.mapper.get_display_name(node)
            color = self.mapper.get_entity_color(maltego_type)

            entity_elem.set("id", str(node["id"]))
            entity_elem.set("type", maltego_type)
            entity_elem.set("value", display_name)

            # Position
            pos = positions[i] if i < len(positions) else (i * 100, i * 100)
            entity_elem.set("x", str(pos[0]))
            entity_elem.set("y", str(pos[1]))

            # Style
            style = ET.SubElement(entity_elem, "Style")
            ET.SubElement(style, "Color").text = color
            ET.SubElement(style, "BorderColor").text = "#000000"
            ET.SubElement(style, "BorderWidth").text = "1"

            # Properties
            props_elem = ET.SubElement(entity_elem, "Properties")
            for key, value in node["properties"].items():
                prop = ET.SubElement(props_elem, "Property")
                prop.set("name", key)
                prop.text = str(value) if value is not None else ""

        # Relationships section
        relationships_elem = ET.SubElement(root, "Relationships")

        for rel in data["relationships"]:
            rel_elem = ET.SubElement(relationships_elem, "Relationship")
            rel_elem.set("source", str(rel["from"]))
            rel_elem.set("target", str(rel["to"]))
            rel_elem.set("type", rel["type"])

            # Style
            rel_style = ET.SubElement(rel_elem, "Style")
            ET.SubElement(rel_style, "Color").text = "#7F8C8D"
            ET.SubElement(rel_style, "Width").text = "1.5"
            ET.SubElement(rel_style, "Direction").text = "directed"

            # Properties
            rel_props = ET.SubElement(rel_elem, "Properties")
            for key, value in rel.get("properties", {}).items():
                prop = ET.SubElement(rel_props, "Property")
                prop.set("name", key)
                prop.text = str(value) if value is not None else ""

        # Convert to string
        tree = ET.ElementTree(root)
        import io
        xml_buffer = io.BytesIO()
        tree.write(xml_buffer, encoding="utf-8", xml_declaration=True)
        return xml_buffer.getvalue().decode("utf-8")

    def _generate_entities_xml(self, data: Dict[str, List]) -> str:
        """Generate entities definition XML."""
        root = ET.Element("EntityDefinitions")

        used_types = set()
        for node in data["nodes"]:
            maltego_type = self.mapper.get_maltego_type(node["label"])
            used_types.add(maltego_type)

        for entity_type in used_types:
            entity_def = ET.SubElement(root, "EntityDefinition")
            entity_def.set("type", entity_type)
            entity_def.set("category", "OSINT")

            color = self.mapper.get_entity_color(entity_type)
            ET.SubElement(entity_def, "Color").text = color
            ET.SubElement(entity_def, "Icon").text = ""

        tree = ET.ElementTree(root)
        import io
        xml_buffer = io.BytesIO()
        tree.write(xml_buffer, encoding="utf-8", xml_declaration=True)
        return xml_buffer.getvalue().decode("utf-8")

    def _generate_properties_xml(self) -> str:
        """Generate properties XML."""
        root = ET.Element("Properties")
        ET.SubElement(root, "Version").text = "1.0"
        ET.SubElement(root, "Tool").text = "OSINT Intelligence Platform v4"
        ET.SubElement(root, "Generated").text = datetime.now().isoformat()

        tree = ET.ElementTree(root)
        import io
        xml_buffer = io.BytesIO()
        tree.write(xml_buffer, encoding="utf-8", xml_declaration=True)
        return xml_buffer.getvalue().decode("utf-8")

    def _generate_manifest(self, graph_name: str) -> str:
        """Generate manifest XML untuk .mtz archive."""
        root = ET.Element("MaltegoArchive")
        root.set("version", "1.0")

        ET.SubElement(root, "Name").text = graph_name
        ET.SubElement(root, "Created").text = datetime.now().isoformat()
        ET.SubElement(root, "Tool").text = "OSINT Intelligence Platform v4"

        files = ET.SubElement(root, "Files")
        ET.SubElement(files, "File").set("path", "Graphs/graph.xml")
        ET.SubElement(files, "File").set("path", "Entities/entities.xml")
        ET.SubElement(files, "File").set("path", "properties.xml")

        tree = ET.ElementTree(root)
        import io
        xml_buffer = io.BytesIO()
        tree.write(xml_buffer, encoding="utf-8", xml_declaration=True)
        return xml_buffer.getvalue().decode("utf-8")

    def _calculate_layout(self, node_count: int, radius: int = 300) -> List[Tuple[int, int]]:
        """
        Calculate circular layout positions untuk nodes.

        Args:
            node_count: Number of nodes
            radius: Radius of the circle

        Returns:
            List of (x, y) positions
        """
        import math
        positions = []

        for i in range(node_count):
            angle = (2 * math.pi * i) / max(node_count, 1)
            x = int(radius * math.cos(angle)) + radius
            y = int(radius * math.sin(angle)) + radius
            positions.append((x, y))

        return positions

    def _get_graph_data(self) -> Dict[str, List]:
        """
        Get graph data dari connector.

        Returns:
            Dict dengan "nodes" dan "relationships" lists
        """
        if self.connector.in_memory_mode:
            nodes = [n.to_dict() for n in self.connector._nodes.values()]
            relationships = [r.to_dict() for r in self.connector._relationships.values()]
        else:
            nodes = []
            relationships = []

            try:
                result = self.connector.execute_cypher("MATCH (n) RETURN n")
                for record in result:
                    node = record["n"]
                    nodes.append({
                        "id": str(node.element_id),
                        "label": list(node.labels)[0] if node.labels else "Unknown",
                        "properties": dict(node)
                    })

                result = self.connector.execute_cypher("MATCH ()-[r]->() RETURN r")
                for record in result:
                    rel = record["r"]
                    relationships.append({
                        "id": str(rel.element_id),
                        "from": str(rel.start_node.element_id),
                        "to": str(rel.end_node.element_id),
                        "type": rel.type,
                        "properties": dict(rel)
                    })
            except Exception as e:
                logger.error(f"Error querying Neo4j: {e}")

        return {"nodes": nodes, "relationships": relationships}

    def get_summary(self) -> Dict[str, Any]:
        """Get export summary."""
        stats = self.connector.get_stats()
        return {
            "total_nodes": stats.get("total_nodes", 0),
            "total_relationships": stats.get("total_relationships", 0),
            "mode": stats.get("mode", "unknown"),
            "export_formats": ["mtz", "mtgl", "csv", "json"],
            "entity_types_mapped": len(self.mapper.ENTITY_MAPPING)
        }


# ============== CONVENIENCE FUNCTIONS ==============

def export_to_maltego(connector: Neo4jConnector, filepath: str, 
                       graph_name: str = "OSINT Investigation") -> str:
    """Quick export ke Maltego .mtz format."""
    exporter = MaltegoExporter(connector)
    return exporter.export_mtz(filepath, graph_name)


def export_to_maltego_csv(connector: Neo4jConnector, filepath: str) -> str:
    """Quick export ke Maltego CSV format."""
    exporter = MaltegoExporter(connector)
    return exporter.export_csv(filepath)


# ============== MAIN ==============

if __name__ == "__main__":
    print("=" * 60)
    print("Maltego Export Module")
    print("=" * 60)

    # Demo dengan in-memory connector
    connector = Neo4jConnector()

    # Create sample data
    person_id = connector.create_node("Person", {
        "name": "John Doe",
        "normalized_name": "john_doe",
        "confidence_score": 0.95
    })

    email_id = connector.create_node("Email", {
        "email": "john.doe@example.com",
        "domain": "example.com"
    })

    username_id = connector.create_node("Username", {
        "username": "johndoe",
        "platform": "twitter"
    })

    connector.create_relationship(person_id, email_id, "HAS_EMAIL")
    connector.create_relationship(person_id, username_id, "USES")

    exporter = MaltegoExporter(connector)

    print(f"\n[*] Graph stats: {exporter.get_summary()}")

    print("\n[*] Exporting to MTZ...")
    mtz_path = exporter.export_mtz("/mnt/agents/output/demo_investigation.mtz")
    print(f"[+] Saved: {mtz_path}")

    print("\n[*] Exporting to CSV...")
    csv_path = exporter.export_csv("/mnt/agents/output/demo_entities.csv")
    print(f"[+] Saved: {csv_path}")

    print("\n[*] Exporting entity list...")
    json_path = exporter.export_entity_list("/mnt/agents/output/demo_entities.json")
    print(f"[+] Saved: {json_path}")

    print("\n" + "=" * 60)
    print("Export complete!")
    print("=" * 60)