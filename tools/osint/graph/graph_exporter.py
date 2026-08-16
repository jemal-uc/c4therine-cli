"""
graph_exporter.py - Graph Exporter v2.0
Export OSINT graph ke multiple formats:
- JSON (nodes & relationships)
- Cypher (Neo4j import statements)
- CSV (node/edge lists)
- GEXF (Gephi compatible)
- GraphML (yEd, Cytoscape compatible)
- D3.js JSON (web visualization)
- Maltego .mtz (V4 - via maltego_export.py)
- PDF Report (V4)
- HTML Report (V4)

Features:
- Filter by node label atau relationship type
- Include/exclude properties
- Pretty print options
"""

import json
import csv
import logging
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime

from .neo4j_connector import Neo4jConnector

logger = logging.getLogger("osint.graph_exporter")


class GraphExporter:
    """
    Export OSINT graph ke berbagai formats.
    """

    def __init__(self, connector: Neo4jConnector):
        """
        Initialize exporter.

        Args:
            connector: Neo4jConnector instance
        """
        self.connector = connector

    def export_json(self, filepath: str, 
                    node_labels: Optional[List[str]] = None,
                    rel_types: Optional[List[str]] = None) -> str:
        """
        Export graph ke JSON format.

        Args:
            filepath: Output file path
            node_labels: Filter by node labels (None = all)
            rel_types: Filter by relationship types (None = all)

        Returns:
            Filepath
        """
        data = self._get_graph_data(node_labels, rel_types)

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        logger.info(f"[GraphExporter] Exported JSON to {filepath}")
        return filepath

    def export_cypher(self, filepath: str) -> str:
        """
        Export graph ke Cypher statements.
        Can be imported ke Neo4j via cypher-shell.

        Returns:
            Filepath
        """
        data = self._get_graph_data()

        statements = []
        statements.append("// OSINT Graph Export")
        statements.append(f"// Generated: {datetime.now().isoformat()}")
        statements.append("")

        # Create constraints
        statements.append("// Create constraints")
        labels = set(node["label"] for node in data["nodes"])
        for label in labels:
            statements.append(f"CREATE CONSTRAINT {label.lower()}_id IF NOT EXISTS FOR (n:{label}) REQUIRE n.id IS UNIQUE;")
        statements.append("")

        # Create nodes
        statements.append("// Create nodes")
        for node in data["nodes"]:
            label = node["label"]
            props = node["properties"]
            props["id"] = node["id"]

            props_str = ", ".join([f'{k}: {json.dumps(v)}' for k, v in props.items()])
            statements.append(f"MERGE (n:{label} {{ {props_str} }});")

        statements.append("")

        # Create relationships
        statements.append("// Create relationships")
        for rel in data["relationships"]:
            rel_type = rel["type"]
            from_id = rel["from"]
            to_id = rel["to"]
            props = rel.get("properties", {})

            if props:
                props_str = ", ".join([f'{k}: {json.dumps(v)}' for k, v in props.items()])
                statements.append(
                    f"MATCH (a {{id: {json.dumps(from_id)}}}), "
                    f"(b {{id: {json.dumps(to_id)}}}) "
                    f"MERGE (a)-[r:{rel_type} {{ {props_str} }}]->(b);"
                )
            else:
                statements.append(
                    f"MATCH (a {{id: {json.dumps(from_id)}}}), "
                    f"(b {{id: {json.dumps(to_id)}}}) "
                    f"MERGE (a)-[:{rel_type}]->(b);"
                )

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(statements))

        logger.info(f"[GraphExporter] Exported Cypher to {filepath}")
        return filepath

    def export_csv(self, nodes_filepath: str, edges_filepath: str) -> Tuple[str, str]:
        """
        Export graph ke CSV (nodes dan edges).

        Returns:
            Tuple of (nodes_filepath, edges_filepath)
        """
        data = self._get_graph_data()

        # Export nodes
        with open(nodes_filepath, "w", newline="", encoding="utf-8") as f:
            if data["nodes"]:
                # Get all possible properties
                all_props = set()
                for node in data["nodes"]:
                    all_props.update(node["properties"].keys())
                all_props.add("id")
                all_props.add("label")

                fieldnames = ["id", "label"] + sorted(all_props - {"id", "label"})
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()

                for node in data["nodes"]:
                    row = {"id": node["id"], "label": node["label"]}
                    row.update({k: json.dumps(v) if isinstance(v, (list, dict)) else v 
                               for k, v in node["properties"].items()})
                    writer.writerow(row)

        # Export edges
        with open(edges_filepath, "w", newline="", encoding="utf-8") as f:
            if data["relationships"]:
                all_props = set()
                for rel in data["relationships"]:
                    all_props.update(rel.get("properties", {}).keys())

                fieldnames = ["source", "target", "type"] + sorted(all_props)
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()

                for rel in data["relationships"]:
                    row = {
                        "source": rel["from"],
                        "target": rel["to"],
                        "type": rel["type"]
                    }
                    row.update(rel.get("properties", {}))
                    writer.writerow(row)

        logger.info(f"[GraphExporter] Exported CSV: {nodes_filepath}, {edges_filepath}")
        return nodes_filepath, edges_filepath

    def export_gexf(self, filepath: str) -> str:
        """
        Export graph ke GEXF format (Gephi compatible).

        Returns:
            Filepath
        """
        data = self._get_graph_data()

        # Create GEXF XML
        root = ET.Element("gexf")
        root.set("xmlns", "http://www.gexf.net/1.3")
        root.set("version", "1.3")

        meta = ET.SubElement(root, "meta")
        meta.set("lastmodifieddate", datetime.now().strftime("%Y-%m-%d"))
        creator = ET.SubElement(meta, "creator")
        creator.text = "OSINT Engine"
        description = ET.SubElement(meta, "description")
        description.text = "OSINT Investigation Graph"

        graph_elem = ET.SubElement(root, "graph")
        graph_elem.set("mode", "static")
        graph_elem.set("defaultedgetype", "directed")

        # Nodes
        nodes_elem = ET.SubElement(graph_elem, "nodes")
        for node in data["nodes"]:
            n = ET.SubElement(nodes_elem, "node")
            n.set("id", str(node["id"]))
            n.set("label", node["properties"].get("name", node["properties"].get("username", 
                  node["properties"].get("email", node["id"]))))

            # Add properties sebagai attributes
            attvalues = ET.SubElement(n, "attvalues")
            for key, value in node["properties"].items():
                attvalue = ET.SubElement(attvalues, "attvalue")
                attvalue.set("for", key)
                attvalue.set("value", str(value) if value is not None else "")

        # Edges
        edges_elem = ET.SubElement(graph_elem, "edges")
        for i, rel in enumerate(data["relationships"]):
            e = ET.SubElement(edges_elem, "edge")
            e.set("id", str(i))
            e.set("source", str(rel["from"]))
            e.set("target", str(rel["to"]))
            e.set("label", rel["type"])

        tree = ET.ElementTree(root)
        tree.write(filepath, encoding="utf-8", xml_declaration=True)

        logger.info(f"[GraphExporter] Exported GEXF to {filepath}")
        return filepath

    def export_graphml(self, filepath: str) -> str:
        """
        Export graph ke GraphML format (yEd, Cytoscape compatible).

        Returns:
            Filepath
        """
        data = self._get_graph_data()

        # Create GraphML XML
        root = ET.Element("graphml")
        root.set("xmlns", "http://graphml.graphdrawing.org/xmlns")

        # Define keys (attributes)
        all_node_props = set()
        for node in data["nodes"]:
            all_node_props.update(node["properties"].keys())

        for prop in all_node_props:
            key = ET.SubElement(root, "key")
            key.set("id", prop)
            key.set("for", "node")
            key.set("attr.name", prop)
            key.set("attr.type", "string")

        # Label key
        label_key = ET.SubElement(root, "key")
        label_key.set("id", "label")
        label_key.set("for", "node")
        label_key.set("attr.name", "label")
        label_key.set("attr.type", "string")

        # Edge label key
        edge_label_key = ET.SubElement(root, "key")
        edge_label_key.set("id", "edgelabel")
        edge_label_key.set("for", "edge")
        edge_label_key.set("attr.name", "label")
        edge_label_key.set("attr.type", "string")

        graph_elem = ET.SubElement(root, "graph")
        graph_elem.set("id", "osint")
        graph_elem.set("edgedefault", "directed")

        # Nodes
        for node in data["nodes"]:
            n = ET.SubElement(graph_elem, "node")
            n.set("id", str(node["id"]))

            # Label
            d_label = ET.SubElement(n, "data")
            d_label.set("key", "label")
            d_label.text = node["label"]

            # Properties
            for key, value in node["properties"].items():
                d = ET.SubElement(n, "data")
                d.set("key", key)
                d.text = str(value) if value is not None else ""

        # Edges
        for i, rel in enumerate(data["relationships"]):
            e = ET.SubElement(graph_elem, "edge")
            e.set("id", str(i))
            e.set("source", str(rel["from"]))
            e.set("target", str(rel["to"]))

            d = ET.SubElement(e, "data")
            d.set("key", "edgelabel")
            d.text = rel["type"]

        tree = ET.ElementTree(root)
        tree.write(filepath, encoding="utf-8", xml_declaration=True)

        logger.info(f"[GraphExporter] Exported GraphML to {filepath}")
        return filepath

    def export_d3_json(self, filepath: str) -> str:
        """
        Export graph ke D3.js force-directed graph format.

        Returns:
            Filepath
        """
        data = self._get_graph_data()

        # Group nodes by label untuk color coding
        label_groups = {}
        for i, node in enumerate(data["nodes"]):
            label = node["label"]
            if label not in label_groups:
                label_groups[label] = len(label_groups)

        d3_data = {
            "nodes": [
                {
                    "id": node["id"],
                    "name": node["properties"].get("name", 
                           node["properties"].get("username",
                           node["properties"].get("email", node["id"]))),
                    "label": node["label"],
                    "group": label_groups.get(node["label"], 0),
                    "properties": node["properties"]
                }
                for node in data["nodes"]
            ],
            "links": [
                {
                    "source": rel["from"],
                    "target": rel["to"],
                    "type": rel["type"],
                    "value": 1
                }
                for rel in data["relationships"]
            ]
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(d3_data, f, indent=2, ensure_ascii=False)

        logger.info(f"[GraphExporter] Exported D3 JSON to {filepath}")
        return filepath

    def export_html(self, filepath: str, title: str = "OSINT Graph Visualization") -> str:
        """
        Export graph ke interactive HTML dengan D3.js embedded.

        Args:
            filepath: Output file path
            title: Page title

        Returns:
            Filepath
        """
        data = self._get_graph_data()

        # Group nodes by label untuk color coding
        label_groups = {}
        colors = [
            "#e74c3c", "#3498db", "#2ecc71", "#f39c12", "#9b59b6",
            "#1abc9c", "#e67e22", "#34495e", "#16a085", "#c0392b"
        ]

        for node in data["nodes"]:
            label = node["label"]
            if label not in label_groups:
                label_groups[label] = len(label_groups)

        d3_data = {
            "nodes": [
                {
                    "id": node["id"],
                    "name": node["properties"].get("name", 
                           node["properties"].get("username",
                           node["properties"].get("email", node["id"]))),
                    "label": node["label"],
                    "group": label_groups.get(node["label"], 0),
                    "color": colors[label_groups.get(node["label"], 0) % len(colors)],
                    "properties": node["properties"]
                }
                for node in data["nodes"]
            ],
            "links": [
                {
                    "source": rel["from"],
                    "target": rel["to"],
                    "type": rel["type"],
                    "value": 1
                }
                for rel in data["relationships"]
            ]
        }

        # Generate legend HTML
        legend_items = ""
        for label, idx in sorted(label_groups.items(), key=lambda x: x[1]):
            color = colors[idx % len(colors)]
            legend_items += f'''<div class="legend-item"><span class="legend-color" style="background:{color}"></span>{label}</div>'''

        html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f0f1a; color: #fff; overflow: hidden; }}
        #header {{ padding: 15px 25px; background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); border-bottom: 2px solid #e94560; }}
        #header h1 {{ font-size: 1.5rem; color: #e94560; }}
        #header .stats {{ font-size: 0.85rem; color: #888; margin-top: 5px; }}
        #graph {{ width: 100vw; height: calc(100vh - 80px); }}
        #sidebar {{ position: fixed; right: 0; top: 80px; width: 300px; height: calc(100vh - 80px); background: rgba(26, 26, 46, 0.95); border-left: 1px solid #333; padding: 20px; overflow-y: auto; transform: translateX(100%); transition: transform 0.3s; }}
        #sidebar.active {{ transform: translateX(0); }}
        #sidebar h3 {{ color: #e94560; margin-bottom: 15px; font-size: 1rem; }}
        #sidebar .prop-row {{ display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #333; font-size: 0.85rem; }}
        #sidebar .prop-key {{ color: #888; }}
        #sidebar .prop-value {{ color: #fff; max-width: 150px; word-break: break-all; }}
        #legend {{ position: fixed; left: 20px; bottom: 20px; background: rgba(26, 26, 46, 0.9); padding: 15px; border-radius: 8px; border: 1px solid #333; }}
        .legend-item {{ display: flex; align-items: center; margin: 5px 0; font-size: 0.8rem; }}
        .legend-color {{ width: 12px; height: 12px; border-radius: 50%; margin-right: 8px; }}
        #controls {{ position: fixed; left: 20px; top: 90px; display: flex; gap: 10px; }}
        .btn {{ background: rgba(233, 69, 96, 0.8); color: white; border: none; padding: 8px 15px; border-radius: 5px; cursor: pointer; font-size: 0.8rem; transition: background 0.2s; }}
        .btn:hover {{ background: rgba(233, 69, 96, 1); }}
        .tooltip {{ position: absolute; padding: 8px 12px; background: rgba(0,0,0,0.8); color: white; border-radius: 4px; font-size: 0.75rem; pointer-events: none; opacity: 0; transition: opacity 0.2s; z-index: 1000; }}
        .node {{ cursor: pointer; }}
        .link {{ stroke-opacity: 0.6; }}
    </style>
</head>
<body>
    <div id="header">
        <h1>🔍 {title}</h1>
        <div class="stats">Nodes: {len(data["nodes"])} | Edges: {len(data["relationships"])} | Generated: {datetime.now().strftime("%Y-%m-%d %H:%M")}</div>
    </div>

    <div id="controls">
        <button class="btn" onclick="resetZoom()">Reset Zoom</button>
        <button class="btn" onclick="togglePhysics()">Toggle Physics</button>
    </div>

    <svg id="graph"></svg>

    <div id="sidebar">
        <h3>📋 Node Details</h3>
        <div id="node-details">Click a node to view details</div>
    </div>

    <div id="legend">
        {legend_items}
    </div>

    <div class="tooltip" id="tooltip"></div>

    <script>
        const graphData = {json.dumps(d3_data, ensure_ascii=False)};

        const width = window.innerWidth;
        const height = window.innerHeight - 80;

        const svg = d3.select("#graph")
            .attr("width", width)
            .attr("height", height);

        const g = svg.append("g");

        // Zoom behavior
        const zoom = d3.zoom()
            .scaleExtent([0.1, 4])
            .on("zoom", (event) => g.attr("transform", event.transform));

        svg.call(zoom);

        // Force simulation
        const simulation = d3.forceSimulation(graphData.nodes)
            .force("link", d3.forceLink(graphData.links).id(d => d.id).distance(100))
            .force("charge", d3.forceManyBody().strength(-300))
            .force("center", d3.forceCenter(width / 2, height / 2))
            .force("collision", d3.forceCollide().radius(30));

        // Draw links
        const link = g.append("g")
            .selectAll("line")
            .data(graphData.links)
            .join("line")
            .attr("class", "link")
            .attr("stroke", "#555")
            .attr("stroke-width", 1.5);

        // Draw nodes
        const node = g.append("g")
            .selectAll("g")
            .data(graphData.nodes)
            .join("g")
            .attr("class", "node")
            .call(d3.drag()
                .on("start", dragstarted)
                .on("drag", dragged)
                .on("end", dragended));

        node.append("circle")
            .attr("r", d => d.label === "Person" ? 20 : 12)
            .attr("fill", d => d.color)
            .attr("stroke", "#fff")
            .attr("stroke-width", 2);

        node.append("text")
            .text(d => d.name.length > 15 ? d.name.substring(0, 15) + "..." : d.name)
            .attr("x", 18)
            .attr("y", 4)
            .attr("fill", "#fff")
            .attr("font-size", "10px")
            .style("pointer-events", "none");

        // Tooltip
        const tooltip = d3.select("#tooltip");

        node.on("mouseover", (event, d) => {{
            tooltip.style("opacity", 1)
                .html(`<strong>${d.name}</strong><br/>Type: ${d.label}`)
                .style("left", (event.pageX + 10) + "px")
                .style("top", (event.pageY - 10) + "px");
        }}).on("mouseout", () => {{
            tooltip.style("opacity", 0);
        }}).on("click", (event, d) => {{
            showDetails(d);
        }});

        function showDetails(d) {{
            const sidebar = document.getElementById("sidebar");
            const details = document.getElementById("node-details");

            let html = `<div class="prop-row"><span class="prop-key">ID</span><span class="prop-value">${d.id}</span></div>`;
            html += `<div class="prop-row"><span class="prop-key">Label</span><span class="prop-value">${d.label}</span></div>`;
            html += `<div class="prop-row"><span class="prop-key">Name</span><span class="prop-value">${d.name}</span></div>`;

            for (const [key, value] of Object.entries(d.properties)) {{
                if (key !== "name" && key !== "username" && key !== "email") {{
                    html += `<div class="prop-row"><span class="prop-key">${key}</span><span class="prop-value">${value}</span></div>`;
                }}
            }}

            details.innerHTML = html;
            sidebar.classList.add("active");
        }}

        function resetZoom() {{
            svg.transition().duration(750).call(zoom.transform, d3.zoomIdentity);
        }}

        let physicsEnabled = true;
        function togglePhysics() {{
            physicsEnabled = !physicsEnabled;
            if (physicsEnabled) {{
                simulation.alpha(1).restart();
            }} else {{
                simulation.stop();
            }}
        }}

        // Update positions
        simulation.on("tick", () => {{
            link
                .attr("x1", d => d.source.x)
                .attr("y1", d => d.source.y)
                .attr("x2", d => d.target.x)
                .attr("y2", d => d.target.y);

            node.attr("transform", d => `translate(${d.x},${d.y})`);
        }});

        function dragstarted(event, d) {{
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
        }}

        function dragged(event, d) {{
            d.fx = event.x;
            d.fy = event.y;
        }}

        function dragended(event, d) {{
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
        }}

        // Close sidebar when clicking outside
        document.addEventListener("click", (e) => {{
            if (!e.target.closest("#sidebar") && !e.target.closest(".node")) {{
                document.getElementById("sidebar").classList.remove("active");
            }}
        }});
    </script>
</body>
</html>'''

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_content)

        logger.info(f"[GraphExporter] Exported HTML to {filepath}")
        return filepath

    def export_pdf(self, filepath: str, title: str = "OSINT Graph Report") -> str:
        """
        Export graph ke PDF report menggunakan fpdf2.

        Args:
            filepath: Output file path
            title: Report title

        Returns:
            Filepath
        """
        try:
            from fpdf import FPDF
        except ImportError:
            logger.error("[GraphExporter] fpdf2 not installed. Install: pip install fpdf2")
            # Fallback: create placeholder
            with open(filepath.replace(".pdf", "_placeholder.txt"), "w") as f:
                f.write("PDF export requires fpdf2. Install: pip install fpdf2\n")
            return filepath.replace(".pdf", "_placeholder.txt")

        data = self._get_graph_data()
        stats = self.connector.get_stats()

        class PDF(FPDF):
            def header(self):
                self.set_font("Arial", "B", 16)
                self.set_text_color(233, 69, 96)
                self.cell(0, 10, title, ln=True, align="C")
                self.ln(5)

            def footer(self):
                self.set_y(-15)
                self.set_font("Arial", "I", 8)
                self.set_text_color(128)
                self.cell(0, 10, f"Page {self.page_no()}", align="C")

        pdf = PDF()
        pdf.add_page()
        pdf.set_auto_page_break(auto=True, margin=15)

        # Executive Summary
        pdf.set_font("Arial", "B", 14)
        pdf.set_text_color(26, 26, 46)
        pdf.cell(0, 10, "Executive Summary", ln=True)
        pdf.ln(2)

        pdf.set_font("Arial", "", 10)
        pdf.set_text_color(60)
        pdf.multi_cell(0, 6, 
            f"This report presents the OSINT investigation graph generated on {datetime.now().strftime('%Y-%m-%d %H:%M')}. "
            f"The graph contains {stats.get('total_nodes', 0)} nodes and {stats.get('total_relationships', 0)} relationships "
            f"across {len(stats.get('labels', []) if isinstance(stats.get('labels'), list) else []) if not self.connector.in_memory_mode else len(stats.get('node_labels', {}))} entity types."
        )
        pdf.ln(5)

        # Statistics
        pdf.set_font("Arial", "B", 12)
        pdf.set_text_color(26, 26, 46)
        pdf.cell(0, 10, "Graph Statistics", ln=True)
        pdf.ln(2)

        pdf.set_font("Arial", "", 10)
        pdf.set_text_color(60)

        stats_data = [
            ["Total Nodes", str(stats.get("total_nodes", 0))],
            ["Total Relationships", str(stats.get("total_relationships", 0))],
            ["Mode", stats.get("mode", "unknown")],
        ]

        if self.connector.in_memory_mode:
            for label, count in stats.get("node_labels", {}).items():
                stats_data.append([f"  {label}", str(count)])
        else:
            for label in stats.get("labels", []):
                stats_data.append([f"  {label}", "-"])

        # Draw stats table
        col_width = 90
        row_height = 8
        pdf.set_fill_color(240, 240, 245)

        for i, (key, value) in enumerate(stats_data):
            if i % 2 == 0:
                pdf.set_fill_color(240, 240, 245)
            else:
                pdf.set_fill_color(255, 255, 255)
            pdf.cell(col_width, row_height, f"  {key}", border=1, fill=True)
            pdf.cell(col_width, row_height, f"  {value}", border=1, fill=True, ln=True)

        pdf.ln(10)

        # Nodes section
        if len(data["nodes"]) > 0:
            pdf.add_page()
            pdf.set_font("Arial", "B", 14)
            pdf.set_text_color(26, 26, 46)
            pdf.cell(0, 10, "Nodes", ln=True)
            pdf.ln(2)

            pdf.set_font("Arial", "", 8)
            pdf.set_text_color(60)

            # Table header
            pdf.set_fill_color(233, 69, 96)
            pdf.set_text_color(255)
            pdf.cell(40, 8, "ID", border=1, fill=True)
            pdf.cell(30, 8, "Label", border=1, fill=True)
            pdf.cell(0, 8, "Name", border=1, fill=True, ln=True)

            pdf.set_text_color(60)
            for i, node in enumerate(data["nodes"][:50]):  # Limit to 50 nodes
                if i % 2 == 0:
                    pdf.set_fill_color(245, 245, 250)
                else:
                    pdf.set_fill_color(255, 255, 255)

                name = node["properties"].get("name", 
                     node["properties"].get("username",
                     node["properties"].get("email", node["id"])))

                pdf.cell(40, 6, str(node["id"])[:20], border=1, fill=True)
                pdf.cell(30, 6, node["label"], border=1, fill=True)
                pdf.cell(0, 6, str(name)[:40], border=1, fill=True, ln=True)

            if len(data["nodes"]) > 50:
                pdf.cell(0, 6, f"... and {len(data['nodes']) - 50} more nodes", ln=True, align="C")

        # Relationships section
        if len(data["relationships"]) > 0:
            pdf.add_page()
            pdf.set_font("Arial", "B", 14)
            pdf.set_text_color(26, 26, 46)
            pdf.cell(0, 10, "Relationships", ln=True)
            pdf.ln(2)

            pdf.set_font("Arial", "", 8)

            # Table header
            pdf.set_fill_color(233, 69, 96)
            pdf.set_text_color(255)
            pdf.cell(50, 8, "Source", border=1, fill=True)
            pdf.cell(30, 8, "Type", border=1, fill=True)
            pdf.cell(0, 8, "Target", border=1, fill=True, ln=True)

            pdf.set_text_color(60)
            for i, rel in enumerate(data["relationships"][:50]):
                if i % 2 == 0:
                    pdf.set_fill_color(245, 245, 250)
                else:
                    pdf.set_fill_color(255, 255, 255)

                pdf.cell(50, 6, str(rel["from"])[:25], border=1, fill=True)
                pdf.cell(30, 6, rel["type"], border=1, fill=True)
                pdf.cell(0, 6, str(rel["to"])[:25], border=1, fill=True, ln=True)

            if len(data["relationships"]) > 50:
                pdf.cell(0, 6, f"... and {len(data['relationships']) - 50} more relationships", ln=True, align="C")

        # Footer
        pdf.set_y(-30)
        pdf.set_font("Arial", "I", 8)
        pdf.set_text_color(128)
        pdf.cell(0, 10, f"Generated by OSINT Intelligence Platform v4.0 | {datetime.now().isoformat()}", align="C")

        pdf.output(filepath)
        logger.info(f"[GraphExporter] Exported PDF to {filepath}")
        return filepath

    def _get_graph_data(self, node_labels: Optional[List[str]] = None,
                        rel_types: Optional[List[str]] = None) -> Dict[str, List]:
        """
        Get graph data dari connector.

        Returns:
            Dict dengan "nodes" dan "relationships" lists
        """
        if self.connector.in_memory_mode:
            nodes = [n.to_dict() for n in self.connector._nodes.values()]
            relationships = [r.to_dict() for r in self.connector._relationships.values()]
        else:
            # Query dari Neo4j
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

        # Filter jika diminta
        if node_labels:
            nodes = [n for n in nodes if n["label"] in node_labels]
            allowed_ids = {n["id"] for n in nodes}
            relationships = [r for r in relationships 
                           if r["from"] in allowed_ids and r["to"] in allowed_ids]

        if rel_types:
            relationships = [r for r in relationships if r["type"] in rel_types]

        return {"nodes": nodes, "relationships": relationships}

    def get_summary(self) -> Dict[str, Any]:
        """Get export summary."""
        stats = self.connector.get_stats()
        return {
            "total_nodes": stats.get("total_nodes", 0),
            "total_relationships": stats.get("total_relationships", 0),
            "mode": stats.get("mode", "unknown"),
            "export_formats": ["json", "cypher", "csv", "gexf", "graphml", "d3_json", "html", "pdf"]
        }