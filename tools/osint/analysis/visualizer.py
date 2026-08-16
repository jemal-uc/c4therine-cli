"""
visualizer.py - Graph & Timeline Visualization Module
Part of OSINT Intelligence Platform v4

Features:
- NetworkX graph analysis (centrality, shortest path, clustering)
- Matplotlib static visualization
- Plotly interactive visualization
- Timeline visualization
- Community detection visualization
- Export ke PNG, SVG, HTML
"""

import os
import json
import logging
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass
from datetime import datetime
from collections import defaultdict

import numpy as np

# Network analysis
import networkx as nx
from networkx.algorithms import community

# Visualization
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch
import matplotlib.colors as mcolors

logger = logging.getLogger("osint.visualizer")


@dataclass
class VisualizationConfig:
    """Configuration untuk visualisasi."""
    width: int = 1200
    height: int = 800
    dpi: int = 150
    node_size: int = 300
    font_size: int = 8
    edge_width: float = 1.0
    layout: str = "spring"  # spring, circular, kamada_kawai, shell
    color_scheme: str = "category"  # category, centrality, community
    show_labels: bool = True
    show_legend: bool = True
    dark_mode: bool = True


class GraphVisualizer:
    """
    Visualize OSINT graph menggunakan NetworkX dan Matplotlib.
    """

    # Color palette untuk entity types
    ENTITY_COLORS = {
        "Person": "#e74c3c",
        "Username": "#3498db",
        "Email": "#2ecc71",
        "Domain": "#f39c12",
        "Website": "#9b59b6",
        "Organization": "#1abc9c",
        "Location": "#e67e22",
        "Phone": "#34495e",
        "IPAddress": "#16a085",
        "Certificate": "#c0392b",
        "Subdomain": "#8e44ad",
        "Breach": "#d35400",
        "GitHubRepo": "#2c3e50",
        "GitHubUser": "#27ae60",
        "Face": "#f1c40f",
        "Image": "#95a5a6",
    }

    # Relationship colors
    RELATIONSHIP_COLORS = {
        "USES": "#3498db",
        "HAS_EMAIL": "#2ecc71",
        "OWNS": "#f39c12",
        "STUDIED_AT": "#9b59b6",
        "WORKS_AT": "#1abc9c",
        "LOCATED_IN": "#e67e22",
        "HAS_PHONE": "#34495e",
        "RESOLVES_TO": "#16a085",
        "CONTAINS": "#8e44ad",
        "LINKS_TO": "#d35400",
        "ALIAS_OF": "#2c3e50",
        "ASSOCIATED_WITH": "#7f8c8d",
        "FOUND_IN": "#e74c3c",
        "COMMITTED_TO": "#27ae60",
        "MATCHES": "#f1c40f",
    }

    def __init__(self, config: Optional[VisualizationConfig] = None):
        """
        Initialize visualizer.

        Args:
            config: VisualizationConfig instance
        """
        self.config = config or VisualizationConfig()
        self._setup_style()

    def _setup_style(self):
        """Setup matplotlib style."""
        if self.config.dark_mode:
            plt.style.use("dark_background")
            self.bg_color = "#0f0f1a"
            self.text_color = "#ffffff"
            self.grid_color = "#333344"
        else:
            plt.style.use("default")
            self.bg_color = "#ffffff"
            self.text_color = "#000000"
            self.grid_color = "#dddddd"

    def build_networkx_graph(self, nodes: List[Dict], relationships: List[Dict]) -> nx.DiGraph:
        """
        Build NetworkX graph dari OSINT data.

        Args:
            nodes: List of node dictionaries
            relationships: List of relationship dictionaries

        Returns:
            NetworkX DiGraph
        """
        G = nx.DiGraph()

        # Add nodes
        for node in nodes:
            node_id = str(node["id"])
            label = node.get("label", "Unknown")
            props = node.get("properties", {})

            display_name = (
                props.get("name") or
                props.get("username") or
                props.get("email") or
                props.get("url") or
                node_id
            )

            G.add_node(
                node_id,
                label=label,
                display_name=display_name,
                color=self.ENTITY_COLORS.get(label, "#95a5a6"),
                **props
            )

        # Add edges
        for rel in relationships:
            source = str(rel["from"])
            target = str(rel["to"])
            rel_type = rel.get("type", "UNKNOWN")

            if source in G and target in G:
                G.add_edge(
                    source, target,
                    type=rel_type,
                    color=self.RELATIONSHIP_COLORS.get(rel_type, "#7f8c8d"),
                    **rel.get("properties", {})
                )

        return G

    def calculate_layout(self, G: nx.DiGraph) -> Dict[str, Tuple[float, float]]:
        """
        Calculate node positions berdasarkan layout type.

        Args:
            G: NetworkX graph

        Returns:
            Dictionary mapping node ID ke (x, y) position
        """
        if self.config.layout == "spring":
            return nx.spring_layout(G, k=2/np.sqrt(len(G.nodes())+1), iterations=50, seed=42)
        elif self.config.layout == "circular":
            return nx.circular_layout(G)
        elif self.config.layout == "kamada_kawai":
            return nx.kamada_kawai_layout(G)
        elif self.config.layout == "shell":
            # Group nodes by label untuk shell layout
            labels = defaultdict(list)
            for node, data in G.nodes(data=True):
                labels[data.get("label", "Unknown")].append(node)

            shells = [labels[label] for label in sorted(labels.keys())]
            if not shells:
                shells = [list(G.nodes())]

            return nx.shell_layout(G, shells)
        elif self.config.layout == "hierarchical":
            return nx.multipartite_layout(G, subset_key="layer")
        else:
            return nx.spring_layout(G, seed=42)

    def visualize(self, nodes: List[Dict], relationships: List[Dict],
                  title: str = "OSINT Investigation Graph",
                  output_path: Optional[str] = None,
                  show_plot: bool = False) -> Optional[str]:
        """
        Create static visualization menggunakan Matplotlib.

        Args:
            nodes: List of node dictionaries
            relationships: List of relationship dictionaries
            title: Graph title
            output_path: Path untuk save image (None = tidak save)
            show_plot: Whether to show plot window

        Returns:
            Output path jika disave, None otherwise
        """
        # Build graph
        G = self.build_networkx_graph(nodes, relationships)

        if len(G.nodes()) == 0:
            logger.warning("[Visualizer] No nodes to visualize")
            return None

        # Calculate layout
        pos = self.calculate_layout(G)

        # Create figure
        fig, ax = plt.subplots(figsize=(self.config.width/100, self.config.height/100), 
                               dpi=self.config.dpi)
        fig.patch.set_facecolor(self.bg_color)
        ax.set_facecolor(self.bg_color)

        # Calculate node sizes berdasarkan degree centrality
        if len(G.nodes()) > 1:
            centrality = nx.degree_centrality(G)
            node_sizes = [
                self.config.node_size * (1 + centrality.get(node, 0) * 5)
                for node in G.nodes()
            ]
        else:
            node_sizes = [self.config.node_size] * len(G.nodes())

        # Node colors
        node_colors = [data["color"] for _, data in G.nodes(data=True)]

        # Edge colors
        edge_colors = [data["color"] for _, _, data in G.edges(data=True)]

        # Draw edges
        nx.draw_networkx_edges(
            G, pos,
            edge_color=edge_colors,
            width=self.config.edge_width,
            alpha=0.6,
            arrows=True,
            arrowsize=15,
            connectionstyle="arc3,rad=0.1",
            ax=ax
        )

        # Draw nodes
        nx.draw_networkx_nodes(
            G, pos,
            node_color=node_colors,
            node_size=node_sizes,
            alpha=0.9,
            edgecolors="white",
            linewidths=2,
            ax=ax
        )

        # Draw labels
        if self.config.show_labels:
            labels = {
                node: data["display_name"][:20]
                for node, data in G.nodes(data=True)
            }
            nx.draw_networkx_labels(
                G, pos,
                labels=labels,
                font_size=self.config.font_size,
                font_color="white" if self.config.dark_mode else "black",
                font_weight="bold",
                ax=ax
            )

        # Add title
        ax.set_title(
            title,
            fontsize=16,
            fontweight="bold",
            color=self.text_color,
            pad=20
        )

        # Add legend
        if self.config.show_legend:
            legend_elements = [
                mpatches.Patch(color=color, label=label)
                for label, color in sorted(self.ENTITY_COLORS.items())
                if any(data.get("label") == label for _, data in G.nodes(data=True))
            ]

            if legend_elements:
                ax.legend(
                    handles=legend_elements,
                    loc="upper left",
                    bbox_to_anchor=(1.02, 1),
                    fontsize=8,
                    facecolor=self.bg_color,
                    edgecolor=self.grid_color,
                    labelcolor=self.text_color
                )

        # Add stats text
        stats_text = f"Nodes: {len(G.nodes())} | Edges: {len(G.edges())}"
        ax.text(
            0.02, 0.02, stats_text,
            transform=ax.transAxes,
            fontsize=8,
            color=self.text_color,
            alpha=0.7,
            verticalalignment="bottom"
        )

        # Remove axes
        ax.set_axis_off()

        # Adjust layout
        plt.tight_layout()

        # Save jika diminta
        if output_path:
            plt.savefig(
                output_path,
                dpi=self.config.dpi,
                bbox_inches="tight",
                facecolor=self.bg_color,
                edgecolor="none"
            )
            logger.info(f"[Visualizer] Saved visualization to {output_path}")

        # Show plot
        if show_plot:
            plt.show()
        else:
            plt.close()

        return output_path

    def visualize_communities(self, nodes: List[Dict], relationships: List[Dict],
                               title: str = "Community Detection",
                               output_path: Optional[str] = None) -> Optional[str]:
        """
        Visualize graph dengan community detection.

        Args:
            nodes: List of node dictionaries
            relationships: List of relationship dictionaries
            title: Graph title
            output_path: Path untuk save image

        Returns:
            Output path jika disave
        """
        G = self.build_networkx_graph(nodes, relationships)

        if len(G.nodes()) < 3:
            logger.warning("[Visualizer] Need at least 3 nodes for community detection")
            return None

        # Convert to undirected untuk community detection
        G_undirected = G.to_undirected()

        # Detect communities
        try:
            communities = community.greedy_modularity_communities(G_undirected)
        except:
            logger.warning("[Visualizer] Community detection failed")
            return None

        # Assign community colors
        community_colors = plt.cm.Set3(np.linspace(0, 1, len(communities)))
        node_community = {}

        for i, comm in enumerate(communities):
            for node in comm:
                node_community[node] = i

        # Calculate layout
        pos = self.calculate_layout(G)

        # Create figure
        fig, ax = plt.subplots(figsize=(self.config.width/100, self.config.height/100),
                               dpi=self.config.dpi)
        fig.patch.set_facecolor(self.bg_color)
        ax.set_facecolor(self.bg_color)

        # Draw edges
        nx.draw_networkx_edges(G, pos, alpha=0.3, edge_color="gray", ax=ax)

        # Draw nodes dengan community colors
        for i, comm in enumerate(communities):
            comm_nodes = list(comm)
            nx.draw_networkx_nodes(
                G, pos,
                nodelist=comm_nodes,
                node_color=[community_colors[i]],
                node_size=300,
                alpha=0.8,
                edgecolors="white",
                linewidths=2,
                ax=ax,
                label=f"Community {i+1} ({len(comm_nodes)} nodes)"
            )

        # Draw labels
        labels = {node: data["display_name"][:15] for node, data in G.nodes(data=True)}
        nx.draw_networkx_labels(G, pos, labels, font_size=7, font_color="white", ax=ax)

        ax.set_title(title, fontsize=16, fontweight="bold", color=self.text_color, pad=20)
        ax.legend(loc="upper left", bbox_to_anchor=(1.02, 1), fontsize=8,
                 facecolor=self.bg_color, edgecolor=self.grid_color, labelcolor=self.text_color)

        ax.set_axis_off()
        plt.tight_layout()

        if output_path:
            plt.savefig(output_path, dpi=self.config.dpi, bbox_inches="tight",
                       facecolor=self.bg_color)
            logger.info(f"[Visualizer] Saved community visualization to {output_path}")

        plt.close()
        return output_path

    def visualize_centrality(self, nodes: List[Dict], relationships: List[Dict],
                             centrality_type: str = "degree",
                             title: str = "Centrality Analysis",
                             output_path: Optional[str] = None) -> Optional[str]:
        """
        Visualize graph dengan centrality analysis.

        Args:
            nodes: List of node dictionaries
            relationships: List of relationship dictionaries
            centrality_type: Type of centrality (degree, betweenness, closeness, eigenvector)
            title: Graph title
            output_path: Path untuk save image

        Returns:
            Output path jika disave
        """
        G = self.build_networkx_graph(nodes, relationships)

        if len(G.nodes()) < 2:
            logger.warning("[Visualizer] Need at least 2 nodes for centrality")
            return None

        # Calculate centrality
        G_undirected = G.to_undirected()

        if centrality_type == "degree":
            centrality = nx.degree_centrality(G_undirected)
        elif centrality_type == "betweenness":
            centrality = nx.betweenness_centrality(G_undirected)
        elif centrality_type == "closeness":
            centrality = nx.closeness_centrality(G_undirected)
        elif centrality_type == "eigenvector":
            try:
                centrality = nx.eigenvector_centrality(G_undirected, max_iter=1000)
            except:
                centrality = nx.degree_centrality(G_undirected)
        else:
            centrality = nx.degree_centrality(G_undirected)

        # Calculate layout
        pos = self.calculate_layout(G)

        # Create figure
        fig, ax = plt.subplots(figsize=(self.config.width/100, self.config.height/100),
                               dpi=self.config.dpi)
        fig.patch.set_facecolor(self.bg_color)
        ax.set_facecolor(self.bg_color)

        # Node sizes dan colors berdasarkan centrality
        centrality_values = [centrality.get(node, 0) for node in G.nodes()]
        node_sizes = [self.config.node_size * (1 + c * 10) for c in centrality_values]

        # Color map
        cmap = plt.cm.plasma
        norm = plt.Normalize(vmin=min(centrality_values), vmax=max(centrality_values))
        node_colors = [cmap(norm(c)) for c in centrality_values]

        # Draw edges
        nx.draw_networkx_edges(G, pos, alpha=0.3, edge_color="gray", ax=ax)

        # Draw nodes
        nx.draw_networkx_nodes(
            G, pos,
            node_color=node_colors,
            node_size=node_sizes,
            alpha=0.9,
            edgecolors="white",
            linewidths=2,
            ax=ax
        )

        # Draw labels
        labels = {node: data["display_name"][:15] for node, data in G.nodes(data=True)}
        nx.draw_networkx_labels(G, pos, labels, font_size=7, font_color="white", ax=ax)

        # Add colorbar
        sm = plt.cm.ScalarMappable(cmap=cmap, norm=norm)
        sm.set_array([])
        cbar = plt.colorbar(sm, ax=ax, shrink=0.6, pad=0.02)
        cbar.set_label(f"{centrality_type.title()} Centrality", color=self.text_color)
        cbar.ax.yaxis.set_tick_params(color=self.text_color)
        plt.setp(plt.getp(cbar.ax.axes, "yticklabels"), color=self.text_color)

        ax.set_title(title, fontsize=16, fontweight="bold", color=self.text_color, pad=20)
        ax.set_axis_off()
        plt.tight_layout()

        if output_path:
            plt.savefig(output_path, dpi=self.config.dpi, bbox_inches="tight",
                       facecolor=self.bg_color)
            logger.info(f"[Visualizer] Saved centrality visualization to {output_path}")

        plt.close()
        return output_path

    def analyze_graph(self, nodes: List[Dict], relationships: List[Dict]) -> Dict[str, Any]:
        """
        Perform graph analysis dan return metrics.

        Args:
            nodes: List of node dictionaries
            relationships: List of relationship dictionaries

        Returns:
            Dictionary dengan graph metrics
        """
        G = self.build_networkx_graph(nodes, relationships)
        G_undirected = G.to_undirected()

        metrics = {
            "basic": {
                "nodes": len(G.nodes()),
                "edges": len(G.edges()),
                "density": nx.density(G) if len(G.nodes()) > 1 else 0,
                "is_connected": nx.is_connected(G_undirected) if len(G.nodes()) > 0 else False,
            },
            "centrality": {},
            "communities": {},
            "paths": {}
        }

        if len(G.nodes()) > 1:
            # Centrality metrics
            metrics["centrality"]["degree"] = dict(nx.degree_centrality(G_undirected))

            if len(G.nodes()) > 2:
                try:
                    metrics["centrality"]["betweenness"] = dict(nx.betweenness_centrality(G_undirected))
                    metrics["centrality"]["closeness"] = dict(nx.closeness_centrality(G_undirected))
                except:
                    pass

            # Community detection
            try:
                communities = community.greedy_modularity_communities(G_undirected)
                metrics["communities"]["count"] = len(communities)
                metrics["communities"]["sizes"] = [len(c) for c in communities]
                metrics["communities"]["modularity"] = community.modularity(
                    G_undirected, communities
                )
            except:
                pass

            # Shortest paths
            try:
                if nx.is_connected(G_undirected):
                    metrics["paths"]["diameter"] = nx.diameter(G_undirected)
                    metrics["paths"]["average_shortest_path"] = nx.average_shortest_path_length(G_undirected)
            except:
                pass

        # Top nodes by degree
        if metrics["centrality"].get("degree"):
            top_degree = sorted(
                metrics["centrality"]["degree"].items(),
                key=lambda x: x[1],
                reverse=True
            )[:5]
            metrics["top_nodes_by_degree"] = [
                {"node": node, "centrality": score}
                for node, score in top_degree
            ]

        return metrics

    def export_interactive_html(self, nodes: List[Dict], relationships: List[Dict],
                                 output_path: str, title: str = "OSINT Graph") -> str:
        """
        Export interactive visualization ke HTML menggunakan D3.js.
        (Wrapper untuk graph_exporter.export_html)

        Args:
            nodes: List of node dictionaries
            relationships: List of relationship dictionaries
            output_path: Output file path
            title: Graph title

        Returns:
            Output path
        """
        # Import graph_exporter untuk reuse HTML generation
        from ..graph.graph_exporter import GraphExporter

        # Create temporary connector dengan data
        from ..graph.neo4j_connector import Neo4jConnector
        connector = Neo4jConnector()

        for node in nodes:
            connector.create_node(node["label"], node["properties"])

        for rel in relationships:
            connector.create_relationship(rel["from"], rel["to"], rel["type"])

        exporter = GraphExporter(connector)
        return exporter.export_html(output_path, title)


class TimelineVisualizer:
    """
    Visualize timeline dari investigation events.
    """

    def __init__(self, config: Optional[VisualizationConfig] = None):
        self.config = config or VisualizationConfig()
        self._setup_style()

    def _setup_style(self):
        if self.config.dark_mode:
            plt.style.use("dark_background")
            self.bg_color = "#0f0f1a"
            self.text_color = "#ffffff"
        else:
            plt.style.use("default")
            self.bg_color = "#ffffff"
            self.text_color = "#000000"

    def visualize(self, events: List[Dict[str, Any]],
                  title: str = "Investigation Timeline",
                  output_path: Optional[str] = None) -> Optional[str]:
        """
        Create timeline visualization.

        Args:
            events: List of event dictionaries dengan keys: timestamp, event, description, category
            title: Timeline title
            output_path: Path untuk save image

        Returns:
            Output path jika disave
        """
        if not events:
            logger.warning("[TimelineVisualizer] No events to visualize")
            return None

        # Sort events by timestamp
        sorted_events = sorted(events, key=lambda x: x.get("timestamp", ""))

        # Create figure
        fig, ax = plt.subplots(figsize=(self.config.width/100, self.config.height/100),
                               dpi=self.config.dpi)
        fig.patch.set_facecolor(self.bg_color)
        ax.set_facecolor(self.bg_color)

        # Colors by category
        category_colors = {
            "discovery": "#3498db",
            "breach": "#e74c3c",
            "social": "#2ecc71",
            "domain": "#f39c12",
            "network": "#9b59b6",
            "default": "#95a5a6"
        }

        # Plot events
        y_positions = range(len(sorted_events))

        for i, event in enumerate(sorted_events):
            category = event.get("category", "default")
            color = category_colors.get(category, category_colors["default"])

            # Draw event marker
            ax.scatter(0, i, s=200, c=color, zorder=5, edgecolors="white", linewidths=2)

            # Draw event text
            event_text = event.get("event", "Unknown")
            description = event.get("description", "")
            timestamp = event.get("timestamp", "")

            ax.text(0.02, i, f"{timestamp} | {event_text}", 
                   va="center", ha="left", fontsize=9, color=self.text_color,
                   fontweight="bold")

            if description:
                ax.text(0.02, i - 0.3, description[:80],
                       va="center", ha="left", fontsize=7, color="gray")

        # Draw connecting line
        ax.axvline(x=0, color="gray", alpha=0.3, linewidth=2, zorder=1)

        # Styling
        ax.set_yticks([])
        ax.set_xticks([])
        ax.set_xlim(-0.1, 1)
        ax.set_ylim(-1, len(sorted_events))

        # Remove spines
        for spine in ax.spines.values():
            spine.set_visible(False)

        ax.set_title(title, fontsize=16, fontweight="bold", 
                    color=self.text_color, pad=20)

        # Add legend
        legend_elements = [
            mpatches.Patch(color=color, label=cat.title())
            for cat, color in category_colors.items()
            if cat != "default"
        ]
        ax.legend(handles=legend_elements, loc="upper right", fontsize=8,
                 facecolor=self.bg_color, edgecolor="gray", labelcolor=self.text_color)

        plt.tight_layout()

        if output_path:
            plt.savefig(output_path, dpi=self.config.dpi, bbox_inches="tight",
                       facecolor=self.bg_color)
            logger.info(f"[TimelineVisualizer] Saved timeline to {output_path}")

        plt.close()
        return output_path


# ============== CONVENIENCE FUNCTIONS ==============

def quick_visualize(nodes: List[Dict], relationships: List[Dict],
                     output_path: str, title: str = "OSINT Graph") -> str:
    """Quick graph visualization."""
    viz = GraphVisualizer()
    return viz.visualize(nodes, relationships, title, output_path) or output_path


def quick_timeline(events: List[Dict], output_path: str, 
                   title: str = "Timeline") -> str:
    """Quick timeline visualization."""
    viz = TimelineVisualizer()
    return viz.visualize(events, title, output_path) or output_path


# ============== MAIN ==============

if __name__ == "__main__":
    print("=" * 60)
    print("Graph Visualizer Module")
    print("=" * 60)

    # Demo data
    demo_nodes = [
        {"id": "person_1", "label": "Person", "properties": {"name": "John Doe"}},
        {"id": "email_1", "label": "Email", "properties": {"email": "john@example.com"}},
        {"id": "username_1", "label": "Username", "properties": {"username": "johndoe", "platform": "twitter"}},
        {"id": "domain_1", "label": "Domain", "properties": {"name": "example.com"}},
        {"id": "website_1", "label": "Website", "properties": {"url": "https://example.com"}},
    ]

    demo_relationships = [
        {"from": "person_1", "to": "email_1", "type": "HAS_EMAIL"},
        {"from": "person_1", "to": "username_1", "type": "USES"},
        {"from": "person_1", "to": "website_1", "type": "OWNS"},
        {"from": "website_1", "to": "domain_1", "type": "RESOLVES_TO"},
    ]

    viz = GraphVisualizer()

    print("\n[*] Analyzing graph...")
    metrics = viz.analyze_graph(demo_nodes, demo_relationships)
    print(f"[+] Metrics: {json.dumps(metrics, indent=2, default=str)}")

    print("\n[*] Creating basic visualization...")
    viz.visualize(demo_nodes, demo_relationships, 
                  title="Demo OSINT Graph",
                  output_path="/mnt/agents/output/demo_graph.png")
    print("[+] Saved: /mnt/agents/output/demo_graph.png")

    print("\n[*] Creating community visualization...")
    viz.visualize_communities(demo_nodes, demo_relationships,
                               output_path="/mnt/agents/output/demo_communities.png")
    print("[+] Saved: /mnt/agents/output/demo_communities.png")

    print("\n[*] Creating centrality visualization...")
    viz.visualize_centrality(demo_nodes, demo_relationships,
                              output_path="/mnt/agents/output/demo_centrality.png")
    print("[+] Saved: /mnt/agents/output/demo_centrality.png")

    # Demo timeline
    timeline_events = [
        {"timestamp": "2024-01-01", "event": "First discovery", "description": "Found on social media", "category": "discovery"},
        {"timestamp": "2024-01-15", "event": "Breach found", "description": "Email in breach database", "category": "breach"},
        {"timestamp": "2024-02-01", "event": "Domain registered", "description": "example.com registered", "category": "domain"},
    ]

    print("\n[*] Creating timeline visualization...")
    timeline_viz = TimelineVisualizer()
    timeline_viz.visualize(timeline_events, title="Demo Timeline",
                          output_path="/mnt/agents/output/demo_timeline.png")
    print("[+] Saved: /mnt/agents/output/demo_timeline.png")

    print("\n" + "=" * 60)
    print("Visualization complete!")
    print("=" * 60)