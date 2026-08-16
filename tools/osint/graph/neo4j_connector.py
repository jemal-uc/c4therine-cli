"""
neo4j_connector.py - Neo4j Connector dengan In-Memory Fallback
Part of OSINT Intelligence Platform v4
"""

import json
import logging
import hashlib
from typing import Dict, List, Optional, Set, Tuple, Any, Union
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger("osint.neo4j")

@dataclass
class Neo4jConfig:
    uri: str = "bolt://localhost:7687"
    username: str = "neo4j"
    password: str = "password"
    database: str = "neo4j"
    
    def to_dict(self) -> dict:
        return {
            "uri": self.uri,
            "username": self.username,
            "database": self.database
        }

@dataclass
class Node:
    """Graph node representation."""
    id: str
    label: str
    properties: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "label": self.label,
            "properties": self.properties
        }


@dataclass
class Relationship:
    """Graph relationship representation."""
    id: str
    from_node: str
    to_node: str
    rel_type: str
    properties: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "from": self.from_node,
            "to": self.to_node,
            "type": self.rel_type,
            "properties": self.properties
        }


class GraphSchema:
    """
    Neo4j schema definition untuk OSINT graph.
    Defines node labels, relationship types, dan constraints.
    """

    # Node labels
    NODE_LABELS = {
        "Person": {
            "properties": ["name", "normalized_name", "aliases", "confidence_score"],
            "constraints": ["normalized_name"]
        },
        "Username": {
            "properties": ["username", "platform", "url", "confidence"],
            "constraints": ["username", "platform"]
        },
        "Email": {
            "properties": ["email", "domain", "gravatar_hash", "confidence"],
            "constraints": ["email"]
        },
        "Domain": {
            "properties": ["name", "tld", "registrar", "creation_date", "expiration_date"],
            "constraints": ["name"]
        },
        "Subdomain": {
            "properties": ["name", "parent_domain", "is_resolvable"],
            "constraints": ["name"]
        },
        "Website": {
            "properties": ["url", "title", "technologies", "confidence"],
            "constraints": ["url"]
        },
        "Organization": {
            "properties": ["name", "type", "industry", "location"],
            "constraints": ["name"]
        },
        "Location": {
            "properties": ["name", "country", "city", "coordinates"],
            "constraints": ["name"]
        },
        "Phone": {
            "properties": ["number", "country_code", "type"],
            "constraints": ["number"]
        },
        "IPAddress": {
            "properties": ["address", "version", "asn", "isp"],
            "constraints": ["address"]
        },
        "Certificate": {
            "properties": ["serial", "issuer", "subject", "not_before", "not_after"],
            "constraints": ["serial"]
        },
        "Breach": {
            "properties": ["name", "date", "source", "description"],
            "constraints": ["name"]
        },
        "GitHubRepo": {
            "properties": ["name", "owner", "url", "language"],
            "constraints": ["name", "owner"]
        },
        "GitHubUser": {
            "properties": ["username", "url", "followers"],
            "constraints": ["username"]
        },
        "Face": {
            "properties": ["face_id", "person_id", "confidence"],
            "constraints": ["face_id"]
        },
        "Image": {
            "properties": ["file_hash", "filename", "format", "dimensions"],
            "constraints": ["file_hash"]
        },
    }

    # Relationship types
    RELATIONSHIP_TYPES = [
        "USES",              # Person -> Username
        "HAS_EMAIL",         # Person -> Email
        "OWNS",              # Person -> Website/Domain
        "STUDIED_AT",        # Person -> Organization
        "WORKS_AT",          # Person -> Organization
        "LOCATED_IN",        # Person -> Location
        "HAS_PHONE",         # Person -> Phone
        "HAS_FACE",          # Person -> Face
        "HAS_IMAGE",         # Person -> Image
        "RESOLVES_TO",       # Domain -> IPAddress
        "ISSUED_BY",         # Certificate -> Organization
        "CONTAINS",          # Domain -> Subdomain
        "LINKS_TO",          # Website -> Website
        "ALIAS_OF",          # Username -> Username
        "ASSOCIATED_WITH",   # Generic association
        "FOUND_IN",          # Email -> Breach
        "COMMITTED_TO",      # GitHubUser -> GitHubRepo
        "FOLLOWS",           # GitHubUser -> GitHubUser
        "MATCHES",           # Face -> Face
        "APPEARS_IN",        # Face -> Image
    ]

    @classmethod
    def get_create_node_cypher(cls, label: str, properties: Dict[str, Any]) -> str:
        """Generate Cypher untuk create node."""
        props_str = ", ".join([f"{k}: ${k}" for k in properties.keys()])
        return f"CREATE (n:{label} {{ {props_str} }}) RETURN n"

    @classmethod
    def get_merge_node_cypher(cls, label: str, match_props: Dict[str, Any], 
                               set_props: Optional[Dict[str, Any]] = None) -> str:
        """Generate Cypher untuk merge node (create if not exists)."""
        match_str = ", ".join([f"{k}: ${k}" for k in match_props.keys()])

        cypher = f"MERGE (n:{label} {{ {match_str} }})"

        if set_props:
            set_items = ", ".join([f"n.{k} = ${k}" for k in set_props.keys()])
            cypher += f" SET {set_items}"

        cypher += " RETURN n"
        return cypher

    @classmethod
    def get_merge_relationship_cypher(cls, from_label: str, from_props: Dict[str, Any],
                                         to_label: str, to_props: Dict[str, Any],
                                         rel_type: str, rel_props: Optional[Dict[str, Any]] = None) -> str:
        """Generate Cypher untuk merge relationship."""
        from_match = ", ".join([f"{k}: ${k}_from" for k in from_props.keys()])
        to_match = ", ".join([f"{k}: ${k}_to" for k in to_props.keys()])

        cypher = (
            f"MATCH (a:{from_label} {{ {from_match} }}) "
            f"MATCH (b:{to_label} {{ {to_match} }}) "
            f"MERGE (a)-[r:{rel_type}]->(b)"
        )

        if rel_props:
            set_items = ", ".join([f"r.{k} = ${k}_rel" for k in rel_props.keys()])
            cypher += f" SET {set_items}"

        cypher += " RETURN r"
        return cypher


class Neo4jConnector:
    """
    Neo4j database connector dengan in-memory fallback.
    """

    def __init__(self, 
                 uri: Optional[str] = None,
                 username: Optional[str] = None,
                 password: Optional[str] = None,
                 database: str = "neo4j"):
        """
        Initialize Neo4j connector.

        Args:
            uri: Neo4j bolt URI (e.g., "bolt://localhost:7687")
            username: Neo4j username
            password: Neo4j password
            database: Database name
        """
        self.uri = uri or "bolt://localhost:7687"
        self.username = username or "neo4j"
        self.password = password or "password"
        self.database = database

        self.driver = None
        self._in_memory_mode = True

        # In-memory storage (fallback)
        self._nodes: Dict[str, Node] = {}
        self._relationships: Dict[str, Relationship] = {}
        self._node_index: Dict[str, Set[str]] = {}  # label -> node_ids

        self._connect()

    def _connect(self):
        """Connect ke Neo4j atau fallback ke in-memory."""
        try:
            from neo4j import GraphDatabase
            self.driver = GraphDatabase.driver(
                self.uri,
                auth=(self.username, self.password)
            )
            self.driver.verify_connectivity()
            self._in_memory_mode = False
            logger.info(f"[Neo4j] Connected to {self.uri}")
        except ImportError:
            logger.warning("[Neo4j] neo4j package not installed. Using in-memory mode.")
            self._in_memory_mode = True
        except Exception as e:
            logger.warning(f"[Neo4j] Connection failed: {e}. Using in-memory mode.")
            self._in_memory_mode = True

    def close(self):
        """Close Neo4j connection."""
        if self.driver and not self._in_memory_mode:
            self.driver.close()
            logger.info("[Neo4j] Connection closed")

    def is_connected(self) -> bool:
        """Check if connected ke Neo4j."""
        return not self._in_memory_mode

    @property
    def in_memory_mode(self) -> bool:
        """Check if running in in-memory mode."""
        return self._in_memory_mode

    def _generate_id(self, label: str, key_props: Dict[str, Any]) -> str:
        """Generate unique node ID."""
        key_str = "|".join(f"{k}={v}" for k, v in sorted(key_props.items()))
        hash_str = hashlib.md5(f"{label}:{key_str}".encode()).hexdigest()[:12]
        return f"{label.lower()}_{hash_str}"

    def create_node(self, label: str, properties: Dict[str, Any], 
                    merge: bool = True) -> Optional[str]:
        """
        Create atau merge node.

        Args:
            label: Node label
            properties: Node properties
            merge: If True, merge (create if not exists)

        Returns:
            Node ID atau None
        """
        # Extract constraint properties untuk matching
        schema = GraphSchema.NODE_LABELS.get(label, {})
        constraints = schema.get("constraints", [])

        match_props = {k: properties.get(k) for k in constraints if k in properties}
        if not match_props:
            match_props = {"id": properties.get("id", self._generate_id(label, properties))}

        node_id = self._generate_id(label, match_props)

        if self._in_memory_mode:
            if merge and node_id in self._nodes:
                # Merge properties
                self._nodes[node_id].properties.update(properties)
            else:
                self._nodes[node_id] = Node(id=node_id, label=label, properties=properties)

            # Index by label
            if label not in self._node_index:
                self._node_index[label] = set()
            self._node_index[label].add(node_id)

            return node_id

        else:
            # Neo4j mode
            try:
                with self.driver.session(database=self.database) as session:
                    if merge:
                        cypher = GraphSchema.get_merge_node_cypher(label, match_props, properties)
                        params = {**match_props, **properties}
                    else:
                        cypher = GraphSchema.get_create_node_cypher(label, properties)
                        params = properties

                    result = session.run(cypher, **params)
                    record = result.single()
                    if record:
                        return str(record["n"].element_id)
            except Exception as e:
                logger.error(f"[Neo4j] Create node error: {e}")
                return None

    def create_relationship(self, from_id: str, to_id: str, rel_type: str,
                            properties: Optional[Dict[str, Any]] = None,
                            merge: bool = True) -> Optional[str]:
        """
        Create relationship antara dua nodes.

        Args:
            from_id: Source node ID
            to_id: Target node ID
            rel_type: Relationship type
            properties: Relationship properties
            merge: If True, merge

        Returns:
            Relationship ID atau None
        """
        rel_id = f"{from_id}_{rel_type}_{to_id}"
        props = properties or {}

        if self._in_memory_mode:
            if merge and rel_id in self._relationships:
                self._relationships[rel_id].properties.update(props)
            else:
                self._relationships[rel_id] = Relationship(
                    id=rel_id,
                    from_node=from_id,
                    to_node=to_id,
                    rel_type=rel_type,
                    properties=props
                )
            return rel_id

        else:
            try:
                with self.driver.session(database=self.database) as session:
                    # Get node labels untuk Cypher
                    from_node = self._nodes.get(from_id)
                    to_node = self._nodes.get(to_id)

                    if not from_node or not to_node:
                        logger.error("Nodes not found in memory cache")
                        return None

                    cypher = (
                        f"MATCH (a:{from_node.label} {{id: $from_id}}) "
                        f"MATCH (b:{to_node.label} {{id: $to_id}}) "
                    )

                    if merge:
                        cypher += f"MERGE (a)-[r:{rel_type}]->(b)"
                    else:
                        cypher += f"CREATE (a)-[r:{rel_type}]->(b)"

                    if props:
                        set_items = ", ".join([f"r.{k} = ${k}" for k in props.keys()])
                        cypher += f" SET {set_items}"

                    cypher += " RETURN r"

                    params = {"from_id": from_id, "to_id": to_id, **props}
                    result = session.run(cypher, **params)
                    record = result.single()
                    if record:
                        return str(record["r"].element_id)
            except Exception as e:
                logger.error(f"[Neo4j] Create relationship error: {e}")
                return None

    def get_node(self, node_id: str) -> Optional[Node]:
        """Get node by ID."""
        if self._in_memory_mode:
            return self._nodes.get(node_id)

        try:
            with self.driver.session(database=self.database) as session:
                result = session.run("MATCH (n) WHERE elementId(n) = $id RETURN n", id=node_id)
                record = result.single()
                if record:
                    node = record["n"]
                    return Node(
                        id=str(node.element_id),
                        label=list(node.labels)[0] if node.labels else "Unknown",
                        properties=dict(node)
                    )
        except Exception as e:
            logger.error(f"[Neo4j] Get node error: {e}")

        return None

    def get_nodes_by_label(self, label: str) -> List[Node]:
        """Get all nodes dengan specific label."""
        if self._in_memory_mode:
            node_ids = self._node_index.get(label, set())
            return [self._nodes[nid] for nid in node_ids if nid in self._nodes]

        try:
            with self.driver.session(database=self.database) as session:
                result = session.run(f"MATCH (n:{label}) RETURN n")
                nodes = []
                for record in result:
                    node = record["n"]
                    nodes.append(Node(
                        id=str(node.element_id),
                        label=label,
                        properties=dict(node)
                    ))
                return nodes
        except Exception as e:
            logger.error(f"[Neo4j] Get nodes error: {e}")
            return []

    def get_relationships(self, node_id: str, direction: str = "both") -> List[Relationship]:
        """
        Get relationships untuk sebuah node.

        Args:
            node_id: Node ID
            direction: "in", "out", atau "both"
        """
        if self._in_memory_mode:
            rels = []
            for rel in self._relationships.values():
                if direction in ("out", "both") and rel.from_node == node_id:
                    rels.append(rel)
                if direction in ("in", "both") and rel.to_node == node_id:
                    rels.append(rel)
            return rels

        try:
            with self.driver.session(database=self.database) as session:
                if direction == "out":
                    cypher = "MATCH (n)-[r]->() WHERE elementId(n) = $id RETURN r"
                elif direction == "in":
                    cypher = "MATCH ()-[r]->(n) WHERE elementId(n) = $id RETURN r"
                else:
                    cypher = "MATCH (n)-[r]-() WHERE elementId(n) = $id RETURN r"

                result = session.run(cypher, id=node_id)
                rels = []
                for record in result:
                    rel = record["r"]
                    rels.append(Relationship(
                        id=str(rel.element_id),
                        from_node=str(rel.start_node.element_id),
                        to_node=str(rel.end_node.element_id),
                        rel_type=rel.type,
                        properties=dict(rel)
                    ))
                return rels
        except Exception as e:
            logger.error(f"[Neo4j] Get relationships error: {e}")
            return []

    def execute_cypher(self, cypher: str, parameters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Execute raw Cypher query.

        Args:
            cypher: Cypher query string
            parameters: Query parameters

        Returns:
            List of result records sebagai dicts
        """
        if self._in_memory_mode:
            logger.warning("Cypher execution not available in in-memory mode")
            return []

        try:
            with self.driver.session(database=self.database) as session:
                result = session.run(cypher, parameters or {})
                return [record.data() for record in result]
        except Exception as e:
            logger.error(f"[Neo4j] Cypher execution error: {e}")
            return []

    def clear_database(self, confirm: bool = False):
        """Clear all data dari database. DANGEROUS!"""
        if not confirm:
            logger.warning("Set confirm=True untuk clear database")
            return

        if self._in_memory_mode:
            self._nodes.clear()
            self._relationships.clear()
            self._node_index.clear()
            logger.info("[Neo4j] In-memory database cleared")
        else:
            try:
                with self.driver.session(database=self.database) as session:
                    session.run("MATCH (n) DETACH DELETE n")
                    logger.info("[Neo4j] Database cleared")
            except Exception as e:
                logger.error(f"[Neo4j] Clear error: {e}")

    def get_stats(self) -> Dict[str, Any]:
        """Get database statistics."""
        if self._in_memory_mode:
            return {
                "mode": "in-memory",
                "total_nodes": len(self._nodes),
                "total_relationships": len(self._relationships),
                "node_labels": {label: len(ids) for label, ids in self._node_index.items()}
            }

        try:
            with self.driver.session(database=self.database) as session:
                node_count = session.run("MATCH (n) RETURN count(n) as count").single()["count"]
                rel_count = session.run("MATCH ()-[r]->() RETURN count(r) as count").single()["count"]

                labels_result = session.run("CALL db.labels() YIELD label RETURN label")
                labels = [record["label"] for record in labels_result]

                rel_types_result = session.run("CALL db.relationshipTypes() YIELD relationshipType RETURN relationshipType")
                rel_types = [record["relationshipType"] for record in rel_types_result]

                return {
                    "mode": "neo4j",
                    "uri": self.uri,
                    "total_nodes": node_count,
                    "total_relationships": rel_count,
                    "labels": labels,
                    "relationship_types": rel_types
                }
        except Exception as e:
            logger.error(f"[Neo4j] Stats error: {e}")
            return {"mode": "neo4j", "error": str(e)}

    def to_networkx(self) -> Dict:
        """
        Export graph data untuk NetworkX.

        Returns:
            Dict dengan nodes dan edges untuk NetworkX
        """
        nodes_data = {}
        for node_id, node in self._nodes.items():
            nodes_data[node_id] = {
                "label": node.label,
                **node.properties
            }

        edges_data = []
        for rel_id, rel in self._relationships.items():
            edges_data.append((
                rel.from_node,
                rel.to_node,
                {
                    "type": rel.rel_type,
                    **rel.properties
                }
            ))

        return {
            "nodes": nodes_data,
            "edges": edges_data
        }

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()