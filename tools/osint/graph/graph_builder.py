"""
graph_builder.py - Graph Builder Module
Part of OSINT Intelligence Platform v4

Build graph database dari OSINT investigation results.
Supports Neo4j (persistent) dan NetworkX (in-memory analysis).
"""

import logging
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass, field
from datetime import datetime

import networkx as nx

from .neo4j_connector import Neo4jConnector, GraphSchema

logger = logging.getLogger("osint.graph_builder")


@dataclass
class OSINTEntity:
    """Generic OSINT entity untuk graph building."""
    entity_type: str
    id_key: str
    properties: Dict[str, Any] = field(default_factory=dict)
    relationships: List[Dict[str, Any]] = field(default_factory=list)


class GraphBuilder:
    """
    Build graph database dari OSINT investigation results.
    """

    def __init__(self, connector: Optional[Neo4jConnector] = None,
                 enable_networkx: bool = True):
        """
        Initialize graph builder.

        Args:
            connector: Neo4jConnector instance (None = create new)
            enable_networkx: Whether to maintain NetworkX graph in parallel
        """
        self.connector = connector or Neo4jConnector()
        self.enable_networkx = enable_networkx
        self._person_node_id: Optional[str] = None

        # NetworkX graph untuk analisis in-memory
        self.nx_graph: Optional[nx.DiGraph] = nx.DiGraph() if enable_networkx else None

    def _add_to_networkx(self, node_id: str, label: str, properties: Dict[str, Any]):
        """Add node ke NetworkX graph."""
        if self.nx_graph is not None:
            self.nx_graph.add_node(
                node_id,
                label=label,
                **properties
            )

    def _add_edge_to_networkx(self, from_id: str, to_id: str, rel_type: str,
                               properties: Optional[Dict[str, Any]] = None):
        """Add edge ke NetworkX graph."""
        if self.nx_graph is not None:
            self.nx_graph.add_edge(
                from_id, to_id,
                type=rel_type,
                **(properties or {})
            )

    def build_from_person(self, 
                          name: str,
                          normalized_name: str,
                          aliases: Optional[List[str]] = None,
                          confidence_score: float = 0.0) -> str:
        """
        Create Person node sebagai root entity.

        Returns:
            Person node ID
        """
        properties = {
            "name": name,
            "normalized_name": normalized_name,
            "aliases": aliases or [],
            "confidence_score": confidence_score,
            "created_at": datetime.now().isoformat()
        }

        self._person_node_id = self.connector.create_node(
            "Person", properties, merge=True
        )

        # Add to NetworkX
        self._add_to_networkx(self._person_node_id, "Person", properties)

        logger.info(f"[GraphBuilder] Created Person node: {name}")
        return self._person_node_id

    def add_usernames(self, usernames: List[Dict[str, Any]]) -> List[str]:
        """
        Add username nodes dan link ke Person.

        Args:
            usernames: List of dicts dengan keys: username, platform, url, confidence

        Returns:
            List of username node IDs
        """
        if not self._person_node_id:
            logger.error("Person node not created yet")
            return []

        node_ids = []

        for u in usernames:
            username = u.get("username")
            platform = u.get("platform")

            if not username or not platform:
                continue

            properties = {
                "username": username,
                "platform": platform,
                "url": u.get("url", ""),
                "confidence": u.get("confidence", 0.0),
                "discovered_at": u.get("discovered_at", datetime.now().isoformat())
            }

            node_id = self.connector.create_node("Username", properties, merge=True)
            if node_id:
                node_ids.append(node_id)

                # Create USES relationship
                rel_props = {"confidence": u.get("confidence", 0.0)}
                self.connector.create_relationship(
                    self._person_node_id, node_id, "USES", rel_props
                )

                # Add to NetworkX
                self._add_to_networkx(node_id, "Username", properties)
                self._add_edge_to_networkx(self._person_node_id, node_id, "USES", rel_props)

        logger.info(f"[GraphBuilder] Added {len(node_ids)} username nodes")
        return node_ids

    def add_emails(self, emails: List[Dict[str, Any]]) -> List[str]:
        """
        Add email nodes dan link ke Person.

        Args:
            emails: List of dicts dengan keys: email, domain, gravatar_hash, confidence
        """
        if not self._person_node_id:
            logger.error("Person node not created yet")
            return []

        node_ids = []

        for e in emails:
            email = e.get("email")
            if not email or "@" not in email:
                continue

            domain = email.split("@")[1]

            properties = {
                "email": email,
                "domain": domain,
                "gravatar_hash": e.get("gravatar_hash", ""),
                "confidence": e.get("confidence", 0.0),
                "is_disposable": e.get("is_disposable", False),
                "is_role_account": e.get("is_role_account", False)
            }

            node_id = self.connector.create_node("Email", properties, merge=True)
            if node_id:
                node_ids.append(node_id)

                rel_props = {"confidence": e.get("confidence", 0.0)}
                self.connector.create_relationship(
                    self._person_node_id, node_id, "HAS_EMAIL", rel_props
                )

                # Add to NetworkX
                self._add_to_networkx(node_id, "Email", properties)
                self._add_edge_to_networkx(self._person_node_id, node_id, "HAS_EMAIL", rel_props)

                # Also create domain node jika belum ada
                domain_props = {"name": domain}
                domain_id = self.connector.create_node("Domain", domain_props, merge=True)
                if domain_id:
                    self.connector.create_relationship(
                        node_id, domain_id, "BELONGS_TO"
                    )
                    self._add_to_networkx(domain_id, "Domain", domain_props)
                    self._add_edge_to_networkx(node_id, domain_id, "BELONGS_TO")

        logger.info(f"[GraphBuilder] Added {len(node_ids)} email nodes")
        return node_ids

    def add_websites(self, websites: List[Dict[str, Any]]) -> List[str]:
        """
        Add website nodes dan link ke Person.

        Args:
            websites: List of dicts dengan keys: url, title, emails, phones, confidence
        """
        if not self._person_node_id:
            logger.error("Person node not created yet")
            return []

        node_ids = []

        for w in websites:
            url = w.get("url")
            if not url:
                continue

            properties = {
                "url": url,
                "title": w.get("title", ""),
                "emails_found": w.get("emails", []),
                "phones_found": w.get("phones", []),
                "technologies": w.get("technologies", []),
                "confidence": w.get("confidence", 0.0)
            }

            node_id = self.connector.create_node("Website", properties, merge=True)
            if node_id:
                node_ids.append(node_id)

                rel_props = {"confidence": w.get("confidence", 0.0)}
                self.connector.create_relationship(
                    self._person_node_id, node_id, "OWNS", rel_props
                )

                # Add to NetworkX
                self._add_to_networkx(node_id, "Website", properties)
                self._add_edge_to_networkx(self._person_node_id, node_id, "OWNS", rel_props)

        logger.info(f"[GraphBuilder] Added {len(node_ids)} website nodes")
        return node_ids

    def add_locations(self, locations: List[Dict[str, Any]]) -> List[str]:
        """
        Add location nodes dan link ke Person.

        Args:
            locations: List of dicts dengan keys: name, country, city, confidence
        """
        if not self._person_node_id:
            logger.error("Person node not created yet")
            return []

        node_ids = []

        for loc in locations:
            name = loc.get("name")
            if not name:
                continue

            properties = {
                "name": name,
                "country": loc.get("country", ""),
                "city": loc.get("city", ""),
                "coordinates": loc.get("coordinates", "")
            }

            node_id = self.connector.create_node("Location", properties, merge=True)
            if node_id:
                node_ids.append(node_id)

                rel_props = {"confidence": loc.get("confidence", 0.0)}
                self.connector.create_relationship(
                    self._person_node_id, node_id, "LOCATED_IN", rel_props
                )

                # Add to NetworkX
                self._add_to_networkx(node_id, "Location", properties)
                self._add_edge_to_networkx(self._person_node_id, node_id, "LOCATED_IN", rel_props)

        logger.info(f"[GraphBuilder] Added {len(node_ids)} location nodes")
        return node_ids

    def add_education(self, education: List[Dict[str, Any]]) -> List[str]:
        """
        Add education/organization nodes dan link ke Person.

        Args:
            education: List of dicts dengan keys: institution, program, degree, years
        """
        if not self._person_node_id:
            logger.error("Person node not created yet")
            return []

        node_ids = []

        for edu in education:
            institution = edu.get("institution")
            if not institution:
                continue

            properties = {
                "name": institution,
                "type": "educational",
                "industry": "education",
                "location": edu.get("location", "")
            }

            node_id = self.connector.create_node("Organization", properties, merge=True)
            if node_id:
                node_ids.append(node_id)

                rel_props = {
                    "program": edu.get("program", ""),
                    "degree": edu.get("degree", ""),
                    "year_start": edu.get("year_start"),
                    "year_end": edu.get("year_end"),
                    "confidence": edu.get("confidence", 0.0)
                }

                self.connector.create_relationship(
                    self._person_node_id, node_id, "STUDIED_AT", rel_props
                )

                # Add to NetworkX
                self._add_to_networkx(node_id, "Organization", properties)
                self._add_edge_to_networkx(self._person_node_id, node_id, "STUDIED_AT", rel_props)

        logger.info(f"[GraphBuilder] Added {len(node_ids)} education nodes")
        return node_ids

    def add_employment(self, employment: List[Dict[str, Any]]) -> List[str]:
        """
        Add employment/organization nodes dan link ke Person.

        Args:
            employment: List of dicts dengan keys: company, position, years
        """
        if not self._person_node_id:
            logger.error("Person node not created yet")
            return []

        node_ids = []

        for emp in employment:
            company = emp.get("company")
            if not company:
                continue

            properties = {
                "name": company,
                "type": "company",
                "industry": emp.get("industry", ""),
                "location": emp.get("location", "")
            }

            node_id = self.connector.create_node("Organization", properties, merge=True)
            if node_id:
                node_ids.append(node_id)

                rel_props = {
                    "position": emp.get("position", ""),
                    "year_start": emp.get("year_start"),
                    "year_end": emp.get("year_end"),
                    "confidence": emp.get("confidence", 0.0)
                }

                self.connector.create_relationship(
                    self._person_node_id, node_id, "WORKS_AT", rel_props
                )

                # Add to NetworkX
                self._add_to_networkx(node_id, "Organization", properties)
                self._add_edge_to_networkx(self._person_node_id, node_id, "WORKS_AT", rel_props)

        logger.info(f"[GraphBuilder] Added {len(node_ids)} employment nodes")
        return node_ids

    def add_domains(self, domains: List[Dict[str, Any]]) -> List[str]:
        """
        Add domain nodes.

        Args:
            domains: List of dicts dengan keys: name, registrar, creation_date, etc.
        """
        node_ids = []

        for d in domains:
            name = d.get("name")
            if not name:
                continue

            properties = {
                "name": name,
                "tld": name.split(".")[-1] if "." in name else "",
                "registrar": d.get("registrar", ""),
                "creation_date": d.get("creation_date", ""),
                "expiration_date": d.get("expiration_date", ""),
                "name_servers": d.get("name_servers", [])
            }

            node_id = self.connector.create_node("Domain", properties, merge=True)
            if node_id:
                node_ids.append(node_id)

                # Add to NetworkX
                self._add_to_networkx(node_id, "Domain", properties)

                # Link ke Person jika ada
                if self._person_node_id:
                    self.connector.create_relationship(
                        self._person_node_id, node_id, "OWNS"
                    )
                    self._add_edge_to_networkx(self._person_node_id, node_id, "OWNS")

        logger.info(f"[GraphBuilder] Added {len(node_ids)} domain nodes")
        return node_ids

    def add_subdomains(self, subdomains: List[Dict[str, Any]], parent_domain: str) -> List[str]:
        """
        Add subdomain nodes dan link ke parent domain.

        Args:
            subdomains: List of dicts dengan keys: name, is_resolvable, ip_addresses
            parent_domain: Parent domain name
        """
        node_ids = []

        # Get atau create parent domain node
        parent_props = {"name": parent_domain}
        parent_id = self.connector.create_node("Domain", parent_props, merge=True)

        # Add parent to NetworkX
        if parent_id:
            self._add_to_networkx(parent_id, "Domain", parent_props)

        for sub in subdomains:
            name = sub.get("name")
            if not name:
                continue

            properties = {
                "name": name,
                "parent_domain": parent_domain,
                "is_resolvable": sub.get("is_resolvable", False),
                "ip_addresses": sub.get("ip_addresses", [])
            }

            node_id = self.connector.create_node("Subdomain", properties, merge=True)
            if node_id:
                node_ids.append(node_id)

                # Link ke parent domain
                if parent_id:
                    self.connector.create_relationship(
                        parent_id, node_id, "CONTAINS"
                    )
                    self._add_to_networkx(node_id, "Subdomain", properties)
                    self._add_edge_to_networkx(parent_id, node_id, "CONTAINS")

        logger.info(f"[GraphBuilder] Added {len(node_ids)} subdomain nodes")
        return node_ids

    def add_phones(self, phones: List[Dict[str, Any]]) -> List[str]:
        """
        Add phone number nodes.

        Args:
            phones: List of dicts dengan keys: number, country_code, type
        """
        if not self._person_node_id:
            logger.error("Person node not created yet")
            return []

        node_ids = []

        for p in phones:
            number = p.get("number")
            if not number:
                continue

            properties = {
                "number": number,
                "country_code": p.get("country_code", ""),
                "type": p.get("type", "unknown")
            }

            node_id = self.connector.create_node("Phone", properties, merge=True)
            if node_id:
                node_ids.append(node_id)

                self.connector.create_relationship(
                    self._person_node_id, node_id, "HAS_PHONE"
                )

                # Add to NetworkX
                self._add_to_networkx(node_id, "Phone", properties)
                self._add_edge_to_networkx(self._person_node_id, node_id, "HAS_PHONE")

        logger.info(f"[GraphBuilder] Added {len(node_ids)} phone nodes")
        return node_ids

    def add_ip_addresses(self, ips: List[Dict[str, Any]]) -> List[str]:
        """
        Add IP address nodes.

        Args:
            ips: List of dicts dengan keys: address, version, asn, isp
        """
        node_ids = []

        for ip in ips:
            address = ip.get("address")
            if not address:
                continue

            properties = {
                "address": address,
                "version": ip.get("version", "4"),
                "asn": ip.get("asn", ""),
                "isp": ip.get("isp", "")
            }

            node_id = self.connector.create_node("IPAddress", properties, merge=True)
            if node_id:
                node_ids.append(node_id)

                # Add to NetworkX
                self._add_to_networkx(node_id, "IPAddress", properties)

        logger.info(f"[GraphBuilder] Added {len(node_ids)} IP nodes")
        return node_ids

    def add_breach_data(self, breaches: List[Dict[str, Any]]) -> List[str]:
        """
        Add breach data nodes.

        Args:
            breaches: List of dicts dengan keys: name, date, source, description
        """
        node_ids = []

        for b in breaches:
            name = b.get("name")
            if not name:
                continue

            properties = {
                "name": name,
                "date": b.get("date", ""),
                "source": b.get("source", ""),
                "description": b.get("description", "")
            }

            node_id = self.connector.create_node("Breach", properties, merge=True)
            if node_id:
                node_ids.append(node_id)

                # Add to NetworkX
                self._add_to_networkx(node_id, "Breach", properties)

        logger.info(f"[GraphBuilder] Added {len(node_ids)} breach nodes")
        return node_ids

    def add_github_data(self, repos: List[Dict[str, Any]], 
                        users: List[Dict[str, Any]]) -> Tuple[List[str], List[str]]:
        """
        Add GitHub data nodes.

        Args:
            repos: List of repo dicts
            users: List of user dicts

        Returns:
            Tuple of (repo_node_ids, user_node_ids)
        """
        repo_ids = []
        user_ids = []

        # Add repos
        for repo in repos:
            name = repo.get("name")
            owner = repo.get("owner")
            if not name or not owner:
                continue

            properties = {
                "name": name,
                "owner": owner,
                "url": repo.get("url", ""),
                "language": repo.get("language", "")
            }

            node_id = self.connector.create_node("GitHubRepo", properties, merge=True)
            if node_id:
                repo_ids.append(node_id)
                self._add_to_networkx(node_id, "GitHubRepo", properties)

        # Add users
        for user in users:
            username = user.get("username")
            if not username:
                continue

            properties = {
                "username": username,
                "url": user.get("url", ""),
                "followers": user.get("followers", 0)
            }

            node_id = self.connector.create_node("GitHubUser", properties, merge=True)
            if node_id:
                user_ids.append(node_id)
                self._add_to_networkx(node_id, "GitHubUser", properties)

        logger.info(f"[GraphBuilder] Added {len(repo_ids)} repos, {len(user_ids)} users")
        return repo_ids, user_ids

    def build_complete_profile(self, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build complete graph dari OSINT profile data.

        Args:
            profile_data: Dict dengan semua OSINT data

        Returns:
            Graph statistics
        """
        # Create person node
        person_id = self.build_from_person(
            name=profile_data.get("name", "Unknown"),
            normalized_name=profile_data.get("normalized_name", ""),
            aliases=profile_data.get("aliases", []),
            confidence_score=profile_data.get("confidence_score", 0.0)
        )

        # Add all entity types
        if "usernames" in profile_data:
            self.add_usernames(profile_data["usernames"])

        if "emails" in profile_data:
            self.add_emails(profile_data["emails"])

        if "websites" in profile_data:
            self.add_websites(profile_data["websites"])

        if "locations" in profile_data:
            self.add_locations(profile_data["locations"])

        if "education" in profile_data:
            self.add_education(profile_data["education"])

        if "employment" in profile_data:
            self.add_employment(profile_data["employment"])

        if "domains" in profile_data:
            self.add_domains(profile_data["domains"])

        if "subdomains" in profile_data:
            for domain, subs in profile_data["subdomains"].items():
                self.add_subdomains(subs, domain)

        if "phones" in profile_data:
            self.add_phones(profile_data["phones"])

        if "ip_addresses" in profile_data:
            self.add_ip_addresses(profile_data["ip_addresses"])

        if "breaches" in profile_data:
            self.add_breach_data(profile_data["breaches"])

        if "github" in profile_data:
            github_data = profile_data["github"]
            self.add_github_data(
                github_data.get("repos", []),
                github_data.get("users", [])
            )

        stats = self.connector.get_stats()
        logger.info(f"[GraphBuilder] Complete profile built: {stats}")

        return stats

    def get_networkx_graph(self) -> Optional[nx.DiGraph]:
        """
        Get NetworkX graph untuk analisis.

        Returns:
            NetworkX DiGraph atau None
        """
        return self.nx_graph

    def analyze_networkx(self) -> Optional[Dict[str, Any]]:
        """
        Analyze graph menggunakan NetworkX algorithms.

        Returns:
            Dictionary dengan analysis results
        """
        if self.nx_graph is None or len(self.nx_graph.nodes()) == 0:
            return None

        G = self.nx_graph
        G_undirected = G.to_undirected()

        analysis = {
            "basic": {
                "nodes": len(G.nodes()),
                "edges": len(G.edges()),
                "density": nx.density(G) if len(G.nodes()) > 1 else 0,
            },
            "centrality": {},
            "connectivity": {},
            "communities": {}
        }

        if len(G.nodes()) > 1:
            # Centrality
            analysis["centrality"]["degree"] = dict(nx.degree_centrality(G_undirected))

            if len(G.nodes()) > 2:
                try:
                    analysis["centrality"]["betweenness"] = dict(nx.betweenness_centrality(G_undirected))
                    analysis["centrality"]["closeness"] = dict(nx.closeness_centrality(G_undirected))
                except:
                    pass

            # Connectivity
            try:
                analysis["connectivity"]["is_connected"] = nx.is_connected(G_undirected)
                if analysis["connectivity"]["is_connected"]:
                    analysis["connectivity"]["diameter"] = nx.diameter(G_undirected)
            except:
                pass

            # Communities
            try:
                communities = list(nx.community.greedy_modularity_communities(G_undirected))
                analysis["communities"]["count"] = len(communities)
                analysis["communities"]["sizes"] = [len(c) for c in communities]
            except:
                pass

        return analysis

    def get_graph_stats(self) -> Dict[str, Any]:
        """Get current graph statistics."""
        return self.connector.get_stats()

    def close(self):
        """Close connector."""
        self.connector.close()


# ============== CONVENIENCE FUNCTIONS ==============

def build_profile_graph(profile_data: Dict[str, Any], 
                         enable_networkx: bool = True) -> GraphBuilder:
    """Quick build graph dari profile data."""
    builder = GraphBuilder(enable_networkx=enable_networkx)
    builder.build_complete_profile(profile_data)
    return builder


# ============== MAIN ==============

if __name__ == "__main__":
    print("=" * 60)
    print("Graph Builder Module")
    print("=" * 60)

    # Demo
    builder = GraphBuilder()

    profile = {
        "name": "John Doe",
        "normalized_name": "john_doe",
        "aliases": ["JD", "Johnny"],
        "confidence_score": 0.95,
        "usernames": [
            {"username": "johndoe", "platform": "twitter", "confidence": 0.9},
            {"username": "johndoe123", "platform": "github", "confidence": 0.85}
        ],
        "emails": [
            {"email": "john.doe@example.com", "confidence": 0.95}
        ],
        "domains": [
            {"name": "example.com", "registrar": "GoDaddy"}
        ]
    }

    print("\n[*] Building profile graph...")
    stats = builder.build_complete_profile(profile)
    print(f"[+] Stats: {stats}")

    if builder.nx_graph:
        print(f"\n[*] NetworkX graph: {len(builder.nx_graph.nodes())} nodes, {len(builder.nx_graph.edges())} edges")
        analysis = builder.analyze_networkx()
        print(f"[+] Analysis: {json.dumps(analysis, indent=2, default=str) if analysis else 'None'}")

    builder.close()

    print("\n" + "=" * 60)
    print("Demo complete!")
    print("=" * 60)