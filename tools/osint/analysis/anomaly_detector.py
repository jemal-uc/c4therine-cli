"""
anomaly_detector.py - Anomaly Detection Module
Part of OSINT Intelligence Platform v4

Mendeteksi anomali, outlier, dan pola tidak wajar dalam data OSINT.
Menggunakan berbagai algoritma: statistical, graph-based, dan ML-based.

Features:
- Statistical anomaly detection (Z-score, IQR)
- Graph anomaly detection (degree, centrality, community)
- Temporal anomaly detection (time-based patterns)
- Behavioral anomaly detection (pattern deviation)
- Multi-dimensional anomaly detection (isolation forest)
- Anomaly scoring dan ranking
- Alert generation
"""

import math
import logging
import statistics
from typing import Dict, List, Optional, Tuple, Any, Union, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from collections import defaultdict, Counter

import numpy as np

# Graph analysis
import networkx as nx

logger = logging.getLogger("osint.anomaly_detector")


class AnomalyType(Enum):
    """Types of anomalies yang bisa dideteksi."""
    STATISTICAL = "statistical"
    GRAPH = "graph"
    TEMPORAL = "temporal"
    BEHAVIORAL = "behavioral"
    MULTI_DIMENSIONAL = "multi_dimensional"
    PATTERN = "pattern"


class SeverityLevel(Enum):
    """Severity levels untuk anomalies."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Anomaly:
    """Single anomaly detection result."""
    anomaly_id: str
    anomaly_type: AnomalyType
    severity: SeverityLevel
    entity_id: str
    entity_type: str
    description: str
    score: float  # 0.0 - 1.0
    confidence: float  # 0.0 - 1.0
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    recommended_action: str = ""
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "anomaly_id": self.anomaly_id,
            "anomaly_type": self.anomaly_type.value,
            "severity": self.severity.value,
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "description": self.description,
            "score": self.score,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "recommended_action": self.recommended_action,
            "timestamp": self.timestamp
        }


@dataclass
class AnomalyReport:
    """Complete anomaly detection report."""
    report_id: str
    target: str
    anomalies: List[Anomaly]
    summary: Dict[str, Any]
    statistics: Dict[str, Any]
    generated_at: str = ""

    def __post_init__(self):
        if not self.generated_at:
            self.generated_at = datetime.now().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "report_id": self.report_id,
            "target": self.target,
            "anomaly_count": len(self.anomalies),
            "summary": self.summary,
            "statistics": self.statistics,
            "anomalies": [a.to_dict() for a in self.anomalies],
            "generated_at": self.generated_at
        }


class AnomalyDetector:
    """
    Anomaly detection engine untuk OSINT data.
    """

    # Threshold defaults
    Z_SCORE_THRESHOLD = 3.0
    IQR_MULTIPLIER = 1.5
    DEGREE_OUTLIER_THRESHOLD = 2.5
    TEMPORAL_BURST_THRESHOLD = 5
    BEHAVIORAL_DEVIATION_THRESHOLD = 0.3

    def __init__(self, 
                 z_threshold: float = 3.0,
                 iqr_multiplier: float = 1.5,
                 degree_threshold: float = 2.5,
                 temporal_burst: int = 5):
        """
        Initialize anomaly detector.

        Args:
            z_threshold: Z-score threshold untuk statistical outliers
            iqr_multiplier: IQR multiplier untuk outlier detection
            degree_threshold: Degree outlier threshold (std dev)
            temporal_burst: Threshold untuk temporal burst detection
        """
        self.z_threshold = z_threshold
        self.iqr_multiplier = iqr_multiplier
        self.degree_threshold = degree_threshold
        self.temporal_burst = temporal_burst

        self._anomalies: List[Anomaly] = []
        self._detection_history: List[Dict] = []

        logger.info("[AnomalyDetector] Initialized")

    # ==================== STATISTICAL ANOMALIES ====================

    def detect_statistical_outliers(self,
                                       data: List[float],
                                       labels: Optional[List[str]] = None,
                                       entity_type: str = "Unknown") -> List[Anomaly]:
        """
        Detect statistical outliers menggunakan Z-score dan IQR.

        Args:
            data: List of numerical values
            labels: Optional labels untuk setiap data point
            entity_type: Type of entities

        Returns:
            List of Anomaly objects
        """
        anomalies = []

        if len(data) < 3:
            return anomalies

        # Z-score method
        mean = statistics.mean(data)
        std_dev = statistics.stdev(data) if len(data) > 1 else 0

        if std_dev > 0:
            for i, value in enumerate(data):
                z_score = abs((value - mean) / std_dev)

                if z_score > self.z_threshold:
                    entity_id = labels[i] if labels and i < len(labels) else f"item_{i}"

                    anomaly = Anomaly(
                        anomaly_id=f"stat_z_{entity_id}",
                        anomaly_type=AnomalyType.STATISTICAL,
                        severity=self._severity_from_zscore(z_score),
                        entity_id=entity_id,
                        entity_type=entity_type,
                        description=(
                            f"Statistical outlier detected: value={value:.2f}, "
                            f"z-score={z_score:.2f} (threshold: {self.z_threshold})"
                        ),
                        score=min(1.0, z_score / (self.z_threshold * 2)),
                        confidence=min(1.0, z_score / (self.z_threshold * 1.5)),
                        evidence=[
                            {"method": "z_score", "value": z_score, "threshold": self.z_threshold},
                            {"mean": mean, "std_dev": std_dev, "data_point": value}
                        ],
                        recommended_action="Verify data accuracy and investigate cause"
                    )
                    anomalies.append(anomaly)

        # IQR method
        sorted_data = sorted(data)
        q1 = np.percentile(sorted_data, 25)
        q3 = np.percentile(sorted_data, 75)
        iqr = q3 - q1
        lower_bound = q1 - self.iqr_multiplier * iqr
        upper_bound = q3 + self.iqr_multiplier * iqr

        for i, value in enumerate(data):
            if value < lower_bound or value > upper_bound:
                entity_id = labels[i] if labels and i < len(labels) else f"item_{i}"

                # Skip jika sudah terdeteksi oleh Z-score
                if any(a.entity_id == entity_id for a in anomalies):
                    continue

                distance = max(lower_bound - value, value - upper_bound)

                anomaly = Anomaly(
                    anomaly_id=f"stat_iqr_{entity_id}",
                    anomaly_type=AnomalyType.STATISTICAL,
                    severity=self._severity_from_iqr(distance, iqr),
                    entity_id=entity_id,
                    entity_type=entity_type,
                    description=(
                        f"IQR outlier detected: value={value:.2f}, "
                        f"outside range [{lower_bound:.2f}, {upper_bound:.2f}]"
                    ),
                    score=min(1.0, distance / (iqr * 2)) if iqr > 0 else 0.5,
                    confidence=0.7,
                    evidence=[
                        {"method": "iqr", "q1": q1, "q3": q3, "iqr": iqr},
                        {"bounds": [lower_bound, upper_bound], "data_point": value}
                    ],
                    recommended_action="Investigate unusual value and verify source"
                )
                anomalies.append(anomaly)

        self._anomalies.extend(anomalies)
        logger.info(f"[AnomalyDetector] Statistical: {len(anomalies)} outliers detected")
        return anomalies

    # ==================== GRAPH ANOMALIES ====================

    def detect_graph_anomalies(self,
                                nodes: List[Dict[str, Any]],
                                relationships: List[Dict[str, Any]]) -> List[Anomaly]:
        """
        Detect anomalies dalam graph structure.

        Args:
            nodes: List of node dictionaries
            relationships: List of relationship dictionaries

        Returns:
            List of Anomaly objects
        """
        anomalies = []

        if len(nodes) < 3:
            return anomalies

        # Build NetworkX graph
        G = nx.DiGraph()

        for node in nodes:
            G.add_node(
                str(node["id"]),
                label=node.get("label", "Unknown"),
                **node.get("properties", {})
            )

        for rel in relationships:
            source = str(rel["from"])
            target = str(rel["to"])
            if source in G and target in G:
                G.add_edge(source, target, type=rel.get("type", "UNKNOWN"))

        # 1. Degree anomalies (nodes dengan degree tidak wajar)
        degree_anomalies = self._detect_degree_anomalies(G)
        anomalies.extend(degree_anomalies)

        # 2. Centrality anomalies
        centrality_anomalies = self._detect_centrality_anomalies(G)
        anomalies.extend(centrality_anomalies)

        # 3. Community anomalies (nodes yang bridge communities)
        community_anomalies = self._detect_community_anomalies(G)
        anomalies.extend(community_anomalies)

        # 4. Structural anomalies (isolated nodes, cliques)
        structural_anomalies = self._detect_structural_anomalies(G)
        anomalies.extend(structural_anomalies)

        self._anomalies.extend(anomalies)
        logger.info(f"[AnomalyDetector] Graph: {len(anomalies)} anomalies detected")
        return anomalies

    def _detect_degree_anomalies(self, G: nx.DiGraph) -> List[Anomaly]:
        """Detect nodes dengan degree tidak wajar."""
        anomalies = []

        if len(G.nodes()) < 3:
            return anomalies

        # Calculate degrees
        in_degrees = [d for n, d in G.in_degree()]
        out_degrees = [d for n, d in G.out_degree()]
        total_degrees = [in_deg + out_deg for in_deg, out_deg in zip(in_degrees, out_degrees)]

        # Statistical analysis pada total degrees
        if len(total_degrees) > 2 and statistics.stdev(total_degrees) > 0:
            mean_deg = statistics.mean(total_degrees)
            std_deg = statistics.stdev(total_degrees)

            for node in G.nodes():
                node_in_deg = G.in_degree(node)
                node_out_deg = G.out_degree(node)
                node_total = node_in_deg + node_out_deg

                z_score = abs((node_total - mean_deg) / std_deg)

                if z_score > self.degree_threshold:
                    anomaly = Anomaly(
                        anomaly_id=f"graph_deg_{node}",
                        anomaly_type=AnomalyType.GRAPH,
                        severity=self._severity_from_zscore(z_score),
                        entity_id=node,
                        entity_type=G.nodes[node].get("label", "Unknown"),
                        description=(
                            f"Unusual degree detected: total={node_total}, "
                            f"in={node_in_deg}, out={node_out_deg}, "
                            f"z-score={z_score:.2f}"
                        ),
                        score=min(1.0, z_score / (self.degree_threshold * 2)),
                        confidence=min(1.0, z_score / self.degree_threshold),
                        evidence=[
                            {"metric": "degree", "value": node_total, "mean": mean_deg, "std": std_deg},
                            {"in_degree": node_in_deg, "out_degree": node_out_deg}
                        ],
                        recommended_action="Investigate node connections and verify relationships"
                    )
                    anomalies.append(anomaly)

        return anomalies

    def _detect_centrality_anomalies(self, G: nx.DiGraph) -> List[Anomaly]:
        """Detect nodes dengan centrality tidak wajar."""
        anomalies = []

        if len(G.nodes()) < 3:
            return anomalies

        G_undirected = G.to_undirected()

        try:
            # Betweenness centrality
            betweenness = nx.betweenness_centrality(G_undirected)

            if betweenness:
                values = list(betweenness.values())
                mean_bet = statistics.mean(values)
                std_bet = statistics.stdev(values) if len(values) > 1 else 0

                if std_bet > 0:
                    for node, score in betweenness.items():
                        z_score = abs((score - mean_bet) / std_bet)

                        if z_score > self.z_threshold:
                            anomaly = Anomaly(
                                anomaly_id=f"graph_bet_{node}",
                                anomaly_type=AnomalyType.GRAPH,
                                severity=self._severity_from_zscore(z_score),
                                entity_id=node,
                                entity_type=G.nodes[node].get("label", "Unknown"),
                                description=(
                                    f"Unusual betweenness centrality: {score:.4f}, "
                                    f"z-score={z_score:.2f}"
                                ),
                                score=min(1.0, z_score / (self.z_threshold * 2)),
                                confidence=0.8,
                                evidence=[
                                    {"metric": "betweenness_centrality", "value": score},
                                    {"mean": mean_bet, "std": std_bet}
                                ],
                                recommended_action="Node may be a key intermediary - investigate role"
                            )
                            anomalies.append(anomaly)
        except Exception as e:
            logger.warning(f"[AnomalyDetector] Betweenness calculation failed: {e}")

        return anomalies

    def _detect_community_anomalies(self, G: nx.DiGraph) -> List[Anomaly]:
        """Detect community structure anomalies."""
        anomalies = []

        if len(G.nodes()) < 5:
            return anomalies

        try:
            G_undirected = G.to_undirected()
            communities = list(nx.community.greedy_modularity_communities(G_undirected))

            # Detect bridge nodes (nodes yang connect multiple communities)
            node_communities = {}
            for i, comm in enumerate(communities):
                for node in comm:
                    node_communities[node] = i

            for node in G.nodes():
                # Count cross-community edges
                cross_community = 0
                node_comm = node_communities.get(node)

                if node_comm is not None:
                    for neighbor in G.neighbors(node):
                        if node_communities.get(neighbor) != node_comm:
                            cross_community += 1

                    if cross_community > 2:
                        anomaly = Anomaly(
                            anomaly_id=f"graph_bridge_{node}",
                            anomaly_type=AnomalyType.GRAPH,
                            severity=SeverityLevel.MEDIUM,
                            entity_id=node,
                            entity_type=G.nodes[node].get("label", "Unknown"),
                            description=(
                                f"Bridge node detected: connects {cross_community} communities, "
                                f"may indicate key intermediary"
                            ),
                            score=min(1.0, cross_community / 5),
                            confidence=0.75,
                            evidence=[
                                {"metric": "cross_community_edges", "value": cross_community},
                                {"communities": len(communities)}
                            ],
                            recommended_action="Investigate node role as potential intermediary"
                        )
                        anomalies.append(anomaly)

        except Exception as e:
            logger.warning(f"[AnomalyDetector] Community detection failed: {e}")

        return anomalies

    def _detect_structural_anomalies(self, G: nx.DiGraph) -> List[Anomaly]:
        """Detect structural anomalies seperti isolated nodes."""
        anomalies = []

        # Isolated nodes
        isolated = list(nx.isolates(G.to_undirected()))
        for node in isolated:
            anomaly = Anomaly(
                anomaly_id=f"graph_iso_{node}",
                anomaly_type=AnomalyType.GRAPH,
                severity=SeverityLevel.LOW,
                entity_id=node,
                entity_type=G.nodes[node].get("label", "Unknown"),
                description="Isolated node detected: no connections to other entities",
                score=0.4,
                confidence=0.9,
                evidence=[{"metric": "isolated", "connections": 0}],
                recommended_action="Verify if node should have connections or remove if irrelevant"
            )
            anomalies.append(anomaly)

        return anomalies

    # ==================== TEMPORAL ANOMALIES ====================

    def detect_temporal_anomalies(self,
                                    events: List[Dict[str, Any]],
                                    entity_id: str = "unknown") -> List[Anomaly]:
        """
        Detect temporal anomalies dalam event sequence.

        Args:
            events: List of event dictionaries dengan timestamp
            entity_id: Entity identifier

        Returns:
            List of Anomaly objects
        """
        anomalies = []

        if len(events) < 3:
            return anomalies

        # Parse timestamps
        parsed_events = []
        for event in events:
            ts = event.get("timestamp")
            if ts:
                try:
                    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    parsed_events.append({**event, "datetime": dt})
                except:
                    pass

        if len(parsed_events) < 3:
            return anomalies

        # Sort by time
        parsed_events.sort(key=lambda x: x["datetime"])

        # 1. Burst detection (many events dalam short time)
        burst_anomalies = self._detect_bursts(parsed_events, entity_id)
        anomalies.extend(burst_anomalies)

        # 2. Gap detection (unusual gaps antara events)
        gap_anomalies = self._detect_gaps(parsed_events, entity_id)
        anomalies.extend(gap_anomalies)

        # 3. Pattern deviation
        pattern_anomalies = self._detect_temporal_patterns(parsed_events, entity_id)
        anomalies.extend(pattern_anomalies)

        self._anomalies.extend(anomalies)
        logger.info(f"[AnomalyDetector] Temporal: {len(anomalies)} anomalies detected")
        return anomalies

    def _detect_bursts(self, events: List[Dict], entity_id: str) -> List[Anomaly]:
        """Detect event bursts."""
        anomalies = []

        # Sliding window analysis (1 hour windows)
        window_size = timedelta(hours=1)

        for i, event in enumerate(events):
            window_start = event["datetime"]
            window_end = window_start + window_size

            events_in_window = [
                e for e in events
                if window_start <= e["datetime"] <= window_end
            ]

            if len(events_in_window) >= self.temporal_burst:
                anomaly = Anomaly(
                    anomaly_id=f"temp_burst_{entity_id}_{i}",
                    anomaly_type=AnomalyType.TEMPORAL,
                    severity=SeverityLevel.HIGH if len(events_in_window) > self.temporal_burst * 2 else SeverityLevel.MEDIUM,
                    entity_id=entity_id,
                    entity_type=event.get("type", "Event"),
                    description=(
                        f"Event burst detected: {len(events_in_window)} events "
                        f"within 1 hour window"
                    ),
                    score=min(1.0, len(events_in_window) / (self.temporal_burst * 3)),
                    confidence=0.8,
                    evidence=[
                        {"window_start": window_start.isoformat(), "event_count": len(events_in_window)},
                        {"threshold": self.temporal_burst}
                    ],
                    recommended_action="Investigate cause of sudden activity spike"
                )
                anomalies.append(anomaly)

        return anomalies

    def _detect_gaps(self, events: List[Dict], entity_id: str) -> List[Anomaly]:
        """Detect unusual gaps antara events."""
        anomalies = []

        if len(events) < 2:
            return anomalies

        # Calculate intervals
        intervals = []
        for i in range(1, len(events)):
            interval = (events[i]["datetime"] - events[i-1]["datetime"]).total_seconds() / 3600  # hours
            intervals.append(interval)

        if len(intervals) < 2:
            return anomalies

        mean_interval = statistics.mean(intervals)
        std_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0

        if std_interval > 0:
            for i, interval in enumerate(intervals):
                z_score = abs((interval - mean_interval) / std_interval)

                if z_score > self.z_threshold and interval > mean_interval * 2:
                    anomaly = Anomaly(
                        anomaly_id=f"temp_gap_{entity_id}_{i}",
                        anomaly_type=AnomalyType.TEMPORAL,
                        severity=self._severity_from_zscore(z_score),
                        entity_id=entity_id,
                        entity_type=events[i+1].get("type", "Event"),
                        description=(
                            f"Unusual gap detected: {interval:.1f} hours "
                            f"(avg: {mean_interval:.1f}h, z-score: {z_score:.2f})"
                        ),
                        score=min(1.0, z_score / (self.z_threshold * 2)),
                        confidence=0.7,
                        evidence=[
                            {"gap_hours": interval, "mean_hours": mean_interval, "std": std_interval}
                        ],
                        recommended_action="Investigate reason for activity gap"
                    )
                    anomalies.append(anomaly)

        return anomalies

    def _detect_temporal_patterns(self, events: List[Dict], entity_id: str) -> List[Anomaly]:
        """Detect deviations dari temporal patterns."""
        anomalies = []

        # Analyze hour-of-day distribution
        hours = [e["datetime"].hour for e in events]
        hour_counts = Counter(hours)

        # Check for unusual hour concentrations
        total_events = len(events)
        for hour, count in hour_counts.items():
            proportion = count / total_events

            # If >50% events terjadi pada single hour
            if proportion > 0.5 and count > 5:
                anomaly = Anomaly(
                    anomaly_id=f"temp_pattern_{entity_id}_{hour}",
                    anomaly_type=AnomalyType.TEMPORAL,
                    severity=SeverityLevel.MEDIUM,
                    entity_id=entity_id,
                    entity_type="Event",
                    description=(
                        f"Temporal concentration: {count} events ({proportion:.1%}) "
                        f"occurred at hour {hour}:00"
                    ),
                    score=proportion,
                    confidence=0.75,
                    evidence=[
                        {"hour": hour, "count": count, "proportion": proportion}
                    ],
                    recommended_action="Check if timing indicates automated activity"
                )
                anomalies.append(anomaly)

        return anomalies

    # ==================== BEHAVIORAL ANOMALIES ====================

    def detect_behavioral_anomalies(self,
                                     current_behavior: Dict[str, Any],
                                     historical_profile: Dict[str, Any],
                                     entity_id: str = "unknown") -> List[Anomaly]:
        """
        Detect behavioral deviations dari historical profile.

        Args:
            current_behavior: Current behavior metrics
            historical_profile: Historical behavior profile
            entity_id: Entity identifier

        Returns:
            List of Anomaly objects
        """
        anomalies = []

        for metric, current_value in current_behavior.items():
            if metric in historical_profile:
                hist_data = historical_profile[metric]

                if isinstance(hist_data, dict):
                    mean = hist_data.get("mean", 0)
                    std = hist_data.get("std", 0)

                    if std > 0 and isinstance(current_value, (int, float)):
                        z_score = abs((current_value - mean) / std)

                        if z_score > self.z_threshold:
                            deviation = abs(current_value - mean) / mean if mean > 0 else 0

                            anomaly = Anomaly(
                                anomaly_id=f"behav_{entity_id}_{metric}",
                                anomaly_type=AnomalyType.BEHAVIORAL,
                                severity=self._severity_from_zscore(z_score),
                                entity_id=entity_id,
                                entity_type="Behavior",
                                description=(
                                    f"Behavioral anomaly in {metric}: "
                                    f"current={current_value}, mean={mean:.2f}, "
                                    f"z-score={z_score:.2f}"
                                ),
                                score=min(1.0, z_score / (self.z_threshold * 2)),
                                confidence=min(1.0, z_score / self.z_threshold),
                                evidence=[
                                    {"metric": metric, "current": current_value, "mean": mean, "std": std},
                                    {"deviation_ratio": deviation}
                                ],
                                recommended_action="Investigate cause of behavioral change"
                            )
                            anomalies.append(anomaly)

        self._anomalies.extend(anomalies)
        logger.info(f"[AnomalyDetector] Behavioral: {len(anomalies)} anomalies detected")
        return anomalies

    # ==================== PATTERN ANOMALIES ====================

    def detect_pattern_anomalies(self,
                                  data_points: List[Dict[str, Any]],
                                  expected_patterns: List[str],
                                  entity_id: str = "unknown") -> List[Anomaly]:
        """
        Detect missing atau unexpected patterns.

        Args:
            data_points: List of data point dictionaries
            expected_patterns: List of expected pattern strings
            entity_id: Entity identifier

        Returns:
            List of Anomaly objects
        """
        anomalies = []

        # Extract actual patterns
        actual_patterns = set()
        for dp in data_points:
            pattern = dp.get("pattern", dp.get("type", ""))
            if pattern:
                actual_patterns.add(pattern)

        # Missing expected patterns
        for expected in expected_patterns:
            if expected not in actual_patterns:
                anomaly = Anomaly(
                    anomaly_id=f"pattern_miss_{entity_id}_{expected}",
                    anomaly_type=AnomalyType.PATTERN,
                    severity=SeverityLevel.MEDIUM,
                    entity_id=entity_id,
                    entity_type="Pattern",
                    description=f"Expected pattern missing: {expected}",
                    score=0.6,
                    confidence=0.7,
                    evidence=[
                        {"expected": expected, "actual_patterns": list(actual_patterns)}
                    ],
                    recommended_action="Investigate why expected pattern is absent"
                )
                anomalies.append(anomaly)

        # Unexpected patterns
        for actual in actual_patterns:
            if actual not in expected_patterns:
                anomaly = Anomaly(
                    anomaly_id=f"pattern_unexp_{entity_id}_{actual}",
                    anomaly_type=AnomalyType.PATTERN,
                    severity=SeverityLevel.LOW,
                    entity_id=entity_id,
                    entity_type="Pattern",
                    description=f"Unexpected pattern detected: {actual}",
                    score=0.4,
                    confidence=0.6,
                    evidence=[
                        {"unexpected": actual, "expected_patterns": expected_patterns}
                    ],
                    recommended_action="Verify if unexpected pattern is legitimate"
                )
                anomalies.append(anomaly)

        self._anomalies.extend(anomalies)
        return anomalies

    # ==================== AGGREGATE FUNCTIONS ====================

    def run_full_detection(self,
                          nodes: List[Dict[str, Any]],
                          relationships: List[Dict[str, Any]],
                          events: Optional[List[Dict]] = None,
                          target: str = "investigation") -> AnomalyReport:
        """
        Run full anomaly detection suite.

        Args:
            nodes: Graph nodes
            relationships: Graph relationships
            events: Optional temporal events
            target: Investigation target

        Returns:
            AnomalyReport
        """
        all_anomalies = []

        # Graph anomalies
        graph_anomalies = self.detect_graph_anomalies(nodes, relationships)
        all_anomalies.extend(graph_anomalies)

        # Temporal anomalies
        if events:
            temporal_anomalies = self.detect_temporal_anomalies(events, target)
            all_anomalies.extend(temporal_anomalies)

        # Generate report
        report = self._generate_report(all_anomalies, target)

        logger.info(f"[AnomalyDetector] Full detection: {len(all_anomalies)} total anomalies")
        return report

    def _generate_report(self, anomalies: List[Anomaly], target: str) -> AnomalyReport:
        """Generate anomaly report."""
        # Summary statistics
        severity_counts = Counter(a.severity.value for a in anomalies)
        type_counts = Counter(a.anomaly_type.value for a in anomalies)

        # Calculate aggregate scores
        scores = [a.score for a in anomalies]
        confidences = [a.confidence for a in anomalies]

        summary = {
            "total_anomalies": len(anomalies),
            "by_severity": dict(severity_counts),
            "by_type": dict(type_counts),
            "critical_count": severity_counts.get("critical", 0),
            "high_count": severity_counts.get("high", 0),
        }

        statistics = {
            "average_score": statistics.mean(scores) if scores else 0,
            "max_score": max(scores) if scores else 0,
            "average_confidence": statistics.mean(confidences) if confidences else 0,
        }

        # Sort anomalies by severity dan score
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_anomalies = sorted(
            anomalies,
            key=lambda a: (severity_order.get(a.severity.value, 5), -a.score)
        )

        report = AnomalyReport(
            report_id=f"anomaly_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            target=target,
            anomalies=sorted_anomalies,
            summary=summary,
            statistics=statistics
        )

        return report

    def get_anomalies_by_severity(self, severity: SeverityLevel) -> List[Anomaly]:
        """Get anomalies by severity level."""
        return [a for a in self._anomalies if a.severity == severity]

    def get_anomalies_by_type(self, anomaly_type: AnomalyType) -> List[Anomaly]:
        """Get anomalies by type."""
        return [a for a in self._anomalies if a.anomaly_type == anomaly_type]

    def get_critical_anomalies(self) -> List[Anomaly]:
        """Get critical severity anomalies."""
        return self.get_anomalies_by_severity(SeverityLevel.CRITICAL)

    def clear_history(self):
        """Clear detection history."""
        self._anomalies.clear()
        self._detection_history.clear()

    # ==================== HELPER METHODS ====================

    def _severity_from_zscore(self, z_score: float) -> SeverityLevel:
        """Convert Z-score ke SeverityLevel."""
        if z_score > self.z_threshold * 2:
            return SeverityLevel.CRITICAL
        elif z_score > self.z_threshold * 1.5:
            return SeverityLevel.HIGH
        elif z_score > self.z_threshold:
            return SeverityLevel.MEDIUM
        else:
            return SeverityLevel.LOW

    def _severity_from_iqr(self, distance: float, iqr: float) -> SeverityLevel:
        """Convert IQR distance ke SeverityLevel."""
        if iqr == 0:
            return SeverityLevel.LOW

        ratio = distance / iqr
        if ratio > 3:
            return SeverityLevel.CRITICAL
        elif ratio > 2:
            return SeverityLevel.HIGH
        elif ratio > 1:
            return SeverityLevel.MEDIUM
        else:
            return SeverityLevel.LOW

    def export_report(self, report: AnomalyReport, output_path: str, 
                      format: str = "json") -> str:
        """
        Export anomaly report ke file.

        Args:
            report: AnomalyReport object
            output_path: Output file path
            format: "json" atau "markdown"

        Returns:
            File path
        """
        if format == "json":
            import json
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(report.to_dict(), f, indent=2, ensure_ascii=False)

        elif format == "markdown":
            md = f"""# Anomaly Detection Report

**Target:** {report.target}  
**Generated:** {report.generated_at}  
**Total Anomalies:** {len(report.anomalies)}

## Summary

| Metric | Value |
|--------|-------|
| Critical | {report.summary["by_severity"].get("critical", 0)} |
| High | {report.summary["by_severity"].get("high", 0)} |
| Medium | {report.summary["by_severity"].get("medium", 0)} |
| Low | {report.summary["by_severity"].get("low", 0)} |
| Info | {report.summary["by_severity"].get("info", 0)} |

## Statistics

| Metric | Value |
|--------|-------|
| Average Score | {report.statistics["average_score"]:.2%} |
| Max Score | {report.statistics["max_score"]:.2%} |
| Average Confidence | {report.statistics["average_confidence"]:.2%} |

## Detected Anomalies

"""
            for i, anomaly in enumerate(report.anomalies, 1):
                md += f"""### {i}. [{anomaly.severity.value.upper()}] {anomaly.anomaly_type.value.title()}

**Entity:** {anomaly.entity_id} ({anomaly.entity_type})  
**Score:** {anomaly.score:.2%} | **Confidence:** {anomaly.confidence:.2%}

{anomaly.description}

**Recommended Action:** {anomaly.recommended_action}

---

"""

            with open(output_path, "w", encoding="utf-8") as f:
                f.write(md)

        logger.info(f"[AnomalyDetector] Report exported to {output_path}")
        return output_path


# ============== CONVENIENCE FUNCTIONS ==============

def detect_outliers(data: List[float], labels: Optional[List[str]] = None) -> List[Anomaly]:
    """Quick statistical outlier detection."""
    detector = AnomalyDetector()
    return detector.detect_statistical_outliers(data, labels)


def detect_graph_outliers(nodes: List[Dict], relationships: List[Dict]) -> List[Anomaly]:
    """Quick graph anomaly detection."""
    detector = AnomalyDetector()
    return detector.detect_graph_anomalies(nodes, relationships)


# ============== MAIN ==============

if __name__ == "__main__":
    print("=" * 70)
    print("Anomaly Detection Module")
    print("=" * 70)

    detector = AnomalyDetector()

    # Demo 1: Statistical outliers
    print("\n[*] Detecting statistical outliers...")
    data = [10, 12, 11, 13, 10, 11, 100, 12, 11, 10, 150, 11]
    labels = [f"item_{i}" for i in range(len(data))]

    stat_anomalies = detector.detect_statistical_outliers(data, labels, "Metric")
    print(f"[+] Found {len(stat_anomalies)} statistical anomalies")
    for a in stat_anomalies:
        print(f"    - {a.entity_id}: {a.description} (score: {a.score:.2%})")

    # Demo 2: Graph anomalies
    print("\n[*] Detecting graph anomalies...")
    nodes = [
        {"id": "person_1", "label": "Person", "properties": {"name": "Alice"}},
        {"id": "person_2", "label": "Person", "properties": {"name": "Bob"}},
        {"id": "person_3", "label": "Person", "properties": {"name": "Charlie"}},
        {"id": "person_4", "label": "Person", "properties": {"name": "David"}},
        {"id": "person_5", "label": "Person", "properties": {"name": "Eve"}},
        {"id": "hub", "label": "Person", "properties": {"name": "Hub"}},
        {"id": "isolated", "label": "Person", "properties": {"name": "Isolated"}},
    ]

    relationships = [
        {"from": "hub", "to": "person_1", "type": "KNOWS"},
        {"from": "hub", "to": "person_2", "type": "KNOWS"},
        {"from": "hub", "to": "person_3", "type": "KNOWS"},
        {"from": "hub", "to": "person_4", "type": "KNOWS"},
        {"from": "hub", "to": "person_5", "type": "KNOWS"},
        {"from": "person_1", "to": "person_2", "type": "KNOWS"},
        {"from": "person_2", "to": "person_3", "type": "KNOWS"},
    ]

    graph_anomalies = detector.detect_graph_anomalies(nodes, relationships)
    print(f"[+] Found {len(graph_anomalies)} graph anomalies")
    for a in graph_anomalies:
        print(f"    - {a.entity_id}: {a.description} (severity: {a.severity.value})")

    # Demo 3: Temporal anomalies
    print("\n[*] Detecting temporal anomalies...")
    events = [
        {"timestamp": "2024-01-01T10:00:00", "type": "login"},
        {"timestamp": "2024-01-01T10:05:00", "type": "login"},
        {"timestamp": "2024-01-01T10:10:00", "type": "login"},
        {"timestamp": "2024-01-01T10:15:00", "type": "login"},
        {"timestamp": "2024-01-01T10:20:00", "type": "login"},
        {"timestamp": "2024-01-01T10:25:00", "type": "login"},
        {"timestamp": "2024-01-01T10:30:00", "type": "login"},
        {"timestamp": "2024-01-05T10:00:00", "type": "login"},
    ]

    temp_anomalies = detector.detect_temporal_anomalies(events, "user_123")
    print(f"[+] Found {len(temp_anomalies)} temporal anomalies")
    for a in temp_anomalies:
        print(f"    - {a.anomaly_id}: {a.description}")

    # Demo 4: Full detection
    print("\n[*] Running full detection...")
    report = detector.run_full_detection(nodes, relationships, events, "Demo Investigation")
    print(f"[+] Report: {len(report.anomalies)} total anomalies")
    print(f"    Critical: {report.summary['by_severity'].get('critical', 0)}")
    print(f"    High: {report.summary['by_severity'].get('high', 0)}")
    print(f"    Medium: {report.summary['by_severity'].get('medium', 0)}")

    # Export
    print("\n[*] Exporting report...")
    detector.export_report(report, "/mnt/agents/output/anomaly_report.json", "json")
    detector.export_report(report, "/mnt/agents/output/anomaly_report.md", "markdown")
    print("[+] Reports saved!")

    print("\n" + "=" * 70)
    print("Anomaly Detection Demo Complete!")
    print("=" * 70)