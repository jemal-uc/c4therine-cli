"""
confidence_engine.py - Confidence Scoring System
Part of OSINT Intelligence Platform v4

Menghitung tingkat kepercayaan (confidence score) untuk setiap entitas,
relasi, dan kesimpulan dalam investigasi OSINT.

Features:
- Entity confidence scoring (0.0 - 1.0)
- Relationship confidence scoring
- Source reliability weighting
- Cross-validation scoring
- Temporal decay scoring
- Aggregate confidence untuk findings
- Confidence report generation
"""

import math
import logging
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from collections import defaultdict

logger = logging.getLogger("osint.confidence_engine")


class SourceReliability(Enum):
    """
    Source reliability ratings berdasarkan NATO OSINT standards.
    """
    A = ("a", "Completely reliable", 1.0)
    B = ("b", "Usually reliable", 0.8)
    C = ("c", "Fairly reliable", 0.6)
    D = ("d", "Not usually reliable", 0.4)
    E = ("e", "Unreliable", 0.2)
    F = ("f", "Reliability cannot be judged", 0.5)

    def __init__(self, code: str, description: str, weight: float):
        self.code = code
        self.description = description
        self.weight = weight


class InformationCredibility(Enum):
    """
    Information credibility ratings berdasarkan NATO OSINT standards.
    """
    ONE = ("1", "Confirmed", 1.0)
    TWO = ("2", "Probably true", 0.8)
    THREE = ("3", "Possibly true", 0.6)
    FOUR = ("4", "Doubtful", 0.4)
    FIVE = ("5", "Improbable", 0.2)
    SIX = ("6", "Truth cannot be judged", 0.5)

    def __init__(self, code: str, description: str, weight: float):
        self.code = code
        self.description = description
        self.weight = weight


@dataclass
class ConfidenceFactor:
    """
    Single factor yang mempengaruhi confidence score.
    """
    name: str
    weight: float  # 0.0 - 1.0
    score: float   # 0.0 - 1.0
    description: str = ""

    @property
    def weighted_score(self) -> float:
        """Calculate weighted score."""
        return self.score * self.weight


@dataclass
class EntityConfidence:
    """
    Confidence assessment untuk sebuah entity.
    """
    entity_id: str
    entity_type: str
    base_score: float
    factors: List[ConfidenceFactor] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()

    @property
    def overall_score(self) -> float:
        """
        Calculate overall confidence score.
        Menggunakan weighted average dari semua factors.
        """
        if not self.factors:
            return self.base_score

        total_weight = sum(f.weight for f in self.factors)
        if total_weight == 0:
            return self.base_score

        weighted_sum = sum(f.weighted_score for f in self.factors)
        return min(1.0, max(0.0, weighted_sum / total_weight))

    @property
    def confidence_level(self) -> str:
        """
        Get confidence level sebagai string.
        """
        score = self.overall_score
        if score >= 0.9:
            return "Very High"
        elif score >= 0.7:
            return "High"
        elif score >= 0.5:
            return "Medium"
        elif score >= 0.3:
            return "Low"
        else:
            return "Very Low"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "base_score": self.base_score,
            "overall_score": self.overall_score,
            "confidence_level": self.confidence_level,
            "factors": [
                {
                    "name": f.name,
                    "weight": f.weight,
                    "score": f.score,
                    "weighted_score": f.weighted_score,
                    "description": f.description
                }
                for f in self.factors
            ],
            "sources": self.sources,
            "timestamp": self.timestamp
        }


@dataclass
class RelationshipConfidence:
    """
    Confidence assessment untuk sebuah relationship.
    """
    source_id: str
    target_id: str
    rel_type: str
    base_score: float
    factors: List[ConfidenceFactor] = field(default_factory=list)
    evidence_count: int = 0
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()

    @property
    def overall_score(self) -> float:
        """Calculate overall confidence score."""
        if not self.factors:
            return self.base_score

        total_weight = sum(f.weight for f in self.factors)
        if total_weight == 0:
            return self.base_score

        weighted_sum = sum(f.weighted_score for f in self.factors)
        return min(1.0, max(0.0, weighted_sum / total_weight))

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "rel_type": self.rel_type,
            "base_score": self.base_score,
            "overall_score": self.overall_score,
            "evidence_count": self.evidence_count,
            "factors": [
                {
                    "name": f.name,
                    "weight": f.weight,
                    "score": f.score,
                    "weighted_score": f.weighted_score
                }
                for f in self.factors
            ],
            "timestamp": self.timestamp
        }


class ConfidenceEngine:
    """
    Engine untuk menghitung dan mengelola confidence scores
    dalam investigasi OSINT.
    """

    # Default weights untuk berbagai factors
    DEFAULT_WEIGHTS = {
        "source_reliability": 0.25,
        "information_credibility": 0.25,
        "cross_validation": 0.20,
        "temporal_freshness": 0.15,
        "corroboration": 0.15,
    }

    # Temporal decay parameters
    TEMPORAL_HALF_LIFE_DAYS = {
        "default": 365,
        "email": 730,
        "username": 365,
        "domain": 1825,  # 5 years
        "phone": 730,
        "location": 365,
        "employment": 730,
        "breach": 1095,  # 3 years
    }

    def __init__(self, weights: Optional[Dict[str, float]] = None):
        """
        Initialize confidence engine.

        Args:
            weights: Custom weights untuk confidence factors
        """
        self.weights = weights or self.DEFAULT_WEIGHTS.copy()

        # Storage untuk confidence assessments
        self._entity_confidences: Dict[str, EntityConfidence] = {}
        self._relationship_confidences: Dict[str, RelationshipConfidence] = {}

        logger.info("[ConfidenceEngine] Initialized")

    def calculate_source_reliability(self, 
                                      source_name: str,
                                      source_type: str,
                                      historical_accuracy: Optional[float] = None,
                                      is_official: bool = False,
                                      is_verified: bool = False) -> ConfidenceFactor:
        """
        Calculate source reliability factor.

        Args:
            source_name: Name of data source
            source_type: Type of source (social_media, breach_db, official, etc.)
            historical_accuracy: Historical accuracy score (0.0 - 1.0)
            is_official: Whether source is official/government
            is_verified: Whether source is verified

        Returns:
            ConfidenceFactor
        """
        score = 0.5  # Default
        description = f"Source: {source_name}"

        # Base score by source type
        source_type_scores = {
            "official_registry": 0.95,
            "government_database": 0.90,
            "verified_api": 0.85,
            "breach_database": 0.75,
            "social_media_verified": 0.70,
            "social_media": 0.55,
            "forum": 0.45,
            "dark_web": 0.35,
            "unknown": 0.30,
        }

        score = source_type_scores.get(source_type, 0.5)

        # Adjust berdasarkan attributes
        if is_official:
            score = min(1.0, score + 0.1)
            description += " | Official source"

        if is_verified:
            score = min(1.0, score + 0.1)
            description += " | Verified"

        if historical_accuracy is not None:
            score = (score + historical_accuracy) / 2
            description += f" | Historical accuracy: {historical_accuracy:.2%}"

        return ConfidenceFactor(
            name="source_reliability",
            weight=self.weights["source_reliability"],
            score=score,
            description=description
        )

    def calculate_information_credibility(self,
                                           data: Dict[str, Any],
                                           is_corroborated: bool = False,
                                           has_direct_evidence: bool = False,
                                           consistency_score: Optional[float] = None) -> ConfidenceFactor:
        """
        Calculate information credibility factor.

        Args:
            data: Data dictionary
            is_corroborated: Whether data is corroborated by other sources
            has_direct_evidence: Whether there is direct evidence
            consistency_score: Consistency score (0.0 - 1.0)

        Returns:
            ConfidenceFactor
        """
        score = 0.5
        description = "Base credibility"

        # Check data completeness
        completeness = self._calculate_completeness(data)
        score = score * (0.5 + 0.5 * completeness)
        description += f" | Completeness: {completeness:.2%}"

        if is_corroborated:
            score = min(1.0, score + 0.2)
            description += " | Corroborated"

        if has_direct_evidence:
            score = min(1.0, score + 0.15)
            description += " | Direct evidence"

        if consistency_score is not None:
            score = (score + consistency_score) / 2
            description += f" | Consistency: {consistency_score:.2%}"

        return ConfidenceFactor(
            name="information_credibility",
            weight=self.weights["information_credibility"],
            score=score,
            description=description
        )

    def calculate_cross_validation(self,
                                    entity_data: Dict[str, Any],
                                    matching_sources: int,
                                    total_sources: int,
                                    conflicting_sources: int = 0) -> ConfidenceFactor:
        """
        Calculate cross-validation factor.

        Args:
            entity_data: Entity data
            matching_sources: Number of sources yang match
            total_sources: Total number of sources checked
            conflicting_sources: Number of conflicting sources

        Returns:
            ConfidenceFactor
        """
        if total_sources == 0:
            score = 0.0
            description = "No sources for cross-validation"
        else:
            match_ratio = matching_sources / total_sources
            conflict_penalty = min(0.5, conflicting_sources * 0.15)

            score = max(0.0, match_ratio - conflict_penalty)
            description = (
                f"Cross-validation: {matching_sources}/{total_sources} match, "
                f"{conflicting_sources} conflict"
            )

        return ConfidenceFactor(
            name="cross_validation",
            weight=self.weights["cross_validation"],
            score=score,
            description=description
        )

    def calculate_temporal_freshness(self,
                                     timestamp: Optional[str],
                                     entity_type: str = "default") -> ConfidenceFactor:
        """
        Calculate temporal freshness factor.

        Args:
            timestamp: Data timestamp (ISO format)
            entity_type: Type of entity untuk half-life calculation

        Returns:
            ConfidenceFactor
        """
        if not timestamp:
            score = 0.5
            description = "No timestamp available"
        else:
            try:
                data_time = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                now = datetime.now()
                age_days = (now - data_time).total_seconds() / 86400

                half_life = self.TEMPORAL_HALF_LIFE_DAYS.get(entity_type, 365)

                # Exponential decay
                score = math.exp(-0.693 * age_days / half_life)
                description = (
                    f"Age: {age_days:.1f} days | "
                    f"Half-life: {half_life} days | "
                    f"Freshness: {score:.2%}"
                )
            except Exception as e:
                score = 0.5
                description = f"Timestamp parse error: {e}"

        return ConfidenceFactor(
            name="temporal_freshness",
            weight=self.weights["temporal_freshness"],
            score=score,
            description=description
        )

    def calculate_corroboration(self,
                                 primary_source: str,
                                 corroborating_sources: List[str],
                                 conflicting_data: Optional[List[Dict]] = None) -> ConfidenceFactor:
        """
        Calculate corroboration factor.

        Args:
            primary_source: Primary data source
            corroborating_sources: List of corroborating sources
            conflicting_data: List of conflicting data points

        Returns:
            ConfidenceFactor
        """
        corroboration_count = len(corroborating_sources)
        conflict_count = len(conflicting_data) if conflicting_data else 0

        # Base score dari corroboration
        if corroboration_count == 0:
            base_score = 0.3
        elif corroboration_count == 1:
            base_score = 0.6
        elif corroboration_count <= 3:
            base_score = 0.8
        else:
            base_score = 0.95

        # Apply conflict penalty
        conflict_penalty = min(0.4, conflict_count * 0.15)
        score = max(0.0, base_score - conflict_penalty)

        description = (
            f"Corroboration: {corroboration_count} sources"
        )
        if conflict_count > 0:
            description += f" | Conflicts: {conflict_count}"

        return ConfidenceFactor(
            name="corroboration",
            weight=self.weights["corroboration"],
            score=score,
            description=description
        )

    def assess_entity(self,
                      entity_id: str,
                      entity_type: str,
                      data: Dict[str, Any],
                      sources: List[Dict[str, Any]],
                      timestamp: Optional[str] = None,
                      base_score: float = 0.5) -> EntityConfidence:
        """
        Perform complete confidence assessment untuk sebuah entity.

        Args:
            entity_id: Unique entity identifier
            entity_type: Type of entity
            data: Entity data dictionary
            sources: List of source dictionaries
            timestamp: Data timestamp
            base_score: Base confidence score

        Returns:
            EntityConfidence object
        """
        factors = []
        source_names = []

        # Calculate factors dari setiap source
        for source in sources:
            source_name = source.get("name", "unknown")
            source_type = source.get("type", "unknown")
            source_names.append(source_name)

            # Source reliability
            reliability = self.calculate_source_reliability(
                source_name=source_name,
                source_type=source_type,
                historical_accuracy=source.get("historical_accuracy"),
                is_official=source.get("is_official", False),
                is_verified=source.get("is_verified", False)
            )
            factors.append(reliability)

        # Information credibility
        credibility = self.calculate_information_credibility(
            data=data,
            is_corroborated=len(sources) > 1,
            has_direct_evidence=any(s.get("has_direct_evidence", False) for s in sources),
            consistency_score=self._calculate_consistency(sources)
        )
        factors.append(credibility)

        # Cross-validation
        matching = sum(1 for s in sources if s.get("matches", False))
        conflicting = sum(1 for s in sources if s.get("conflicts", False))
        cross_val = self.calculate_cross_validation(
            entity_data=data,
            matching_sources=matching,
            total_sources=len(sources),
            conflicting_sources=conflicting
        )
        factors.append(cross_val)

        # Temporal freshness
        freshness = self.calculate_temporal_freshness(
            timestamp=timestamp or data.get("timestamp"),
            entity_type=entity_type
        )
        factors.append(freshness)

        # Corroboration
        corroboration = self.calculate_corroboration(
            primary_source=source_names[0] if source_names else "unknown",
            corroborating_sources=source_names[1:] if len(source_names) > 1 else [],
            conflicting_data=[s for s in sources if s.get("conflicts", False)]
        )
        factors.append(corroboration)

        assessment = EntityConfidence(
            entity_id=entity_id,
            entity_type=entity_type,
            base_score=base_score,
            factors=factors,
            sources=source_names,
            timestamp=datetime.now().isoformat()
        )

        self._entity_confidences[entity_id] = assessment

        logger.info(
            f"[ConfidenceEngine] Entity {entity_id}: "
            f"{assessment.overall_score:.2%} ({assessment.confidence_level})"
        )

        return assessment

    def assess_relationship(self,
                            source_id: str,
                            target_id: str,
                            rel_type: str,
                            evidence: List[Dict[str, Any]],
                            base_score: float = 0.5) -> RelationshipConfidence:
        """
        Perform confidence assessment untuk sebuah relationship.

        Args:
            source_id: Source entity ID
            target_id: Target entity ID
            rel_type: Relationship type
            evidence: List of evidence dictionaries
            base_score: Base confidence score

        Returns:
            RelationshipConfidence object
        """
        factors = []

        # Evidence strength
        evidence_count = len(evidence)
        evidence_score = min(1.0, evidence_count / 5)  # Max at 5 pieces
        factors.append(ConfidenceFactor(
            name="evidence_strength",
            weight=0.3,
            score=evidence_score,
            description=f"Evidence count: {evidence_count}"
        ))

        # Source diversity
        source_types = set(e.get("source_type", "unknown") for e in evidence)
        diversity_score = min(1.0, len(source_types) / 3)
        factors.append(ConfidenceFactor(
            name="source_diversity",
            weight=0.2,
            score=diversity_score,
            description=f"Source types: {len(source_types)}"
        ))

        # Direct vs indirect evidence
        direct_count = sum(1 for e in evidence if e.get("is_direct", False))
        direct_ratio = direct_count / evidence_count if evidence_count > 0 else 0
        factors.append(ConfidenceFactor(
            name="direct_evidence",
            weight=0.25,
            score=direct_ratio,
            description=f"Direct evidence: {direct_count}/{evidence_count}"
        ))

        # Temporal consistency
        timestamps = [e.get("timestamp") for e in evidence if e.get("timestamp")]
        if timestamps:
            try:
                times = [datetime.fromisoformat(t.replace("Z", "+00:00")) for t in timestamps]
                time_span = (max(times) - min(times)).total_seconds() / 86400
                consistency = math.exp(-0.1 * time_span)  # Decay dengan time span
                factors.append(ConfidenceFactor(
                    name="temporal_consistency",
                    weight=0.15,
                    score=consistency,
                    description=f"Time span: {time_span:.1f} days"
                ))
            except:
                pass

        # Entity confidence correlation
        source_conf = self._entity_confidences.get(source_id)
        target_conf = self._entity_confidences.get(target_id)

        if source_conf and target_conf:
            entity_score = (source_conf.overall_score + target_conf.overall_score) / 2
            factors.append(ConfidenceFactor(
                name="entity_confidence",
                weight=0.1,
                score=entity_score,
                description="Based on connected entity confidences"
            ))

        assessment = RelationshipConfidence(
            source_id=source_id,
            target_id=target_id,
            rel_type=rel_type,
            base_score=base_score,
            factors=factors,
            evidence_count=evidence_count,
            timestamp=datetime.now().isoformat()
        )

        rel_key = f"{source_id}_{rel_type}_{target_id}"
        self._relationship_confidences[rel_key] = assessment

        logger.info(
            f"[ConfidenceEngine] Relationship {rel_key}: "
            f"{assessment.overall_score:.2%}"
        )

        return assessment

    def get_entity_confidence(self, entity_id: str) -> Optional[EntityConfidence]:
        """Get confidence assessment untuk entity."""
        return self._entity_confidences.get(entity_id)

    def get_relationship_confidence(self, source_id: str, target_id: str, 
                                     rel_type: str) -> Optional[RelationshipConfidence]:
        """Get confidence assessment untuk relationship."""
        rel_key = f"{source_id}_{rel_type}_{target_id}"
        return self._relationship_confidences.get(rel_key)

    def get_low_confidence_entities(self, threshold: float = 0.5) -> List[EntityConfidence]:
        """
        Get entities dengan confidence di bawah threshold.

        Args:
            threshold: Minimum confidence score

        Returns:
            List of EntityConfidence objects
        """
        return [
            ec for ec in self._entity_confidences.values()
            if ec.overall_score < threshold
        ]

    def get_high_confidence_entities(self, threshold: float = 0.8) -> List[EntityConfidence]:
        """
        Get entities dengan confidence di atas threshold.

        Args:
            threshold: Minimum confidence score

        Returns:
            List of EntityConfidence objects
        """
        return [
            ec for ec in self._entity_confidences.values()
            if ec.overall_score >= threshold
        ]

    def generate_confidence_report(self) -> Dict[str, Any]:
        """
        Generate overall confidence report.

        Returns:
            Dictionary dengan confidence statistics
        """
        entity_scores = [ec.overall_score for ec in self._entity_confidences.values()]
        rel_scores = [rc.overall_score for rc in self._relationship_confidences.values()]

        report = {
            "generated_at": datetime.now().isoformat(),
            "entity_confidences": {
                "count": len(entity_scores),
                "average": sum(entity_scores) / len(entity_scores) if entity_scores else 0,
                "median": sorted(entity_scores)[len(entity_scores)//2] if entity_scores else 0,
                "min": min(entity_scores) if entity_scores else 0,
                "max": max(entity_scores) if entity_scores else 0,
                "distribution": {
                    "very_high": sum(1 for s in entity_scores if s >= 0.9),
                    "high": sum(1 for s in entity_scores if 0.7 <= s < 0.9),
                    "medium": sum(1 for s in entity_scores if 0.5 <= s < 0.7),
                    "low": sum(1 for s in entity_scores if 0.3 <= s < 0.5),
                    "very_low": sum(1 for s in entity_scores if s < 0.3),
                }
            },
            "relationship_confidences": {
                "count": len(rel_scores),
                "average": sum(rel_scores) / len(rel_scores) if rel_scores else 0,
                "median": sorted(rel_scores)[len(rel_scores)//2] if rel_scores else 0,
            },
            "low_confidence_entities": [
                ec.to_dict() for ec in self.get_low_confidence_entities()
            ],
            "high_confidence_entities": [
                ec.to_dict() for ec in self.get_high_confidence_entities()
            ]
        }

        return report

    def _calculate_completeness(self, data: Dict[str, Any]) -> float:
        """
        Calculate data completeness score.

        Args:
            data: Data dictionary

        Returns:
            Completeness score (0.0 - 1.0)
        """
        if not data:
            return 0.0

        # Count non-empty values
        total_fields = len(data)
        filled_fields = sum(1 for v in data.values() if v is not None and v != "")

        return filled_fields / total_fields if total_fields > 0 else 0.0

    def _calculate_consistency(self, sources: List[Dict[str, Any]]) -> float:
        """
        Calculate consistency score across sources.

        Args:
            sources: List of source dictionaries

        Returns:
            Consistency score (0.0 - 1.0)
        """
        if len(sources) < 2:
            return 1.0  # Single source is consistent by default

        # Extract comparable fields
        comparable_fields = defaultdict(list)
        for source in sources:
            for key, value in source.get("data", {}).items():
                if value is not None:
                    comparable_fields[key].append(value)

        if not comparable_fields:
            return 0.5

        # Calculate consistency per field
        consistency_scores = []
        for field, values in comparable_fields.items():
            if len(values) < 2:
                continue

            # Check how many values match the most common value
            from collections import Counter
            most_common_count = Counter(values).most_common(1)[0][1]
            field_consistency = most_common_count / len(values)
            consistency_scores.append(field_consistency)

        return sum(consistency_scores) / len(consistency_scores) if consistency_scores else 0.5

    def export_report(self, output_path: str, format: str = "json") -> str:
        """
        Export confidence report ke file.

        Args:
            output_path: Output file path
            format: "json" atau "markdown"

        Returns:
            File path
        """
        report = self.generate_confidence_report()

        if format == "json":
            import json
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)

        elif format == "markdown":
            md = f"""# Confidence Assessment Report

**Generated:** {report["generated_at"]}

## Entity Confidences

| Metric | Value |
|--------|-------|
| Total Entities | {report["entity_confidences"]["count"]} |
| Average Score | {report["entity_confidences"]["average"]:.2%} |
| Median Score | {report["entity_confidences"]["median"]:.2%} |
| Min Score | {report["entity_confidences"]["min"]:.2%} |
| Max Score | {report["entity_confidences"]["max"]:.2%} |

### Distribution

| Level | Count |
|-------|-------|
| Very High (>=90%) | {report["entity_confidences"]["distribution"]["very_high"]} |
| High (70-90%) | {report["entity_confidences"]["distribution"]["high"]} |
| Medium (50-70%) | {report["entity_confidences"]["distribution"]["medium"]} |
| Low (30-50%) | {report["entity_confidences"]["distribution"]["low"]} |
| Very Low (<30%) | {report["entity_confidences"]["distribution"]["very_low"]} |

## Relationship Confidences

| Metric | Value |
|--------|-------|
| Total Relationships | {report["relationship_confidences"]["count"]} |
| Average Score | {report["relationship_confidences"]["average"]:.2%} |

## Low Confidence Entities

"""
            for ec in report["low_confidence_entities"][:10]:
                md += f"- **{ec['entity_id']}** ({ec['entity_type']}): {ec['overall_score']:.2%}\n"

            with open(output_path, "w", encoding="utf-8") as f:
                f.write(md)

        logger.info(f"[ConfidenceEngine] Report exported to {output_path}")
        return output_path


# ============== CONVENIENCE FUNCTIONS ==============

def quick_assess(entity_id: str, entity_type: str, data: Dict[str, Any],
                  sources: List[Dict[str, Any]]) -> EntityConfidence:
    """Quick entity confidence assessment."""
    engine = ConfidenceEngine()
    return engine.assess_entity(entity_id, entity_type, data, sources)


def assess_data_sources(sources: List[Dict[str, Any]]) -> Dict[str, float]:
    """
    Assess multiple data sources dan return reliability scores.

    Args:
        sources: List of source dictionaries

    Returns:
        Dictionary mapping source names ke reliability scores
    """
    engine = ConfidenceEngine()
    scores = {}

    for source in sources:
        name = source.get("name", "unknown")
        factor = engine.calculate_source_reliability(
            source_name=name,
            source_type=source.get("type", "unknown"),
            historical_accuracy=source.get("historical_accuracy"),
            is_official=source.get("is_official", False),
            is_verified=source.get("is_verified", False)
        )
        scores[name] = factor.score

    return scores


# ============== MAIN ==============

if __name__ == "__main__":
    print("=" * 70)
    print("Confidence Engine Module")
    print("=" * 70)

    engine = ConfidenceEngine()

    # Demo entity assessment
    print("\n[*] Assessing entity confidence...")

    entity_data = {
        "name": "John Doe",
        "email": "john.doe@example.com",
        "username": "johndoe",
        "platform": "twitter"
    }

    sources = [
        {
            "name": "Twitter API",
            "type": "social_media_verified",
            "is_verified": True,
            "historical_accuracy": 0.85,
            "data": {"username": "johndoe", "name": "John Doe"},
            "matches": True
        },
        {
            "name": "HaveIBeenPwned",
            "type": "breach_database",
            "data": {"email": "john.doe@example.com"},
            "matches": True
        },
        {
            "name": "LinkedIn",
            "type": "social_media",
            "data": {"name": "John Doe", "company": "Example Corp"},
            "matches": True
        }
    ]

    assessment = engine.assess_entity(
        entity_id="person_john_doe",
        entity_type="Person",
        data=entity_data,
        sources=sources,
        timestamp="2024-01-15T10:00:00"
    )

    print(f"\n[+] Entity: {assessment.entity_id}")
    print(f"    Overall Score: {assessment.overall_score:.2%}")
    print(f"    Confidence Level: {assessment.confidence_level}")
    print(f"\n    Factors:")
    for factor in assessment.factors:
        print(f"      - {factor.name}: {factor.score:.2%} (weight: {factor.weight})")
        print(f"        {factor.description}")

    # Demo relationship assessment
    print("\n[*] Assessing relationship confidence...")

    evidence = [
        {"source_type": "social_media", "is_direct": True, "timestamp": "2024-01-10"},
        {"source_type": "breach_db", "is_direct": False, "timestamp": "2024-01-12"},
        {"source_type": "official", "is_direct": True, "timestamp": "2024-01-15"},
    ]

    rel_assessment = engine.assess_relationship(
        source_id="person_john_doe",
        target_id="email_john_example",
        rel_type="HAS_EMAIL",
        evidence=evidence
    )

    print(f"\n[+] Relationship: {rel_assessment.source_id} -> {rel_assessment.target_id}")
    print(f"    Overall Score: {rel_assessment.overall_score:.2%}")
    print(f"    Evidence Count: {rel_assessment.evidence_count}")

    # Generate report
    print("\n[*] Generating confidence report...")
    report = engine.generate_confidence_report()
    print(f"[+] Report: {json.dumps(report, indent=2, default=str)}")

    # Export report
    print("\n[*] Exporting report...")
    engine.export_report("/mnt/agents/output/confidence_report.json", "json")
    engine.export_report("/mnt/agents/output/confidence_report.md", "markdown")
    print("[+] Reports saved!")

    print("\n" + "=" * 70)
    print("Confidence Engine Demo Complete!")
    print("=" * 70)