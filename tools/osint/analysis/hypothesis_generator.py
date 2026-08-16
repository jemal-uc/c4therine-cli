"""
hypothesis_generator.py - Auto Hypothesis Generation Module
Part of OSINT Intelligence Platform v4

Secara otomatis menghasilkan hipotesis, pertanyaan investigasi,
dan kemungkinan skenario berdasarkan data OSINT yang terkumpul.

Features:
- Pattern-based hypothesis generation
- Gap analysis untuk missing information
- Scenario generation (best/worst/likely case)
- Question generation untuk follow-up investigation
- Hypothesis scoring dan ranking
- Hypothesis testing framework
- Confidence-based hypothesis filtering
"""

import re
import json
import logging
from typing import Dict, List, Optional, Tuple, Any, Union, Set
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from collections import defaultdict, Counter

logger = logging.getLogger("osint.hypothesis_generator")


class HypothesisType(Enum):
    """Types of hypotheses."""
    IDENTITY = "identity"
    RELATIONSHIP = "relationship"
    LOCATION = "location"
    TEMPORAL = "temporal"
    BEHAVIORAL = "behavioral"
    THREAT = "threat"
    NETWORK = "network"
    GAP = "gap"


class HypothesisStatus(Enum):
    """Status of hypothesis."""
    UNTESTED = "untested"
    SUPPORTED = "supported"
    PARTIALLY_SUPPORTED = "partially_supported"
    UNSUPPORTED = "unsupported"
    CONTRADICTED = "contradicted"


@dataclass
class EvidenceLink:
    """Link antara evidence dan hypothesis."""
    evidence_id: str
    evidence_type: str
    description: str
    supports: bool  # True = supports, False = contradicts
    strength: float  # 0.0 - 1.0


@dataclass
class Hypothesis:
    """Single hypothesis."""
    hypothesis_id: str
    hypothesis_type: HypothesisType
    statement: str
    description: str
    confidence: float  # 0.0 - 1.0
    status: HypothesisStatus
    evidence_links: List[EvidenceLink] = field(default_factory=list)
    related_entities: List[str] = field(default_factory=list)
    generated_at: str = ""
    tested_at: Optional[str] = None

    def __post_init__(self):
        if not self.generated_at:
            self.generated_at = datetime.now().isoformat()

    @property
    def support_score(self) -> float:
        """Calculate net support score dari evidence."""
        if not self.evidence_links:
            return 0.0

        supporting = sum(e.strength for e in self.evidence_links if e.supports)
        contradicting = sum(e.strength for e in self.evidence_links if not e.supports)

        return (supporting - contradicting) / len(self.evidence_links)

    @property
    def evidence_count(self) -> Dict[str, int]:
        """Count supporting dan contradicting evidence."""
        supporting = sum(1 for e in self.evidence_links if e.supports)
        contradicting = sum(1 for e in self.evidence_links if not e.supports)
        return {"supporting": supporting, "contradicting": contradicting}

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "hypothesis_id": self.hypothesis_id,
            "hypothesis_type": self.hypothesis_type.value,
            "statement": self.statement,
            "description": self.description,
            "confidence": self.confidence,
            "status": self.status.value,
            "support_score": self.support_score,
            "evidence": self.evidence_count,
            "evidence_links": [
                {
                    "evidence_id": e.evidence_id,
                    "type": e.evidence_type,
                    "supports": e.supports,
                    "strength": e.strength
                }
                for e in self.evidence_links
            ],
            "related_entities": self.related_entities,
            "generated_at": self.generated_at,
            "tested_at": self.tested_at
        }


@dataclass
class InvestigationQuestion:
    """Question yang dihasilkan untuk follow-up investigation."""
    question_id: str
    question: str
    question_type: str
    priority: str  # critical, high, medium, low
    related_hypothesis: Optional[str] = None
    suggested_sources: List[str] = field(default_factory=list)
    expected_answer_type: str = ""
    generated_at: str = ""

    def __post_init__(self):
        if not self.generated_at:
            self.generated_at = datetime.now().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "question_id": self.question_id,
            "question": self.question,
            "question_type": self.question_type,
            "priority": self.priority,
            "related_hypothesis": self.related_hypothesis,
            "suggested_sources": self.suggested_sources,
            "expected_answer_type": self.expected_answer_type,
            "generated_at": self.generated_at
        }


@dataclass
class Scenario:
    """Generated scenario (best/worst/likely case)."""
    scenario_id: str
    scenario_type: str  # best_case, worst_case, likely_case
    title: str
    description: str
    probability: float  # 0.0 - 1.0
    key_assumptions: List[str] = field(default_factory=list)
    implications: List[str] = field(default_factory=list)
    generated_at: str = ""

    def __post_init__(self):
        if not self.generated_at:
            self.generated_at = datetime.now().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "scenario_type": self.scenario_type,
            "title": self.title,
            "description": self.description,
            "probability": self.probability,
            "key_assumptions": self.key_assumptions,
            "implications": self.implications,
            "generated_at": self.generated_at
        }


class HypothesisGenerator:
    """
    AI-powered hypothesis generation engine untuk OSINT investigations.
    """

    # Pattern templates untuk hypothesis generation
    IDENTITY_PATTERNS = [
        "Target may have {count} additional aliases not yet discovered",
        "Identity {entity} may be connected to {other_entity}",
        "Target may be using {platform} under different username",
        "Real name may differ from known alias {alias}",
    ]

    RELATIONSHIP_PATTERNS = [
        "Connection between {entity1} and {entity2} may indicate {relationship_type}",
        "Shared {attribute} suggests possible association",
        "Mutual connections may reveal {insight}",
    ]

    LOCATION_PATTERNS = [
        "Target may have visited {location} based on {evidence}",
        "Current location may differ from registered address",
        "Multiple locations suggest {pattern}",
    ]

    TEMPORAL_PATTERNS = [
        "Activity spike on {date} may indicate {event}",
        "Gap in activity from {start} to {end} suggests {reason}",
        "Pattern change around {date} may signal {change}",
    ]

    THREAT_PATTERNS = [
        "Combination of {factors} may indicate elevated risk",
        "Presence of {indicator} suggests possible {threat_type}",
        "Target may be involved in {activity} based on {evidence}",
    ]

    GAP_PATTERNS = [
        "No {data_type} found - may indicate {reason} or {alternative}",
        "Missing {information} suggests possible {explanation}",
        "Absence of {indicator} is notable given {context}",
    ]

    def __init__(self, min_confidence: float = 0.3):
        """
        Initialize hypothesis generator.

        Args:
            min_confidence: Minimum confidence untuk generated hypotheses
        """
        self.min_confidence = min_confidence
        self._hypotheses: List[Hypothesis] = []
        self._questions: List[InvestigationQuestion] = []
        self._scenarios: List[Scenario] = []

        logger.info("[HypothesisGenerator] Initialized")

    # ==================== IDENTITY HYPOTHESES ====================

    def generate_identity_hypotheses(self,
                                      entities: List[Dict[str, Any]],
                                      target_id: str) -> List[Hypothesis]:
        """
        Generate hypotheses tentang identitas target.

        Args:
            entities: List of entity dictionaries
            target_id: Target entity ID

        Returns:
            List of Hypothesis objects
        """
        hypotheses = []

        # Get target entity
        target = next((e for e in entities if e.get("id") == target_id), None)
        if not target:
            return hypotheses

        target_props = target.get("properties", {})
        aliases = target_props.get("aliases", [])

        # Hypothesis 1: Additional aliases
        if len(aliases) >= 2:
            h = Hypothesis(
                hypothesis_id=f"hyp_id_alias_{target_id}",
                hypothesis_type=HypothesisType.IDENTITY,
                statement=f"Target may have additional undiscovered aliases beyond {len(aliases)} known ones",
                description=(
                    f"Target has {len(aliases)} known aliases: {', '.join(aliases[:3])}. "
                    f"Individuals with multiple aliases often have more."
                ),
                confidence=min(0.7, 0.4 + len(aliases) * 0.1),
                status=HypothesisStatus.UNTESTED,
                related_entities=[target_id]
            )
            hypotheses.append(h)

        # Hypothesis 2: Cross-platform presence
        usernames = [e for e in entities if e.get("label") == "Username"]
        platforms = set(u.get("properties", {}).get("platform", "") for u in usernames)

        if len(platforms) >= 2:
            h = Hypothesis(
                hypothesis_id=f"hyp_id_platform_{target_id}",
                hypothesis_type=HypothesisType.IDENTITY,
                statement=f"Target likely has presence on additional platforms beyond {len(platforms)} discovered",
                description=(
                    f"Found on {len(platforms)} platforms: {', '.join(platforms)}. "
                    f"Cross-platform users typically maintain 5+ profiles."
                ),
                confidence=min(0.8, 0.5 + len(platforms) * 0.05),
                status=HypothesisStatus.UNTESTED,
                related_entities=[u.get("id") for u in usernames]
            )
            hypotheses.append(h)

        # Hypothesis 3: Name variations
        name = target_props.get("name", "")
        if name:
            variations = self._generate_name_variations(name)
            if variations:
                h = Hypothesis(
                    hypothesis_id=f"hyp_id_namevar_{target_id}",
                    hypothesis_type=HypothesisType.IDENTITY,
                    statement=f"Target may use name variations: {', '.join(variations[:3])}",
                    description="Common name variations used untuk evasion atau branding",
                    confidence=0.5,
                    status=HypothesisStatus.UNTESTED,
                    related_entities=[target_id]
                )
                hypotheses.append(h)

        self._hypotheses.extend(hypotheses)
        logger.info(f"[HypothesisGenerator] Generated {len(hypotheses)} identity hypotheses")
        return hypotheses

    # ==================== RELATIONSHIP HYPOTHESES ====================

    def generate_relationship_hypotheses(self,
                                          nodes: List[Dict[str, Any]],
                                          relationships: List[Dict[str, Any]]) -> List[Hypothesis]:
        """
        Generate hypotheses tentang relationships antar entities.

        Args:
            nodes: List of node dictionaries
            relationships: List of relationship dictionaries

        Returns:
            List of Hypothesis objects
        """
        hypotheses = []

        # Analyze relationship patterns
        rel_types = Counter(r.get("type") for r in relationships)

        # Hypothesis 1: Strong connection indicator
        for rel_type, count in rel_types.items():
            if count >= 3:
                h = Hypothesis(
                    hypothesis_id=f"hyp_rel_strong_{rel_type}",
                    hypothesis_type=HypothesisType.RELATIONSHIP,
                    statement=f"Multiple {rel_type} relationships ({count}) suggest strong organizational tie",
                    description=f"Found {count} instances of {rel_type}, indicating persistent connection",
                    confidence=min(0.9, 0.5 + count * 0.08),
                    status=HypothesisStatus.UNTESTED
                )
                hypotheses.append(h)

        # Hypothesis 2: Missing expected relationships
        person_nodes = [n for n in nodes if n.get("label") == "Person"]
        email_nodes = [n for n in nodes if n.get("label") == "Email"]

        if person_nodes and not email_nodes:
            h = Hypothesis(
                hypothesis_id="hyp_rel_missing_email",
                hypothesis_type=HypothesisType.RELATIONSHIP,
                statement="No email addresses found - target may use disposable emails atau privacy protection",
                description="Absence of email dalam digital footprint is unusual",
                confidence=0.6,
                status=HypothesisStatus.UNTESTED
            )
            hypotheses.append(h)

        # Hypothesis 3: Network density
        if len(nodes) > 5 and len(relationships) > 0:
            density = len(relationships) / (len(nodes) * (len(nodes) - 1)) if len(nodes) > 1 else 0

            if density < 0.2:
                h = Hypothesis(
                    hypothesis_id="hyp_rel_sparse",
                    hypothesis_type=HypothesisType.RELATIONSHIP,
                    statement="Sparse network suggests compartmentalization atau limited investigation scope",
                    description=f"Network density is {density:.2f}, below typical threshold",
                    confidence=0.55,
                    status=HypothesisStatus.UNTESTED
                )
                hypotheses.append(h)

        self._hypotheses.extend(hypotheses)
        logger.info(f"[HypothesisGenerator] Generated {len(hypotheses)} relationship hypotheses")
        return hypotheses

    # ==================== LOCATION HYPOTHESES ====================

    def generate_location_hypotheses(self,
                                      locations: List[Dict[str, Any]],
                                      target_id: str) -> List[Hypothesis]:
        """
        Generate hypotheses tentang lokasi target.

        Args:
            locations: List of location dictionaries
            target_id: Target entity ID

        Returns:
            List of Hypothesis objects
        """
        hypotheses = []

        if not locations:
            h = Hypothesis(
                hypothesis_id=f"hyp_loc_none_{target_id}",
                hypothesis_type=HypothesisType.LOCATION,
                statement="No location data found - target may use VPN/proxy atau be highly privacy-conscious",
                description="Complete absence of location data is unusual dalam OSINT",
                confidence=0.5,
                status=HypothesisStatus.UNTESTED,
                related_entities=[target_id]
            )
            hypotheses.append(h)
            return hypotheses

        # Multiple locations
        countries = set(loc.get("country", "") for loc in locations if loc.get("country"))
        if len(countries) > 2:
            h = Hypothesis(
                hypothesis_id=f"hyp_loc_multi_{target_id}",
                hypothesis_type=HypothesisType.LOCATION,
                statement=f"Presence in {len(countries)} countries suggests travel, relocation, atau proxy usage",
                description=f"Locations span: {', '.join(countries)}",
                confidence=min(0.75, 0.4 + len(countries) * 0.1),
                status=HypothesisStatus.UNTESTED,
                related_entities=[target_id]
            )
            hypotheses.append(h)

        # Conflicting locations
        cities = [loc.get("city", "") for loc in locations if loc.get("city")]
        if len(set(cities)) > 1:
            h = Hypothesis(
                hypothesis_id=f"hyp_loc_conflict_{target_id}",
                hypothesis_type=HypothesisType.LOCATION,
                statement="Multiple cities reported - verify current residence versus historical locations",
                description=f"Cities found: {', '.join(set(cities))}",
                confidence=0.6,
                status=HypothesisStatus.UNTESTED,
                related_entities=[target_id]
            )
            hypotheses.append(h)

        self._hypotheses.extend(hypotheses)
        logger.info(f"[HypothesisGenerator] Generated {len(hypotheses)} location hypotheses")
        return hypotheses

    # ==================== THREAT HYPOTHESES ====================

    def generate_threat_hypotheses(self,
                                    entities: List[Dict[str, Any]],
                                    relationships: List[Dict[str, Any]],
                                    target_id: str) -> List[Hypothesis]:
        """
        Generate hypotheses tentang potensi ancaman.

        Args:
            entities: List of entity dictionaries
            relationships: List of relationship dictionaries
            target_id: Target entity ID

        Returns:
            List of Hypothesis objects
        """
        hypotheses = []

        # Check untuk threat indicators
        breach_nodes = [e for e in entities if e.get("label") == "Breach"]
        email_nodes = [e for e in entities if e.get("label") == "Email"]

        # Breach correlation
        if breach_nodes and email_nodes:
            h = Hypothesis(
                hypothesis_id=f"hyp_threat_breach_{target_id}",
                hypothesis_type=HypothesisType.THREAT,
                statement="Email found dalam breach databases indicates potential credential compromise",
                description=f"Found dalam {len(breach_nodes)} breach(es)",
                confidence=min(0.9, 0.6 + len(breach_nodes) * 0.1),
                status=HypothesisStatus.UNTESTED,
                related_entities=[e.get("id") for e in breach_nodes + email_nodes]
            )
            hypotheses.append(h)

        # Multiple identities
        username_count = len([e for e in entities if e.get("label") == "Username"])
        if username_count > 5:
            h = Hypothesis(
                hypothesis_id=f"hyp_threat_multiid_{target_id}",
                hypothesis_type=HypothesisType.THREAT,
                statement="Large number of online identities may indicate sockpuppeting atau influence operations",
                description=f"Found {username_count} usernames across platforms",
                confidence=min(0.7, 0.4 + username_count * 0.05),
                status=HypothesisStatus.UNTESTED
            )
            hypotheses.append(h)

        # Dark web indicators
        darkweb_indicators = any(
            "dark" in str(e.get("properties", {}).get("source", "")).lower()
            for e in entities
        )
        if darkweb_indicators:
            h = Hypothesis(
                hypothesis_id=f"hyp_threat_darkweb_{target_id}",
                hypothesis_type=HypothesisType.THREAT,
                statement="Dark web presence detected - may indicate involvement dalam illicit activities",
                description="Data sourced dari dark web forums atau markets",
                confidence=0.65,
                status=HypothesisStatus.UNTESTED
            )
            hypotheses.append(h)

        self._hypotheses.extend(hypotheses)
        logger.info(f"[HypothesisGenerator] Generated {len(hypotheses)} threat hypotheses")
        return hypotheses

    # ==================== GAP ANALYSIS ====================

    def generate_gap_hypotheses(self,
                                 expected_data: Dict[str, List[str]],
                                 actual_data: Dict[str, List[Any]],
                                 target_id: str) -> List[Hypothesis]:
        """
        Generate hypotheses berdasarkan gap analysis.

        Args:
            expected_data: Dictionary of expected data types dan fields
            actual_data: Dictionary of actual found data
            target_id: Target entity ID

        Returns:
            List of Hypothesis objects
        """
        hypotheses = []

        for data_type, expected_fields in expected_data.items():
            actual_fields = actual_data.get(data_type, [])
            missing = set(expected_fields) - set(str(f) for f in actual_fields)

            if missing:
                h = Hypothesis(
                    hypothesis_id=f"hyp_gap_{data_type}_{target_id}",
                    hypothesis_type=HypothesisType.GAP,
                    statement=f"Missing {len(missing)} expected {data_type} fields: {', '.join(missing)}",
                    description=(
                        f"Expected: {', '.join(expected_fields)}. "
                        f"Found: {', '.join(str(f) for f in actual_fields)}. "
                        f"Missing data may indicate deletion, privacy measures, atau limited scope."
                    ),
                    confidence=min(0.8, 0.4 + len(missing) * 0.1),
                    status=HypothesisStatus.UNTESTED,
                    related_entities=[target_id]
                )
                hypotheses.append(h)

        self._hypotheses.extend(hypotheses)
        logger.info(f"[HypothesisGenerator] Generated {len(hypotheses)} gap hypotheses")
        return hypotheses

    # ==================== QUESTION GENERATION ====================

    def generate_investigation_questions(self,
                                          hypotheses: Optional[List[Hypothesis]] = None,
                                          entities: Optional[List[Dict]] = None) -> List[InvestigationQuestion]:
        """
        Generate follow-up investigation questions.

        Args:
            hypotheses: List of hypotheses untuk generate questions dari
            entities: List of entities untuk context

        Returns:
            List of InvestigationQuestion objects
        """
        questions = []
        hypotheses = hypotheses or self._hypotheses

        for hyp in hypotheses:
            if hyp.status == HypothesisStatus.UNTESTED and hyp.confidence >= self.min_confidence:
                # Generate questions berdasarkan hypothesis type
                if hyp.hypothesis_type == HypothesisType.IDENTITY:
                    q = InvestigationQuestion(
                        question_id=f"q_id_{hyp.hypothesis_id}",
                        question=f"Can we verify {hyp.statement.lower()}?",
                        question_type="verification",
                        priority="high" if hyp.confidence > 0.7 else "medium",
                        related_hypothesis=hyp.hypothesis_id,
                        suggested_sources=["social_media", "public_records", "breach_databases"],
                        expected_answer_type="boolean"
                    )
                    questions.append(q)

                elif hyp.hypothesis_type == HypothesisType.RELATIONSHIP:
                    q = InvestigationQuestion(
                        question_id=f"q_rel_{hyp.hypothesis_id}",
                        question=f"What is the nature of the relationship: {hyp.statement}?",
                        question_type="exploration",
                        priority="medium",
                        related_hypothesis=hyp.hypothesis_id,
                        suggested_sources=["social_networks", "communication_records", "financial_data"],
                        expected_answer_type="narrative"
                    )
                    questions.append(q)

                elif hyp.hypothesis_type == HypothesisType.THREAT:
                    q = InvestigationQuestion(
                        question_id=f"q_threat_{hyp.hypothesis_id}",
                        question=f"To what extent does {hyp.statement.lower()}?",
                        question_type="risk_assessment",
                        priority="critical" if hyp.confidence > 0.8 else "high",
                        related_hypothesis=hyp.hypothesis_id,
                        suggested_sources=["threat_intelligence", "dark_web", "law_enforcement"],
                        expected_answer_type="severity_scale"
                    )
                    questions.append(q)

                elif hyp.hypothesis_type == HypothesisType.GAP:
                    q = InvestigationQuestion(
                        question_id=f"q_gap_{hyp.hypothesis_id}",
                        question=f"Why is {hyp.statement.lower()}?",
                        question_type="explanation",
                        priority="medium",
                        related_hypothesis=hyp.hypothesis_id,
                        suggested_sources=["deep_web", "alternative_sources", "human_intelligence"],
                        expected_answer_type="narrative"
                    )
                    questions.append(q)

        # Generate generic questions jika tidak ada hypotheses
        if not questions and entities:
            entity_types = Counter(e.get("label") for e in entities)

            if entity_types.get("Person", 0) > 0 and entity_types.get("Location", 0) == 0:
                q = InvestigationQuestion(
                    question_id="q_generic_location",
                    question="Where is the target currently located?",
                    question_type="location",
                    priority="high",
                    suggested_sources=["geolocation", "social_media", "public_records"],
                    expected_answer_type="geographic"
                )
                questions.append(q)

            if entity_types.get("Email", 0) > 0:
                q = InvestigationQuestion(
                    question_id="q_generic_breach",
                    question="Have any email addresses been compromised dalam known breaches?",
                    question_type="security",
                    priority="high",
                    suggested_sources=["haveibeenpwned", "breach_databases"],
                    expected_answer_type="boolean"
                )
                questions.append(q)

        self._questions.extend(questions)
        logger.info(f"[HypothesisGenerator] Generated {len(questions)} investigation questions")
        return questions

    # ==================== SCENARIO GENERATION ====================

    def generate_scenarios(self,
                           entities: List[Dict[str, Any]],
                           relationships: List[Dict[str, Any]],
                           target_id: str) -> List[Scenario]:
        """
        Generate best/worst/likely case scenarios.

        Args:
            entities: List of entity dictionaries
            relationships: List of relationship dictionaries
            target_id: Target entity ID

        Returns:
            List of Scenario objects
        """
        scenarios = []

        # Analyze current state
        entity_labels = Counter(e.get("label") for e in entities)
        rel_types = Counter(r.get("type") for r in relationships)

        # Best case scenario
        best_case = Scenario(
            scenario_id=f"scen_best_{target_id}",
            scenario_type="best_case",
            title="Benign Digital Presence",
            description=(
                "Target maintains normal online presence dengan legitimate purposes. "
                "All identified accounts are authentic dan used untuk personal/professional reasons."
            ),
            probability=0.3,
            key_assumptions=[
                "All online identities are legitimate",
                "No malicious intent behind online activities",
                "Breach exposure is minimal dan remediated"
            ],
            implications=[
                "Low security risk",
                "Standard monitoring sufficient",
                "No immediate action required"
            ]
        )
        scenarios.append(best_case)

        # Worst case scenario
        worst_case = Scenario(
            scenario_id=f"scen_worst_{target_id}",
            scenario_type="worst_case",
            title="Active Threat Actor",
            description=(
                "Target is involved dalam malicious activities menggunakan multiple online identities. "
                "Presence dalam breach databases indicates compromised credentials used untuk further attacks."
            ),
            probability=0.15,
            key_assumptions=[
                "Multiple identities indicate sockpuppeting",
                "Breach data used untuk credential stuffing",
                "Dark web presence indicates illicit activities"
            ],
            implications=[
                "Immediate security response required",
                "Law enforcement notification may be necessary",
                "Comprehensive monitoring dan containment"
            ]
        )
        scenarios.append(worst_case)

        # Likely case scenario
        likely_prob = 1.0 - best_case.probability - worst_case.probability
        likely_case = Scenario(
            scenario_id=f"scen_likely_{target_id}",
            scenario_type="likely_case",
            title="Mixed Risk Profile",
            description=(
                f"Target has {entity_labels.get('Person', 0)} identifiable personas dengan "
                f"{len(relationships)} connections. Some security concerns exist but no clear malicious intent. "
                "Standard OSINT monitoring recommended."
            ),
            probability=likely_prob,
            key_assumptions=[
                "Normal online presence dengan some privacy concerns",
                "Breach exposure may be historical",
                "Multiple accounts untuk legitimate purposes"
            ],
            implications=[
                "Continue monitoring",
                "Verify breach data impact",
                "Periodic reassessment"
            ]
        )
        scenarios.append(likely_case)

        self._scenarios.extend(scenarios)
        logger.info(f"[HypothesisGenerator] Generated {len(scenarios)} scenarios")
        return scenarios

    # ==================== HYPOTHESIS TESTING ====================

    def test_hypothesis(self,
                        hypothesis_id: str,
                        new_evidence: List[Dict[str, Any]]) -> Hypothesis:
        """
        Test hypothesis dengan new evidence.

        Args:
            hypothesis_id: Hypothesis ID
            new_evidence: List of new evidence dictionaries

        Returns:
            Updated Hypothesis
        """
        hypothesis = next((h for h in self._hypotheses if h.hypothesis_id == hypothesis_id), None)
        if not hypothesis:
            raise ValueError(f"Hypothesis {hypothesis_id} not found")

        # Evaluate evidence
        for evidence in new_evidence:
            link = EvidenceLink(
                evidence_id=evidence.get("id", "unknown"),
                evidence_type=evidence.get("type", "unknown"),
                description=evidence.get("description", ""),
                supports=evidence.get("supports", True),
                strength=evidence.get("strength", 0.5)
            )
            hypothesis.evidence_links.append(link)

        # Update status
        support_score = hypothesis.support_score
        evidence_count = hypothesis.evidence_count

        if support_score > 0.5 and evidence_count["supporting"] > evidence_count["contradicting"]:
            hypothesis.status = HypothesisStatus.SUPPORTED
        elif support_score > 0.2:
            hypothesis.status = HypothesisStatus.PARTIALLY_SUPPORTED
        elif support_score < -0.3:
            hypothesis.status = HypothesisStatus.CONTRADICTED
        else:
            hypothesis.status = HypothesisStatus.UNSUPPORTED

        hypothesis.tested_at = datetime.now().isoformat()

        logger.info(f"[HypothesisGenerator] Tested {hypothesis_id}: {hypothesis.status.value}")
        return hypothesis

    # ==================== AGGREGATE FUNCTIONS ====================

    def generate_all_hypotheses(self,
                                 nodes: List[Dict[str, Any]],
                                 relationships: List[Dict[str, Any]],
                                 target_id: str,
                                 expected_data: Optional[Dict[str, List[str]]] = None) -> Dict[str, List]:
        """
        Generate all types of hypotheses.

        Args:
            nodes: Graph nodes
            relationships: Graph relationships
            target_id: Target entity ID
            expected_data: Optional expected data untuk gap analysis

        Returns:
            Dictionary dengan all generated items
        """
        all_hypotheses = []

        # Identity hypotheses
        identity = self.generate_identity_hypotheses(nodes, target_id)
        all_hypotheses.extend(identity)

        # Relationship hypotheses
        rel_hypotheses = self.generate_relationship_hypotheses(nodes, relationships)
        all_hypotheses.extend(rel_hypotheses)

        # Location hypotheses
        locations = [n.get("properties", {}) for n in nodes if n.get("label") == "Location"]
        location = self.generate_location_hypotheses(locations, target_id)
        all_hypotheses.extend(location)

        # Threat hypotheses
        threat = self.generate_threat_hypotheses(nodes, relationships, target_id)
        all_hypotheses.extend(threat)

        # Gap hypotheses
        if expected_data:
            actual_data = defaultdict(list)
            for n in nodes:
                label = n.get("label", "Unknown")
                actual_data[label].append(n.get("id"))

            gaps = self.generate_gap_hypotheses(expected_data, dict(actual_data), target_id)
            all_hypotheses.extend(gaps)

        # Generate questions
        questions = self.generate_investigation_questions(all_hypotheses, nodes)

        # Generate scenarios
        scenarios = self.generate_scenarios(nodes, relationships, target_id)

        # Filter by confidence
        filtered_hypotheses = [h for h in all_hypotheses if h.confidence >= self.min_confidence]

        return {
            "hypotheses": filtered_hypotheses,
            "questions": questions,
            "scenarios": scenarios
        }

    def get_hypotheses_by_type(self, hypothesis_type: HypothesisType) -> List[Hypothesis]:
        """Get hypotheses by type."""
        return [h for h in self._hypotheses if h.hypothesis_type == hypothesis_type]

    def get_untested_hypotheses(self) -> List[Hypothesis]:
        """Get untested hypotheses."""
        return [h for h in self._hypotheses if h.status == HypothesisStatus.UNTESTED]

    def get_high_confidence_hypotheses(self, threshold: float = 0.7) -> List[Hypothesis]:
        """Get high confidence hypotheses."""
        return [h for h in self._hypotheses if h.confidence >= threshold]

    def export_hypotheses(self, output_path: str, format: str = "json") -> str:
        """
        Export hypotheses ke file.

        Args:
            output_path: Output file path
            format: "json" atau "markdown"

        Returns:
            File path
        """
        if format == "json":
            data = {
                "generated_at": datetime.now().isoformat(),
                "hypothesis_count": len(self._hypotheses),
                "question_count": len(self._questions),
                "scenario_count": len(self._scenarios),
                "hypotheses": [h.to_dict() for h in self._hypotheses],
                "questions": [q.to_dict() for q in self._questions],
                "scenarios": [s.to_dict() for s in self._scenarios]
            }

            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

        elif format == "markdown":
            md = f"""# Hypothesis Generation Report

**Generated:** {datetime.now().isoformat()}  
**Total Hypotheses:** {len(self._hypotheses)}  
**Total Questions:** {len(self._questions)}  
**Total Scenarios:** {len(self._scenarios)}

## Hypotheses

"""
            for i, hyp in enumerate(self._hypotheses, 1):
                md += f"""### {i}. [{hyp.hypothesis_type.value.upper()}] {hyp.status.value.replace('_', ' ').title()}

**{hyp.statement}**

{hyp.description}

- **Confidence:** {hyp.confidence:.2%}
- **Support Score:** {hyp.support_score:.2f}
- **Evidence:** {hyp.evidence_count['supporting']} supporting, {hyp.evidence_count['contradicting']} contradicting

---

"""

            md += "## Investigation Questions\n\n"
            for i, q in enumerate(self._questions, 1):
                md += f"{i}. **[{q.priority.upper()}]** {q.question}\n"
                md += f"   - Type: {q.question_type} | Expected: {q.expected_answer_type}\n"
                md += f"   - Sources: {', '.join(q.suggested_sources)}\n\n"

            md += "## Scenarios\n\n"
            for s in self._scenarios:
                md += f"### {s.scenario_type.replace('_', ' ').title()}: {s.title}\n\n"
                md += f"{s.description}\n\n"
                md += f"**Probability:** {s.probability:.2%}\n\n"
                md += "**Key Assumptions:**\n"
                for a in s.key_assumptions:
                    md += f"- {a}\n"
                md += "\n**Implications:**\n"
                for imp in s.implications:
                    md += f"- {imp}\n"
                md += "\n---\n\n"

            with open(output_path, "w", encoding="utf-8") as f:
                f.write(md)

        logger.info(f"[HypothesisGenerator] Exported to {output_path}")
        return output_path

    # ==================== HELPER METHODS ====================

    def _generate_name_variations(self, name: str) -> List[str]:
        """Generate common name variations."""
        variations = []
        parts = name.split()

        if len(parts) >= 2:
            first, last = parts[0], parts[-1]
            variations.extend([
                f"{first[0]}{last}",
                f"{first}.{last}",
                f"{first}_{last}",
                f"{last}{first[0]}",
                f"{first}{last[0]}",
            ])

        return list(set(variations))


# ============== CONVENIENCE FUNCTIONS ==============

def quick_hypotheses(nodes: List[Dict], relationships: List[Dict], 
                     target_id: str) -> Dict[str, List]:
    """Quick generate all hypotheses."""
    generator = HypothesisGenerator()
    return generator.generate_all_hypotheses(nodes, relationships, target_id)


# ============== MAIN ==============

if __name__ == "__main__":
    print("=" * 70)
    print("Hypothesis Generation Module")
    print("=" * 70)

    generator = HypothesisGenerator()

    # Demo data
    nodes = [
        {"id": "person_1", "label": "Person", "properties": {"name": "John Doe", "aliases": ["JD", "Johnny"]}},
        {"id": "email_1", "label": "Email", "properties": {"email": "john@example.com"}},
        {"id": "username_1", "label": "Username", "properties": {"username": "johndoe", "platform": "twitter"}},
        {"id": "username_2", "label": "Username", "properties": {"username": "jdoe", "platform": "github"}},
        {"id": "username_3", "label": "Username", "properties": {"username": "johndoe123", "platform": "instagram"}},
        {"id": "breach_1", "label": "Breach", "properties": {"name": "ExampleLeak2023"}},
        {"id": "domain_1", "label": "Domain", "properties": {"name": "example.com"}},
    ]

    relationships = [
        {"from": "person_1", "to": "email_1", "type": "HAS_EMAIL"},
        {"from": "person_1", "to": "username_1", "type": "USES"},
        {"from": "person_1", "to": "username_2", "type": "USES"},
        {"from": "person_1", "to": "username_3", "type": "USES"},
        {"from": "email_1", "to": "breach_1", "type": "FOUND_IN"},
        {"from": "person_1", "to": "domain_1", "type": "OWNS"},
    ]

    print("\n[*] Generating all hypotheses...")
    results = generator.generate_all_hypotheses(nodes, relationships, "person_1")

    print(f"\n[+] Generated:")
    print(f"    Hypotheses: {len(results['hypotheses'])}")
    print(f"    Questions: {len(results['questions'])}")
    print(f"    Scenarios: {len(results['scenarios'])}")

    print("\n[*] Hypotheses:")
    for i, hyp in enumerate(results["hypotheses"][:5], 1):
        print(f"    {i}. [{hyp.hypothesis_type.value}] {hyp.statement}")
        print(f"       Confidence: {hyp.confidence:.2%} | Status: {hyp.status.value}")

    print("\n[*] Top Questions:")
    for i, q in enumerate(results["questions"][:5], 1):
        print(f"    {i}. [{q.priority.upper()}] {q.question}")

    print("\n[*] Scenarios:")
    for s in results["scenarios"]:
        print(f"    - {s.scenario_type}: {s.title} (probability: {s.probability:.2%})")

    # Test hypothesis
    print("\n[*] Testing hypothesis...")
    test_evidence = [
        {"id": "ev_1", "type": "social_media", "supports": True, "strength": 0.8, "description": "Found matching profile"},
        {"id": "ev_2", "type": "breach_db", "supports": True, "strength": 0.6, "description": "Email confirmed dalam breach"},
    ]

    if results["hypotheses"]:
        tested = generator.test_hypothesis(results["hypotheses"][0].hypothesis_id, test_evidence)
        print(f"[+] Tested: {tested.hypothesis_id} -> {tested.status.value}")
        print(f"    Support score: {tested.support_score:.2f}")

    # Export
    print("\n[*] Exporting...")
    generator.export_hypotheses("/mnt/agents/output/hypotheses.json", "json")
    generator.export_hypotheses("/mnt/agents/output/hypotheses.md", "markdown")
    print("[+] Reports saved!")

    print("\n" + "=" * 70)
    print("Hypothesis Generation Demo Complete!")
    print("=" * 70)