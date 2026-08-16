"""
ai_investigator.py - AI-Powered OSINT Investigation Module
Part of OSINT Intelligence Platform v3
"""

import os
import re
import json
import logging
from typing import Dict, List, Optional, Tuple, Union, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from collections import defaultdict, Counter
import hashlib
import asyncio

# Data analysis
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import DBSCAN, KMeans
from sklearn.decomposition import LatentDirichletAllocation
from sklearn.metrics.pairwise import cosine_similarity

# NLP
import nltk
from nltk.tokenize import sent_tokenize, word_tokenize
from nltk.corpus import stopwords
from nltk.sentiment import SentimentIntensityAnalyzer

# Network analysis
import networkx as nx

# Pattern matching
import regex

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Download required NLTK data
try:
    nltk.data.find('tokenizers/punkt')
except LookupError:
    nltk.download('punkt', quiet=True)
try:
    nltk.data.find('corpora/stopwords')
except LookupError:
    nltk.download('stopwords', quiet=True)
try:
    nltk.data.find('vader_lexicon')
except LookupError:
    nltk.download('vader_lexicon', quiet=True)


class InvestigationType(Enum):
    """Types of AI investigations."""
    IDENTITY = "identity"
    NETWORK = "network"
    SENTIMENT = "sentiment"
    ANOMALY = "anomaly"
    PREDICTIVE = "predictive"
    COMPREHENSIVE = "comprehensive"


class ThreatLevel(Enum):
    """Threat assessment levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"
    UNKNOWN = "unknown"


@dataclass
class Evidence:
    """Piece of evidence found during investigation."""
    source: str
    type: str
    content: str
    confidence: float
    timestamp: str = None
    metadata: Dict = field(default_factory=dict)
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()


@dataclass
class Finding:
    """Investigation finding."""
    title: str
    description: str
    evidence: List[Evidence]
    confidence: float
    severity: str
    related_entities: List[str] = field(default_factory=list)
    timestamp: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()


@dataclass
class InvestigationReport:
    """Complete investigation report."""
    investigation_id: str
    investigation_type: InvestigationType
    target: str
    findings: List[Finding]
    evidence_summary: Dict
    threat_assessment: Dict
    recommendations: List[str]
    timeline: List[Dict]
    confidence_score: float
    processing_time: float
    created_at: str = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now().isoformat()
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            'investigation_id': self.investigation_id,
            'investigation_type': self.investigation_type.value,
            'target': self.target,
            'findings': [asdict(f) for f in self.findings],
            'evidence_summary': self.evidence_summary,
            'threat_assessment': self.threat_assessment,
            'recommendations': self.recommendations,
            'timeline': self.timeline,
            'confidence_score': self.confidence_score,
            'processing_time': self.processing_time,
            'created_at': self.created_at
        }
    
    def to_markdown(self) -> str:
        """Generate markdown report."""
        md = f"""# Investigation Report: {self.target}

**Investigation ID:** {self.investigation_id}  
**Type:** {self.investigation_type.value.title()}  
**Date:** {self.created_at}  
**Confidence Score:** {self.confidence_score:.2%}  
**Processing Time:** {self.processing_time:.2f}s

---

## 🎯 Executive Summary

This report presents findings from an AI-powered OSINT investigation targeting **{self.target}**.

### Threat Assessment
- **Level:** {self.threat_assessment.get('level', 'Unknown').upper()}
- **Risk Score:** {self.threat_assessment.get('risk_score', 0):.2f}/1.0
- **Key Concerns:** {', '.join(self.threat_assessment.get('key_concerns', ['None identified']))}

---

## 🔍 Key Findings

"""
        for i, finding in enumerate(self.findings, 1):
            md += f"""
### {i}. {finding.title}
**Severity:** {finding.severity.upper()} | **Confidence:** {finding.confidence:.2%}

{finding.description}

**Evidence Count:** {len(finding.evidence)}
**Related Entities:** {', '.join(finding.related_entities) if finding.related_entities else 'None'}

"""
        
        md += """
---

## 📊 Evidence Summary

"""
        for source, count in self.evidence_summary.items():
            md += f"- **{source}:** {count} pieces of evidence\n"
        
        md += """

---

## 📅 Timeline

"""
        for event in self.timeline:
            md += f"- **{event.get('timestamp', 'Unknown')}:** {event.get('event', 'Unknown event')}\n"
        
        md += """

---

## 💡 Recommendations

"""
        for i, rec in enumerate(self.recommendations, 1):
            md += f"{i}. {rec}\n"
        
        md += "\n---\n*Generated by OSINT AI Investigator v3.0*\n"
        
        return md


class AIInvestigator:
    """
    AI-Powered OSINT Investigation Engine.
    
    Provides automated analysis, pattern recognition, and report generation
    for OSINT investigations.
    """
    
    # Common patterns for extraction
    PATTERNS = {
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'phone': r'(?:\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}',
        'ip_address': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        'ipv6': r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
        'credit_card': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
        'ssn': r'\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b',
        'btc_address': r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
        'eth_address': r'\b0x[a-fA-F0-9]{40}\b',
        'url': r'https?://(?:[-\w.])+(?:[:/\d]+)?(?:[?\w=&.]*)?',
        'username': r'(?:@|user:|username:)\s*([A-Za-z0-9_]{3,30})',
        'date': r'\b(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}[/-]\d{1,2}[/-]\d{1,2})\b',
    }
    
    # Suspicious keywords for threat assessment
    THREAT_KEYWORDS = {
        'critical': ['bomb', 'terrorist', 'kill', 'attack', 'explosive', 'hostage', 'cyberattack'],
        'high': ['hack', 'breach', 'leak', 'exploit', 'malware', 'phishing', 'fraud'],
        'medium': ['suspicious', 'unusual', 'anonymous', 'proxy', 'vpn', 'tor'],
        'low': ['privacy', 'security', 'concern', 'risk', 'warning']
    }
    
    def __init__(self, 
                 language: str = 'english',
                 min_confidence: float = 0.5,
                 enable_sentiment: bool = True):
        """
        Initialize AI Investigator.
        
        Args:
            language: Primary language for analysis
            min_confidence: Minimum confidence threshold
            enable_sentiment: Enable sentiment analysis
        """
        self.language = language
        self.min_confidence = min_confidence
        self.enable_sentiment = enable_sentiment
        
        # Initialize NLP components
        self.stop_words = set(stopwords.words(language))
        self.sentiment_analyzer = SentimentIntensityAnalyzer() if enable_sentiment else None
        
        # Investigation history
        self.investigation_history: List[InvestigationReport] = []
        
        logger.info("AIInvestigator initialized")
    
    def extract_entities(self, text: str) -> Dict[str, List[str]]:
        """
        Extract entities from text using regex patterns.
        
        Args:
            text: Input text
            
        Returns:
            Dictionary of entity types to found values
        """
        entities = defaultdict(list)
        
        for entity_type, pattern in self.PATTERNS.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                # Handle tuple results from groups
                cleaned = []
                for match in matches:
                    if isinstance(match, tuple):
                        cleaned.append(match[0] if match[0] else match[-1])
                    else:
                        cleaned.append(match)
                entities[entity_type] = list(set(cleaned))  # Deduplicate
        
        return dict(entities)
    
    def analyze_sentiment(self, text: str) -> Dict:
        """
        Analyze sentiment of text.
        
        Args:
            text: Input text
            
        Returns:
            Sentiment analysis results
        """
        if not self.sentiment_analyzer:
            return {'error': 'Sentiment analysis disabled'}
        
        scores = self.sentiment_analyzer.polarity_scores(text)
        
        # Determine overall sentiment
        if scores['compound'] >= 0.05:
            overall = 'positive'
        elif scores['compound'] <= -0.05:
            overall = 'negative'
        else:
            overall = 'neutral'
        
        return {
            'overall': overall,
            'compound': scores['compound'],
            'positive': scores['pos'],
            'negative': scores['neg'],
            'neutral': scores['neu'],
            'intensity': abs(scores['compound'])
        }
    
    def find_patterns(self, 
                     texts: List[str],
                     min_support: int = 2) -> List[Dict]:
        """
        Find common patterns across multiple texts.
        
        Args:
            texts: List of texts to analyze
            min_support: Minimum occurrences to be considered a pattern
            
        Returns:
            List of found patterns with statistics
        """
        # Combine all texts
        combined_text = ' '.join(texts)
        
        # Extract all entities
        all_entities = defaultdict(list)
        for text in texts:
            entities = self.extract_entities(text)
            for entity_type, values in entities.items():
                all_entities[entity_type].extend(values)
        
        # Find common patterns
        patterns = []
        for entity_type, values in all_entities.items():
            counter = Counter(values)
            for value, count in counter.items():
                if count >= min_support:
                    patterns.append({
                        'type': entity_type,
                        'value': value,
                        'frequency': count,
                        'support': count / len(texts),
                        'confidence': min(count / len(texts) * 1.5, 1.0)
                    })
        
        # Sort by frequency
        patterns.sort(key=lambda x: x['frequency'], reverse=True)
        
        return patterns
    
    def cluster_data(self, 
                     texts: List[str],
                     n_clusters: Optional[int] = None,
                     method: str = 'kmeans') -> Dict:
        """
        Cluster texts by similarity.
        
        Args:
            texts: List of texts to cluster
            n_clusters: Number of clusters (auto if None)
            method: Clustering method ('kmeans' or 'dbscan')
            
        Returns:
            Clustering results
        """
        if len(texts) < 2:
            return {'error': 'Need at least 2 texts to cluster'}
        
        # Vectorize texts
        vectorizer = TfidfVectorizer(
            stop_words=self.stop_words,
            max_features=1000,
            ngram_range=(1, 2)
        )
        
        try:
            tfidf_matrix = vectorizer.fit_transform(texts)
        except Exception as e:
            return {'error': f'Vectorization failed: {str(e)}'}
        
        # Determine number of clusters
        if n_clusters is None:
            n_clusters = min(int(len(texts) ** 0.5) + 1, len(texts))
        
        # Perform clustering
        if method == 'kmeans':
            clusterer = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
        elif method == 'dbscan':
            clusterer = DBSCAN(eps=0.5, min_samples=2)
        else:
            return {'error': f'Unknown clustering method: {method}'}
        
        labels = clusterer.fit_predict(tfidf_matrix)
        
        # Organize results
        clusters = defaultdict(list)
        for i, label in enumerate(labels):
            clusters[int(label)].append({
                'index': i,
                'text_preview': texts[i][:100] + '...' if len(texts[i]) > 100 else texts[i]
            })
        
        # Calculate cluster quality
        if method == 'kmeans' and len(set(labels)) > 1:
            from sklearn.metrics import silhouette_score
            try:
                silhouette = silhouette_score(tfidf_matrix, labels)
            except:
                silhouette = 0
        else:
            silhouette = 0
        
        # Get top terms per cluster
        feature_names = vectorizer.get_feature_names_out()
        top_terms = {}
        
        if method == 'kmeans':
            for i in range(n_clusters):
                if i in clusters:
                    center = clusterer.cluster_centers_[i]
                    top_indices = center.argsort()[-10:][::-1]
                    top_terms[i] = [feature_names[j] for j in top_indices]
        
        return {
            'method': method,
            'num_clusters': len(set(labels)) - (1 if -1 in labels else 0),
            'noise_points': list(labels).count(-1) if method == 'dbscan' else 0,
            'silhouette_score': silhouette,
            'clusters': dict(clusters),
            'top_terms': top_terms,
            'labels': labels.tolist()
        }
    
    def build_relationship_graph(self, 
                                  entities: Dict[str, List[str]],
                                  texts: List[str]) -> Dict:
        """
        Build relationship graph between entities.
        
        Args:
            entities: Extracted entities
            texts: Source texts
            
        Returns:
            Graph analysis results
        """
        G = nx.Graph()
        
        # Add nodes for all entities
        all_entities = []
        for entity_type, values in entities.items():
            for value in values:
                node_id = f"{entity_type}:{value}"
                G.add_node(node_id, type=entity_type, value=value)
                all_entities.append(node_id)
        
        # Add edges based on co-occurrence in texts
        for text in texts:
            text_entities = []
            for entity_type, values in entities.items():
                for value in values:
                    if value in text:
                        text_entities.append(f"{entity_type}:{value}")
            
            # Connect all entities found in same text
            for i, e1 in enumerate(text_entities):
                for e2 in text_entities[i+1:]:
                    if G.has_edge(e1, e2):
                        G[e1][e2]['weight'] += 1
                    else:
                        G.add_edge(e1, e2, weight=1)
        
        # Calculate centrality metrics
        if len(G.nodes()) > 0:
            centrality = nx.degree_centrality(G)
            betweenness = nx.betweenness_centrality(G) if len(G.nodes()) > 2 else {}
            
            # Find key nodes
            key_nodes = sorted(
                centrality.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]
        else:
            centrality = {}
            betweenness = {}
            key_nodes = []
        
        # Extract communities
        communities = []
        if len(G.nodes()) > 0:
            try:
                from networkx.algorithms import community
                comms = community.greedy_modularity_communities(G)
                communities = [list(c) for c in comms]
            except:
                pass
        
        return {
            'nodes': len(G.nodes()),
            'edges': len(G.edges()),
            'density': nx.density(G) if len(G.nodes()) > 1 else 0,
            'key_entities': [
                {
                    'entity': node.split(':', 1)[1],
                    'type': node.split(':', 1)[0],
                    'centrality': round(score, 4)
                }
                for node, score in key_nodes
            ],
            'communities': communities,
            'connections': [
                {
                    'source': u.split(':', 1)[1],
                    'target': v.split(':', 1)[1],
                    'weight': d['weight']
                }
                for u, v, d in G.edges(data=True)
            ]
        }
    
    def assess_threat(self, 
                      findings: List[Finding],
                      entities: Dict[str, List[str]]) -> Dict:
        """
        Assess threat level based on findings and entities.
        
        Args:
            findings: Investigation findings
            entities: Extracted entities
            
        Returns:
            Threat assessment
        """
        risk_score = 0.0
        key_concerns = []
        indicators = []
        
        # Check for critical entities
        critical_entities = ['credit_card', 'ssn', 'btc_address']
        for entity_type in critical_entities:
            if entity_type in entities and entities[entity_type]:
                risk_score += 0.3
                key_concerns.append(f"Sensitive data found: {entity_type}")
                indicators.extend(entities[entity_type][:3])
        
        # Check for multiple identities
        if 'email' in entities and len(entities['email']) > 5:
            risk_score += 0.2
            key_concerns.append("Multiple email addresses detected")
        
        # Analyze findings for threat keywords
        all_text = ' '.join([
            f.title + ' ' + f.description 
            for f in findings
        ]).lower()
        
        for level, keywords in self.THREAT_KEYWORDS.items():
            found = [kw for kw in keywords if kw in all_text]
            if found:
                if level == 'critical':
                    risk_score += 0.4
                elif level == 'high':
                    risk_score += 0.25
                elif level == 'medium':
                    risk_score += 0.15
                elif level == 'low':
                    risk_score += 0.05
                
                key_concerns.extend([f"Keyword '{kw}' detected" for kw in found])
        
        # Check sentiment of findings
        if self.enable_sentiment:
            sentiment = self.analyze_sentiment(all_text)
            if sentiment.get('overall') == 'negative' and sentiment.get('intensity', 0) > 0.5:
                risk_score += 0.1
                key_concerns.append("Negative sentiment detected in content")
        
        # Normalize risk score
        risk_score = min(risk_score, 1.0)
        
        # Determine threat level
        if risk_score >= 0.8:
            level = ThreatLevel.CRITICAL
        elif risk_score >= 0.6:
            level = ThreatLevel.HIGH
        elif risk_score >= 0.4:
            level = ThreatLevel.MEDIUM
        elif risk_score >= 0.2:
            level = ThreatLevel.LOW
        else:
            level = ThreatLevel.MINIMAL
        
        return {
            'level': level.value,
            'risk_score': risk_score,
            'key_concerns': list(set(key_concerns))[:10],
            'indicators': list(set(indicators))[:10],
            'recommendation': self._generate_threat_recommendation(level, key_concerns)
        }
    
    def _generate_threat_recommendation(self, 
                                         level: ThreatLevel,
                                         concerns: List[str]) -> str:
        """Generate threat recommendation."""
        recommendations = {
            ThreatLevel.CRITICAL: "Immediate action required. Escalate to security team and law enforcement if applicable.",
            ThreatLevel.HIGH: "Urgent attention needed. Conduct deep-dive investigation and implement monitoring.",
            ThreatLevel.MEDIUM: "Investigate further. Monitor for escalation and gather additional evidence.",
            ThreatLevel.LOW: "Routine monitoring recommended. Document findings for future reference.",
            ThreatLevel.MINIMAL: "No immediate action required. Standard security practices sufficient."
        }
        
        base_rec = recommendations.get(level, "Assess situation manually.")
        
        if concerns:
            base_rec += f" Key concerns: {', '.join(concerns[:3])}."
        
        return base_rec
    
    def generate_recommendations(self, 
                                  findings: List[Finding],
                                  threat_assessment: Dict) -> List[str]:
        """
        Generate actionable recommendations.
        
        Args:
            findings: Investigation findings
            threat_assessment: Threat assessment results
            
        Returns:
            List of recommendations
        """
        recommendations = []
        
        # Based on threat level
        level = threat_assessment.get('level', 'unknown')
        
        if level in ['critical', 'high']:
            recommendations.extend([
                "Implement immediate monitoring of identified entities",
                "Cross-reference findings with threat intelligence databases",
                "Preserve all evidence with proper chain of custody",
                "Consider engaging legal counsel if applicable"
            ])
        
        # Based on findings
        for finding in findings:
            if finding.severity == 'critical':
                recommendations.append(
                    f"Priority investigation needed: {finding.title}"
                )
            elif 'email' in finding.description.lower():
                recommendations.append(
                    f"Verify email addresses found in: {finding.title}"
                )
            elif 'ip' in finding.description.lower():
                recommendations.append(
                    f"Analyze IP addresses for geolocation and ownership"
                )
        
        # General recommendations
        recommendations.extend([
            "Continue monitoring for new data related to target",
            "Update investigation with fresh data periodically",
            "Document all findings with timestamps and sources"
        ])
        
        return list(set(recommendations))  # Deduplicate
    
    def create_timeline(self, evidence_list: List[Evidence]) -> List[Dict]:
        """
        Create chronological timeline from evidence.
        
        Args:
            evidence_list: List of evidence
            
        Returns:
            Sorted timeline events
        """
        # Sort by timestamp
        sorted_evidence = sorted(
            evidence_list,
            key=lambda x: x.timestamp or datetime.min.isoformat()
        )
        
        timeline = []
        for evidence in sorted_evidence:
            timeline.append({
                'timestamp': evidence.timestamp,
                'event': f"{evidence.type} from {evidence.source}",
                'details': evidence.content[:200],
                'confidence': evidence.confidence
            })
        
        return timeline
    
    def investigate_identity(self, 
                            target: str,
                            data_sources: List[Dict]) -> InvestigationReport:
        """
        Perform identity investigation.
        
        Args:
            target: Investigation target (name, email, username)
            data_sources: List of data source dictionaries
            
        Returns:
            InvestigationReport
        """
        import time
        start_time = time.time()
        
        investigation_id = hashlib.sha256(
            f"{target}_{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]
        
        findings = []
        all_evidence = []
        all_entities = defaultdict(list)
        
        # Process each data source
        for source in data_sources:
            source_name = source.get('name', 'unknown')
            source_data = source.get('data', '')
            
            # Extract entities
            entities = self.extract_entities(str(source_data))
            for k, v in entities.items():
                all_entities[k].extend(v)
            
            # Analyze sentiment
            sentiment = self.analyze_sentiment(str(source_data))
            
            # Create evidence
            evidence = Evidence(
                source=source_name,
                type='text_extraction',
                content=str(source_data)[:500],
                confidence=0.7,
                metadata={
                    'entities': entities,
                    'sentiment': sentiment
                }
            )
            all_evidence.append(evidence)
            
            # Check for specific findings
            if 'email' in entities:
                findings.append(Finding(
                    title=f"Email addresses found in {source_name}",
                    description=f"Found {len(entities['email'])} email address(es)",
                    evidence=[evidence],
                    confidence=0.9,
                    severity='medium',
                    related_entities=entities['email']
                ))
            
            if 'phone' in entities:
                findings.append(Finding(
                    title=f"Phone numbers found in {source_name}",
                    description=f"Found {len(entities['phone'])} phone number(s)",
                    evidence=[evidence],
                    confidence=0.85,
                    severity='medium',
                    related_entities=entities['phone']
                ))
            
            if 'url' in entities:
                findings.append(Finding(
                    title=f"URLs found in {source_name}",
                    description=f"Found {len(entities['url'])} URL(s)",
                    evidence=[evidence],
                    confidence=0.8,
                    severity='low',
                    related_entities=entities['url']
                ))
        
        # Deduplicate entities
        all_entities = {k: list(set(v)) for k, v in all_entities.items()}
        
        # Assess threat
        threat = self.assess_threat(findings, all_entities)
        
        # Generate recommendations
        recommendations = self.generate_recommendations(findings, threat)
        
        # Create timeline
        timeline = self.create_timeline(all_evidence)
        
        # Evidence summary
        evidence_summary = Counter([e.source for e in all_evidence])
        
        # Calculate overall confidence
        if findings:
            confidence = sum(f.confidence for f in findings) / len(findings)
        else:
            confidence = 0.0
        
        processing_time = time.time() - start_time
        
        report = InvestigationReport(
            investigation_id=investigation_id,
            investigation_type=InvestigationType.IDENTITY,
            target=target,
            findings=findings,
            evidence_summary=dict(evidence_summary),
            threat_assessment=threat,
            recommendations=recommendations,
            timeline=timeline,
            confidence_score=confidence,
            processing_time=processing_time
        )
        
        self.investigation_history.append(report)
        return report
    
    def investigate_network(self,
                           target: str,
                           connection_data: List[Dict]) -> InvestigationReport:
        """
        Perform network/relationship investigation.
        
        Args:
            target: Central entity
            connection_data: List of connection dictionaries
            
        Returns:
            InvestigationReport
        """
        import time
        start_time = time.time()
        
        investigation_id = hashlib.sha256(
            f"network_{target}_{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]
        
        # Extract all texts
        texts = [str(d.get('content', '')) for d in connection_data]
        
        # Extract entities
        all_entities = defaultdict(list)
        for text in texts:
            entities = self.extract_entities(text)
            for k, v in entities.items():
                all_entities[k].extend(v)
        all_entities = {k: list(set(v)) for k, v in all_entities.items()}
        
        # Build relationship graph
        graph = self.build_relationship_graph(all_entities, texts)
        
        # Find patterns
        patterns = self.find_patterns(texts, min_support=2)
        
        # Cluster data
        clusters = self.cluster_data(texts, method='dbscan')
        
        findings = []
        
        # Graph-based findings
        if graph['key_entities']:
            findings.append(Finding(
                title="Key Entities Identified",
                description=f"Found {graph['nodes']} entities with {graph['edges']} connections",
                evidence=[],
                confidence=0.85,
                severity='medium',
                related_entities=[e['entity'] for e in graph['key_entities'][:5]]
            ))
        
        # Community findings
        if graph['communities']:
            findings.append(Finding(
                title="Network Communities Detected",
                description=f"Identified {len(graph['communities'])} distinct communities",
                evidence=[],
                confidence=0.75,
                severity='low',
                related_entities=[]
            ))
        
        # Pattern findings
        if patterns:
            findings.append(Finding(
                title="Recurring Patterns",
                description=f"Found {len(patterns)} patterns across {len(texts)} data points",
                evidence=[],
                confidence=0.8,
                severity='low',
                related_entities=[p['value'] for p in patterns[:5]]
            ))
        
        # Create evidence
        all_evidence = [
            Evidence(
                source=d.get('source', 'unknown'),
                type='network_data',
                content=str(d.get('content', ''))[:300],
                confidence=0.7
            )
            for d in connection_data
        ]
        
        # Assess threat
        threat = self.assess_threat(findings, all_entities)
        
        # Generate recommendations
        recommendations = self.generate_recommendations(findings, threat)
        
        # Timeline
        timeline = self.create_timeline(all_evidence)
        
        # Evidence summary
        evidence_summary = Counter([e.source for e in all_evidence])
        
        # Confidence
        confidence = sum(f.confidence for f in findings) / len(findings) if findings else 0
        
        processing_time = time.time() - start_time
        
        report = InvestigationReport(
            investigation_id=investigation_id,
            investigation_type=InvestigationType.NETWORK,
            target=target,
            findings=findings,
            evidence_summary=dict(evidence_summary),
            threat_assessment=threat,
            recommendations=recommendations,
            timeline=timeline,
            confidence_score=confidence,
            processing_time=processing_time
        )
        
        self.investigation_history.append(report)
        return report
    
    def comprehensive_investigation(self,
                                    target: str,
                                    data_package: Dict) -> InvestigationReport:
        """
        Perform comprehensive multi-source investigation.
        
        Args:
            target: Investigation target
            data_package: Dictionary with multiple data types
            
        Returns:
            InvestigationReport
        """
        import time
        start_time = time.time()
        
        investigation_id = hashlib.sha256(
            f"comprehensive_{target}_{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]
        
        all_findings = []
        all_evidence = []
        all_entities = defaultdict(list)
        
        # Process identity data
        if 'identity_data' in data_package:
            identity_report = self.investigate_identity(
                target,
                data_package['identity_data']
            )
            all_findings.extend(identity_report.findings)
            all_evidence.extend([
                Evidence(
                    source=e.source,
                    type=e.type,
                    content=e.content,
                    confidence=e.confidence,
                    metadata=e.metadata
                )
                for e in [
                    ev for f in identity_report.findings for ev in f.evidence
                ]
            ])
        
        # Process network data
        if 'network_data' in data_package:
            network_report = self.investigate_network(
                target,
                data_package['network_data']
            )
            all_findings.extend(network_report.findings)
        
        # Process text corpus
        if 'text_corpus' in data_package:
            texts = data_package['text_corpus']
            
            # Cluster analysis
            clusters = self.cluster_data(texts)
            
            # Sentiment analysis
            sentiments = [self.analyze_sentiment(t) for t in texts]
            avg_sentiment = np.mean([s['compound'] for s in sentiments])
            
            # Extract entities
            for text in texts:
                entities = self.extract_entities(text)
                for k, v in entities.items():
                    all_entities[k].extend(v)
            
            all_entities = {k: list(set(v)) for k, v in all_entities.items()}
            
            # Add findings
            if clusters.get('num_clusters', 0) > 0:
                all_findings.append(Finding(
                    title="Content Clustering Analysis",
                    description=f"Data clusters into {clusters['num_clusters']} groups",
                    evidence=[],
                    confidence=0.75,
                    severity='low'
                ))
            
            all_findings.append(Finding(
                title="Sentiment Profile",
                description=f"Average sentiment score: {avg_sentiment:.3f}",
                evidence=[],
                confidence=0.7,
                severity='low'
            ))
        
        # Deduplicate findings
        seen_titles = set()
        unique_findings = []
        for f in all_findings:
            if f.title not in seen_titles:
                seen_titles.add(f.title)
                unique_findings.append(f)
        
        # Assess threat
        threat = self.assess_threat(unique_findings, all_entities)
        
        # Generate recommendations
        recommendations = self.generate_recommendations(unique_findings, threat)
        
        # Timeline
        timeline = self.create_timeline(all_evidence)
        
        # Evidence summary
        evidence_summary = Counter([e.source for e in all_evidence])
        
        # Confidence
        confidence = sum(f.confidence for f in unique_findings) / len(unique_findings) if unique_findings else 0
        
        processing_time = time.time() - start_time
        
        report = InvestigationReport(
            investigation_id=investigation_id,
            investigation_type=InvestigationType.COMPREHENSIVE,
            target=target,
            findings=unique_findings,
            evidence_summary=dict(evidence_summary),
            threat_assessment=threat,
            recommendations=recommendations,
            timeline=timeline,
            confidence_score=confidence,
            processing_time=processing_time
        )
        
        self.investigation_history.append(report)
        return report
    
    def compare_targets(self,
                       target1_data: Dict,
                       target2_data: Dict) -> Dict:
        """
        Compare two targets for similarities.
        
        Args:
            target1_data: First target data
            target2_data: Second target data
            
        Returns:
            Comparison results
        """
        # Extract entities
        entities1 = self.extract_entities(str(target1_data))
        entities2 = self.extract_entities(str(target2_data))
        
        # Find common entities
        common = {}
        for key in set(entities1.keys()) & set(entities2.keys()):
            common_values = set(entities1[key]) & set(entities2[key])
            if common_values:
                common[key] = list(common_values)
        
        # Calculate similarity
        all_keys = set(entities1.keys()) | set(entities2.keys())
        if not all_keys:
            similarity = 0
        else:
            matching_keys = len(common)
            similarity = matching_keys / len(all_keys)
        
        # Text similarity using TF-IDF
        texts = [str(target1_data), str(target2_data)]
        try:
            vectorizer = TfidfVectorizer(stop_words=self.stop_words)
            tfidf = vectorizer.fit_transform(texts)
            text_sim = cosine_similarity(tfidf[0:1], tfidf[1:2])[0][0]
        except:
            text_sim = 0
        
        return {
            'similarity_score': (similarity + text_sim) / 2,
            'entity_overlap': common,
            'text_similarity': text_sim,
            'entity_similarity': similarity,
            'likely_related': (similarity + text_sim) / 2 > 0.5,
            'common_indicators': sum(len(v) for v in common.values())
        }
    
    def generate_investigation_summary(self, 
                                      report: InvestigationReport) -> str:
        """
        Generate human-readable investigation summary.
        
        Args:
            report: InvestigationReport
            
        Returns:
            Summary string
        """
        summary = f"""
╔══════════════════════════════════════════════════════════════╗
║           AI INVESTIGATION SUMMARY                           ║
╠══════════════════════════════════════════════════════════════╣
  Target: {report.target}
  Type: {report.investigation_type.value.title()}
  ID: {report.investigation_id}
  Date: {report.created_at}
╠══════════════════════════════════════════════════════════════╣
  FINDINGS: {len(report.findings)}
  CONFIDENCE: {report.confidence_score:.2%}
  THREAT LEVEL: {report.threat_assessment.get('level', 'Unknown').upper()}
  RISK SCORE: {report.threat_assessment.get('risk_score', 0):.2f}/1.0
╠══════════════════════════════════════════════════════════════╣
  KEY FINDINGS:
"""
        for i, finding in enumerate(report.findings[:5], 1):
            summary += f"  {i}. [{finding.severity.upper()}] {finding.title}\n"
        
        summary += f"""╠══════════════════════════════════════════════════════════════╣
  RECOMMENDATIONS:
"""
        for i, rec in enumerate(report.recommendations[:5], 1):
            summary += f"  {i}. {rec}\n"
        
        summary += "╚══════════════════════════════════════════════════════════════╝"
        
        return summary
    
    def export_report(self, 
                      report: InvestigationReport,
                      output_path: str,
                      format: str = 'json') -> str:
        """
        Export investigation report to file.
        
        Args:
            report: InvestigationReport
            output_path: Output file path
            format: 'json', 'markdown', or 'html'
            
        Returns:
            Path to exported file
        """
        if format == 'json':
            content = json.dumps(report.to_dict(), indent=2)
            ext = 'json'
        elif format == 'markdown':
            content = report.to_markdown()
            ext = 'md'
        elif format == 'html':
            md = report.to_markdown()
            content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Investigation Report - {report.target}</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; max-width: 1000px; margin: 0 auto; padding: 30px; background: #f5f5f5; }}
        .container {{ background: white; padding: 40px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #1a1a2e; border-bottom: 3px solid #e94560; padding-bottom: 15px; }}
        h2 {{ color: #16213e; margin-top: 35px; border-left: 4px solid #e94560; padding-left: 15px; }}
        .severity-critical {{ color: #e74c3c; font-weight: bold; }}
        .severity-high {{ color: #e67e22; font-weight: bold; }}
        .severity-medium {{ color: #f39c12; font-weight: bold; }}
        .severity-low {{ color: #27ae60; }}
        .meta {{ background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .finding {{ background: #fff; border: 1px solid #e0e0e0; padding: 20px; margin: 15px 0; border-radius: 8px; }}
        .timeline {{ border-left: 3px solid #e94560; padding-left: 20px; }}
        .timeline-item {{ margin: 15px 0; }}
        pre {{ background: #f4f4f4; padding: 15px; border-radius: 5px; overflow-x: auto; }}
    </style>
</head>
<body>
    <div class="container">
        {md.replace(chr(10), '<br>').replace('# ', '<h1>').replace('## ', '<h2>').replace('### ', '<h3>')}
    </div>
</body>
</html>"""
            ext = 'html'
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        # Ensure correct extension
        if not output_path.endswith(f'.{ext}'):
            output_path = f"{output_path}.{ext}"
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        logger.info(f"Report exported to {output_path}")
        return output_path
    
    def get_investigation_history(self, 
                                   target: Optional[str] = None) -> List[Dict]:
        """
        Get investigation history.
        
        Args:
            target: Filter by target (optional)
            
        Returns:
            List of investigation summaries
        """
        reports = self.investigation_history
        if target:
            reports = [r for r in reports if r.target == target]
        
        return [
            {
                'investigation_id': r.investigation_id,
                'type': r.investigation_type.value,
                'target': r.target,
                'findings_count': len(r.findings),
                'confidence': r.confidence_score,
                'threat_level': r.threat_assessment.get('level'),
                'created_at': r.created_at
            }
            for r in reports
        ]


# ============== CONVENIENCE FUNCTIONS ==============

def quick_investigate(target: str, data: List[Dict]) -> InvestigationReport:
    """Quick identity investigation."""
    investigator = AIInvestigator()
    return investigator.investigate_identity(target, data)


def analyze_text_patterns(texts: List[str]) -> Dict:
    """Analyze patterns in texts."""
    investigator = AIInvestigator()
    return {
        'entities': [investigator.extract_entities(t) for t in texts],
        'patterns': investigator.find_patterns(texts),
        'clusters': investigator.cluster_data(texts)
    }


def compare_investigation_targets(data1: Dict, data2: Dict) -> Dict:
    """Compare two investigation targets."""
    investigator = AIInvestigator()
    return investigator.compare_targets(data1, data2)


# ============== MAIN ==============

if __name__ == "__main__":
    print("=" * 70)
    print("OSINT AI Investigator v3.0")
    print("=" * 70)
    
    investigator = AIInvestigator()
    
    # Demo investigation
    demo_data = [
        {
            'name': 'social_media',
            'data': 'Contact john.doe@example.com or @johndoe on Twitter. Phone: +1-555-123-4567'
        },
        {
            'name': 'breach_db',
            'data': 'Found email john.doe@example.com in breach from 2023. Password: ********'
        },
        {
            'name': 'forum_post',
            'data': 'User johndoe posted about security exploits and hacking tools. IP: 192.168.1.100'
        }
    ]

    print("\n[*] Running demo identity investigation...")
    report = investigator.investigate_identity("john.doe@example.com", demo_data)

    print(f"\n[+] Investigation Complete!")
    print(f"    ID: {report.investigation_id}")
    print(f"    Findings: {len(report.findings)}")
    print(f"    Confidence: {report.confidence_score:.2%}")
    print(f"    Threat Level: {report.threat_assessment.get('level', 'Unknown').upper()}")

    print("\n" + "=" * 70)
    print(report.generate_investigation_summary(report))

    # Demo network investigation
    print("\n[*] Running demo network investigation...")
    network_data = [
        {'source': 'twitter', 'content': '@johndoe mentioned @hacker_group and shared link https://evil.com/malware'},
        {'source': 'forum', 'content': 'User johndoe contacted admin@darknet.com about exploit sale'},
        {'source': 'breach', 'content': 'john.doe@example.com linked to IP 10.0.0.50 in leaked database'},
        {'source': 'darkweb', 'content': 'Vendor johndoe selling credentials, BTC: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'},
    ]

    net_report = investigator.investigate_network("johndoe", network_data)
    print(f"\n[+] Network Analysis Complete!")
    print(f"    Communities: {len([f for f in net_report.findings if 'Communities' in f.title])}")
    print(f"    Patterns: {len([f for f in net_report.findings if 'Patterns' in f.title])}")

    # Demo comprehensive investigation
    print("\n[*] Running comprehensive investigation...")
    comprehensive_data = {
        'identity_data': demo_data,
        'network_data': network_data,
        'text_corpus': [
            "Security researcher john.doe@example.com published exploit code",
            "User @johndoe accused of selling stolen data on dark web",
            "IP 192.168.1.100 flagged for suspicious activity",
            "Email john.doe@example.com found in multiple breach databases",
        ]
    }

    comp_report = investigator.comprehensive_investigation("johndoe", comprehensive_data)
    print(f"\n[+] Comprehensive Report Generated!")
    print(f"    Total Findings: {len(comp_report.findings)}")
    print(f"    Overall Confidence: {comp_report.confidence_score:.2%}")
    print(f"    Risk Score: {comp_report.threat_assessment.get('risk_score', 0):.2f}/1.0")

    # Export demo report
    print("\n[*] Exporting report to markdown...")
    output_path = investigator.export_report(comp_report, "/mnt/agents/output/demo_report", "markdown")
    print(f"[+] Report saved to: {output_path}")

    # Show history
    print("\n[*] Investigation History:")
    for entry in investigator.get_investigation_history():
        print(f"    - {entry['investigation_id']}: {entry['target']} ({entry['type']})")

    print("\n" + "=" * 70)
    print("Demo complete! AI Investigator v3.0 ready for use.")
    print("=" * 70)