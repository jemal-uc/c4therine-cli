import re
import json
import logging
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field, asdict
from urllib.parse import urlparse

logger = logging.getLogger("osint.entity_resolution")


@dataclass
class IdentityCorrelation:
    """Hasil korelasi identity antara dua kandidat."""
    candidate_a: Dict[str, Any]
    candidate_b: Dict[str, Any]
    identity_score: float = 0.0  # 0-100
    matching_fields: List[str] = field(default_factory=list)
    mismatching_fields: List[str] = field(default_factory=list)
    reasoning: List[str] = field(default_factory=list)
    confidence_level: str = "unknown"  # "high", "moderate", "low", "unknown"
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class EntityProfile:
    """Profile entity untuk resolution."""
    name: str = ""
    aliases: List[str] = field(default_factory=list)
    usernames: Set[str] = field(default_factory=set)
    emails: Set[str] = field(default_factory=set)
    phones: Set[str] = field(default_factory=set)
    locations: Set[str] = field(default_factory=set)
    education: List[Dict[str, Any]] = field(default_factory=list)
    websites: Set[str] = field(default_factory=set)
    social_profiles: Dict[str, str] = field(default_factory=dict)
    images: Set[str] = field(default_factory=set)
    
    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "aliases": self.aliases,
            "usernames": list(self.usernames),
            "emails": list(self.emails),
            "phones": list(self.phones),
            "locations": list(self.locations),
            "education": self.education,
            "websites": list(self.websites),
            "social_profiles": self.social_profiles,
            "images": list(self.images)
        }


class EntityResolutionEngine:
    """
    Engine untuk menentukan apakah dua entity adalah orang yang sama.
    Menggunakan weighted scoring berdasarkan multiple data points.
    """
    
    # Default weights untuk setiap field
    DEFAULT_WEIGHTS = {
        "name": 25.0,
        "username": 20.0,
        "email": 20.0,
        "location": 10.0,
        "education": 10.0,
        "website": 8.0,
        "image": 7.0
    }
    
    # Confidence thresholds
    HIGH_CONFIDENCE = 80.0
    MODERATE_CONFIDENCE = 60.0
    LOW_CONFIDENCE = 40.0
    
    def __init__(self, weights: Optional[Dict[str, float]] = None):
        """
        Initialize entity resolution engine.
        
        Args:
            weights: Custom weights untuk scoring (default: DEFAULT_WEIGHTS)
        """
        self.weights = weights or dict(self.DEFAULT_WEIGHTS)
        self.total_weight = sum(self.weights.values())
    
    def _normalize_text(self, text: str) -> str:
        """Normalize text untuk comparison."""
        if not text:
            return ""
        # Remove non-alphanumeric, lowercase
        return re.sub(r'[^\\w]', '', text.lower().strip())
    
    def _jaro_winkler(self, s1: str, s2: str) -> float:
        """
        Jaro-Winkler similarity (0-1).
        Lebih baik untuk nama dan short strings.
        """
        if not s1 or not s2:
            return 0.0
        if s1 == s2:
            return 1.0
        
        s1, s2 = s1.lower(), s2.lower()
        len1, len2 = len(s1), len(s2)
        
        if len1 == 0 or len2 == 0:
            return 0.0
        
        # Matching window
        match_distance = max(len1, len2) // 2 - 1
        s1_matches = [False] * len1
        s2_matches = [False] * len2
        
        matches = 0
        for i in range(len1):
            start = max(0, i - match_distance)
            end = min(i + match_distance + 1, len2)
            
            for j in range(start, end):
                if s2_matches[j] or s1[i] != s2[j]:
                    continue
                s1_matches[i] = True
                s2_matches[j] = True
                matches += 1
                break
        
        if matches == 0:
            return 0.0
        
        # Transpositions
        k = 0
        transpositions = 0
        for i in range(len1):
            if not s1_matches[i]:
                continue
            while not s2_matches[k]:
                k += 1
            if s1[i] != s2[k]:
                transpositions += 1
            k += 1
        
        jaro = (matches / len1 + matches / len2 + (matches - transpositions / 2) / matches) / 3.0
        
        # Jaro-Winkler prefix bonus
        prefix = 0
        for i in range(min(4, len1, len2)):
            if s1[i] == s2[i]:
                prefix += 1
            else:
                break
        
        return jaro + prefix * 0.1 * (1 - jaro)
    
    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein distance."""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    def _levenshtein_similarity(self, s1: str, s2: str) -> float:
        """Levenshtein similarity (0-1)."""
        if not s1 and not s2:
            return 1.0
        if not s1 or not s2:
            return 0.0
        
        max_len = max(len(s1), len(s2))
        distance = self._levenshtein_distance(s1, s2)
        return 1.0 - (distance / max_len)
    
    def _soundex(self, name: str) -> str:
        """
        Simple Soundex-like phonetic encoding.
        Untuk catch nama yang dieja berbeda tapi dibaca sama.
        """
        if not name:
            return ""
        
        name = name.upper()
        soundex = name[0]
        
        # Soundex mapping
        mapping = {
            'B': '1', 'F': '1', 'P': '1', 'V': '1',
            'C': '2', 'G': '2', 'J': '2', 'K': '2', 'Q': '2', 'S': '2', 'X': '2', 'Z': '2',
            'D': '3', 'T': '3',
            'L': '4',
            'M': '5', 'N': '5',
            'R': '6'
        }
        
        prev_code = mapping.get(soundex, '')
        for char in name[1:]:
            code = mapping.get(char, '')
            if code and code != prev_code:
                soundex += code
                prev_code = code
            if len(soundex) == 4:
                break
        
        return soundex.ljust(4, '0')
    
    def _compare_names(self, name1: str, name2: str) -> Tuple[float, str]:
        """
        Compare two names dengan multiple algorithms.
        
        Returns:
            Tuple of (score 0-1, reason)
        """
        n1 = self._normalize_text(name1)
        n2 = self._normalize_text(name2)
        
        if not n1 or not n2:
            return 0.0, "No name data"
        
        if n1 == n2:
            return 1.0, "Exact name match"
        
        # Jaro-Winkler (best untuk names)
        jw_sim = self._jaro_winkler(n1, n2)
        
        # Levenshtein
        lev_sim = self._levenshtein_similarity(n1, n2)
        
        # Phonetic
        sdx1 = self._soundex(name1)
        sdx2 = self._soundex(name2)
        phonetic_match = sdx1 == sdx2
        
        # Combined score (weighted average)
        score = (jw_sim * 0.5) + (lev_sim * 0.3) + (0.2 if phonetic_match else 0.0)
        
        if score >= 0.9:
            return score, f"Very similar names (JW: {jw_sim:.2f}, LEV: {lev_sim:.2f})"
        elif score >= 0.7:
            return score * 0.8, f"Similar names (JW: {jw_sim:.2f})"
        elif score >= 0.5:
            return score * 0.5, f"Partial name match (JW: {jw_sim:.2f})"
        else:
            return 0.0, f"Names don't match (JW: {jw_sim:.2f})"
    
    def _compare_usernames(self, u1: Set[str], u2: Set[str]) -> Tuple[float, str]:
        """Compare username sets."""
        if not u1 or not u2:
            return 0.0, "No username data"
        
        u1_lower = {u.lower() for u in u1}
        u2_lower = {u.lower() for u in u2}
        
        intersection = u1_lower & u2_lower
        if intersection:
            return 1.0, f"Shared usernames: {intersection}"
        
        # Check similarity
        best_sim = 0.0
        best_pair = None
        for a in u1_lower:
            for b in u2_lower:
                sim = self._jaro_winkler(a, b)
                if sim > best_sim:
                    best_sim = sim
                    best_pair = (a, b)
        
        if best_sim >= 0.9:
            return best_sim, f"Very similar usernames: {best_pair} ({best_sim:.2f})"
        elif best_sim >= 0.8:
            return best_sim * 0.8, f"Similar usernames: {best_pair} ({best_sim:.2f})"
        
        return 0.0, "No username overlap"
    
    def _compare_emails(self, e1: Set[str], e2: Set[str]) -> Tuple[float, str]:
        """Compare email sets."""
        if not e1 or not e2:
            return 0.0, "No email data"
        
        e1_lower = {e.lower() for e in e1}
        e2_lower = {e.lower() for e in e2}
        
        intersection = e1_lower & e2_lower
        if intersection:
            return 1.0, f"Shared emails: {intersection}"
        
        # Check same domain
        d1 = {e.split("@")[1] for e in e1_lower if "@" in e}
        d2 = {e.split("@")[1] for e in e2_lower if "@" in e}
        domain_overlap = d1 & d2
        
        if domain_overlap:
            return 0.3, f"Same email domain: {domain_overlap}"
        
        # Check local part similarity
        l1 = {e.split("@")[0] for e in e1_lower if "@" in e}
        l2 = {e.split("@")[0] for e in e2_lower if "@" in e}
        local_overlap = l1 & l2
        
        if local_overlap:
            return 0.2, f"Same email local part: {local_overlap}"
        
        return 0.0, "No email overlap"
    
    def _compare_locations(self, l1: Set[str], l2: Set[str]) -> Tuple[float, str]:
        """Compare location sets."""
        if not l1 or not l2:
            return 0.0, "No location data"
        
        l1_lower = {l.lower() for l in l1}
        l2_lower = {l.lower() for l in l2}
        
        intersection = l1_lower & l2_lower
        if intersection:
            return 1.0, f"Shared locations: {intersection}"
        
        # Partial match
        for a in l1_lower:
            for b in l2_lower:
                if a in b or b in a:
                    return 0.7, f"Related locations: {a} / {b}"
        
        return 0.0, "No location overlap"
    
    def _compare_education(self, edu1: List[Dict], edu2: List[Dict]) -> Tuple[float, str]:
        """Compare education records."""
        if not edu1 or not edu2:
            return 0.0, "No education data"
        
        pt1 = {e.get("institution", "").lower() for e in edu1 if e.get("institution")}
        pt2 = {e.get("institution", "").lower() for e in edu2 if e.get("institution")}
        
        prodi1 = {e.get("program", "").lower() for e in edu1 if e.get("program")}
        prodi2 = {e.get("program", "").lower() for e in edu2 if e.get("program")}
        
        pt_overlap = pt1 & pt2
        prodi_overlap = prodi1 & prodi2
        
        if pt_overlap and prodi_overlap:
            return 1.0, f"Same university and program: {pt_overlap}, {prodi_overlap}"
        elif pt_overlap:
            return 0.7, f"Same university: {pt_overlap}"
        elif prodi_overlap:
            return 0.5, f"Same program: {prodi_overlap}"
        
        return 0.0, "No education overlap"
    
    def _compare_websites(self, w1: Set[str], w2: Set[str]) -> Tuple[float, str]:
        """Compare website sets."""
        if not w1 or not w2:
            return 0.0, "No website data"
        
        w1_lower = {w.lower().rstrip("/") for w in w1}
        w2_lower = {w.lower().rstrip("/") for w in w2}
        
        intersection = w1_lower & w2_lower
        if intersection:
            return 1.0, f"Shared websites: {intersection}"
        
        # Same domain
        d1 = {urlparse(w).netloc for w in w1_lower if urlparse(w).netloc}
        d2 = {urlparse(w).netloc for w in w2_lower if urlparse(w).netloc}
        domain_overlap = d1 & d2
        
        if domain_overlap:
            return 0.8, f"Same domain: {domain_overlap}"
        
        return 0.0, "No website overlap"
    
    def resolve(
        self,
        candidate_a: EntityProfile,
        candidate_b: EntityProfile
    ) -> IdentityCorrelation:
        """
        Hitung kemungkinan dua entity adalah orang yang sama.
        
        Args:
            candidate_a: First entity profile
            candidate_b: Second entity profile
            
        Returns:
            IdentityCorrelation dengan score dan reasoning
        """
        scores = {}
        reasons = []
        matching = []
        mismatching = []
        
        # Name comparison
        name_score, name_reason = self._compare_names(candidate_a.name, candidate_b.name)
        # Also check aliases
        for alias_a in candidate_a.aliases:
            for alias_b in candidate_b.aliases:
                alias_score, alias_reason = self._compare_names(alias_a, alias_b)
                if alias_score > name_score:
                    name_score = alias_score
                    name_reason = f"Alias match: {alias_reason}"
        
        scores["name"] = name_score
        reasons.append(f"Name: {name_reason}")
        if name_score > 0.5:
            matching.append("name")
        else:
            mismatching.append("name")
        
        # Username comparison
        u_score, u_reason = self._compare_usernames(candidate_a.usernames, candidate_b.usernames)
        scores["username"] = u_score
        reasons.append(f"Username: {u_reason}")
        if u_score > 0.5:
            matching.append("username")
        else:
            mismatching.append("username")
        
        # Email comparison
        e_score, e_reason = self._compare_emails(candidate_a.emails, candidate_b.emails)
        scores["email"] = e_score
        reasons.append(f"Email: {e_reason}")
        if e_score > 0.5:
            matching.append("email")
        else:
            mismatching.append("email")
        
        # Location comparison
        l_score, l_reason = self._compare_locations(candidate_a.locations, candidate_b.locations)
        scores["location"] = l_score
        reasons.append(f"Location: {l_reason}")
        if l_score > 0.5:
            matching.append("location")
        else:
            mismatching.append("location")
        
        # Education comparison
        edu_score, edu_reason = self._compare_education(candidate_a.education, candidate_b.education)
        scores["education"] = edu_score
        reasons.append(f"Education: {edu_reason}")
        if edu_score > 0.5:
            matching.append("education")
        else:
            mismatching.append("education")
        
        # Website comparison
        w_score, w_reason = self._compare_websites(candidate_a.websites, candidate_b.websites)
        scores["website"] = w_score
        reasons.append(f"Website: {w_reason}")
        if w_score > 0.5:
            matching.append("website")
        else:
            mismatching.append("website")
        
        # Calculate weighted identity score
        weighted_sum = sum(scores.get(k, 0) * self.weights.get(k, 0) for k in self.weights)
        identity_score = (weighted_sum / self.total_weight) * 100
        
        # Determine confidence level
        if identity_score >= self.HIGH_CONFIDENCE:
            confidence = "high"
        elif identity_score >= self.MODERATE_CONFIDENCE:
            confidence = "moderate"
        elif identity_score >= self.LOW_CONFIDENCE:
            confidence = "low"
        else:
            confidence = "unknown"
        
        return IdentityCorrelation(
            candidate_a=candidate_a.to_dict(),
            candidate_b=candidate_b.to_dict(),
            identity_score=round(min(identity_score, 100.0), 2),
            matching_fields=matching,
            mismatching_fields=mismatching,
            reasoning=reasons,
            confidence_level=confidence
        )
    
    def resolve_multiple(
        self,
        candidates: List[EntityProfile]
    ) -> List[IdentityCorrelation]:
        """
        Compare all pairs of candidates.
        
        Returns:
            List of IdentityCorrelation, sorted by score descending
        """
        correlations = []
        
        for i in range(len(candidates)):
            for j in range(i + 1, len(candidates)):
                corr = self.resolve(candidates[i], candidates[j])
                correlations.append(corr)
        
        correlations.sort(key=lambda x: x.identity_score, reverse=True)
        return correlations
    
    def find_matches(
        self,
        target: EntityProfile,
        candidates: List[EntityProfile],
        min_score: float = 60.0
    ) -> List[IdentityCorrelation]:
        """
        Find all candidates yang potentially match target.
        
        Args:
            target: Target entity
            candidates: List of candidates to compare
            min_score: Minimum identity score untuk dianggap match
            
        Returns:
            List of matches sorted by score
        """
        matches = []
        for candidate in candidates:
            corr = self.resolve(target, candidate)
            if corr.identity_score >= min_score:
                matches.append(corr)
        
        matches.sort(key=lambda x: x.identity_score, reverse=True)
        return matches
    
    def cluster_entities(
        self,
        entities: List[EntityProfile],
        threshold: float = 70.0
    ) -> List[List[EntityProfile]]:
        """
        Cluster entities yang kemungkinan sama orang.
        
        Returns:
            List of clusters (each cluster is list of EntityProfile)
        """
        n = len(entities)
        parent = list(range(n))
        
        def find(x):
            if parent[x] != x:
                parent[x] = find(parent[x])
            return parent[x]
        
        def union(x, y):
            px, py = find(x), find(y)
            if px != py:
                parent[px] = py
        
        # Compare all pairs dan union jika score >= threshold
        for i in range(n):
            for j in range(i + 1, n):
                corr = self.resolve(entities[i], entities[j])
                if corr.identity_score >= threshold:
                    union(i, j)
        
        # Build clusters
        clusters: Dict[int, List[int]] = {}
        for i in range(n):
            root = find(i)
            if root not in clusters:
                clusters[root] = []
            clusters[root].append(i)
        
        # Convert ke EntityProfile clusters