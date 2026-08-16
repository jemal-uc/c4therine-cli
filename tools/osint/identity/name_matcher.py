"""
Name Matcher v2.0
Advanced name matching dengan multiple algorithms:
- Exact match
- Jaro-Winkler similarity
- Levenshtein distance
- Phonetic matching (Soundex, Metaphone)
- Token-based matching
- Cultural name handling (Indonesian names)

Features:
- Normalization (accents, case, spacing)
- Nickname/alias matching
- Initial handling
- Indonesian name patterns (single name, patronymic)
"""

import re
import logging
from typing import List, Optional, Tuple, Dict, Set
from dataclasses import dataclass

logger = logging.getLogger("osint.name_matcher")


@dataclass
class NameMatchResult:
    """Result dari name matching."""
    name_a: str
    name_b: str
    score: float  # 0-1
    algorithm: str
    details: str
    is_match: bool = False

    def to_dict(self):
        return {
            "name_a": self.name_a,
            "name_b": self.name_b,
            "score": self.score,
            "algorithm": self.algorithm,
            "details": self.details,
            "is_match": self.is_match
        }


class NameMatcher:
    """
    Advanced name matching engine.
    Handles various name formats dan cultural patterns.
    """

    # Common nicknames mapping
    NICKNAMES = {
        "william": ["will", "bill", "billy", "willy"],
        "robert": ["rob", "bob", "bobby", "robbie"],
        "richard": ["rich", "rick", "dick", "ricky"],
        "james": ["jim", "jimmy", "jamie"],
        "john": ["johnny", "jon", "jack"],
        "michael": ["mike", "mikey", "mick"],
        "thomas": ["tom", "tommy"],
        "christopher": ["chris", "kit"],
        "daniel": ["dan", "danny"],
        "matthew": ["matt", "matty"],
        "joseph": ["joe", "joey"],
        "david": ["dave", "davey"],
        "andrew": ["andy", "drew"],
        "edward": ["ed", "eddie", "ted", "teddy"],
        "charles": ["charlie", "chuck"],
        "benjamin": ["ben", "benny"],
        "samuel": ["sam", "sammy"],
        "alexander": ["alex"],
        "nicholas": ["nick", "nicky"],
        "jonathan": ["jon", "john"],
        "stephen": ["steve", "stevie"],
        "anthony": ["tony"],
        "kenneth": ["ken", "kenny"],
        "timothy": ["tim", "timmy"],
        "ronald": ["ron", "ronnie"],
        "gregory": ["greg"],
        "joshua": ["josh"],
        "kevin": ["kev"],
        "brian": ["bri"],
        "jason": ["jay"],
        "jeffrey": ["jeff"],
        "scott": ["scotty"],
        "eric": ["rick"],
        "jacob": ["jake"],
        "nathan": ["nate"],
        "patrick": ["pat", "paddy"],
        "raymond": ["ray"],
        "henry": ["hank", "harry"],
        "peter": ["pete"],
        "frank": ["frankie"],
        "albert": ["al", "bert"],
        "philip": ["phil"],
        "roger": ["rog"],
        "howard": ["howie"],
        "eugene": ["gene"],
        "ralph": ["ralphy"],
        "roy": ["roy"],
        "russell": ["russ", "rusty"],
        "bobby": ["bob", "robert"],
        "tommy": ["tom", "thomas"],
        "jimmy": ["jim", "james"],
        "danny": ["dan", "daniel"],
        "eddie": ["ed", "edward"],
        "teddy": ["ted", "edward"],
        "ricky": ["rick", "richard"],
        "matt": ["matthew"],
        "mike": ["michael"],
        "chris": ["christopher", "christine"],
        "steve": ["stephen", "steven"],
        "dave": ["david"],
        "andy": ["andrew"],
        "bill": ["william"],
        "bob": ["robert"],
        "dick": ["richard"],
        "don": ["donald"],
        "doug": ["douglas"],
        "gene": ["eugene"],
        "hank": ["henry"],
        "harry": ["henry", "harold"],
        "jack": ["john"],
        "jay": ["jason", "james"],
        "jeff": ["jeffrey"],
        "jim": ["james"],
        "joe": ["joseph"],
        "jon": ["jonathan", "john"],
        "ken": ["kenneth"],
        "len": ["leonard"],
        "lou": ["louis", "lewis"],
        "mick": ["michael"],
        "mike": ["michael"],
        "nate": ["nathan"],
        "nick": ["nicholas"],
        "pat": ["patrick", "patricia"],
        "pete": ["peter"],
        "phil": ["philip"],
        "ray": ["raymond"],
        "rich": ["richard"],
        "rick": ["richard", "eric", "frederick", "patrick"],
        "rob": ["robert"],
        "ron": ["ronald"],
        "russ": ["russell"],
        "sam": ["samuel"],
        "sid": ["sidney"],
        "steve": ["stephen", "steven"],
        "ted": ["edward", "theodore"],
        "tim": ["timothy"],
        "tom": ["thomas"],
        "tony": ["anthony"],
        "vic": ["victor"],
        "wally": ["walter"],
        "walt": ["walter"],
        "will": ["william"],
        "willy": ["william"],
    }

    # Indonesian name patterns
    INDONESIAN_TITLES = ["dr", "prof", "ir", "h", "hj", "kh", "kyai", "ustad", "ustadz"]
    INDONESIAN_SUFFIXES = ["s", "sh", "m", "ma", "msi", "mph", "sp", "spd", "mm", "mba", "mcom"]

    def __init__(self, threshold: float = 0.7):
        """
        Initialize name matcher.

        Args:
            threshold: Minimum score untuk dianggap match
        """
        self.threshold = threshold

    def normalize(self, name: str) -> str:
        """
        Normalize name untuk comparison.
        - Lowercase
        - Remove accents
        - Remove extra spaces
        - Remove titles dan suffixes
        """
        if not name:
            return ""

        # Lowercase
        name = name.lower().strip()

        # Remove accents
        import unicodedata
        name = ''.join(c for c in unicodedata.normalize('NFD', name) 
                      if unicodedata.category(c) != 'Mn')

        # Remove titles
        for title in self.INDONESIAN_TITLES:
            name = re.sub(rf'\b{title}\b\.?\s*', '', name, flags=re.IGNORECASE)

        # Remove common suffixes
        for suffix in self.INDONESIAN_SUFFIXES:
            name = re.sub(rf'\b\.?\s*{suffix}\b\.?\s*$', '', name, flags=re.IGNORECASE)

        # Remove non-alphanumeric (keep spaces)
        name = re.sub(r'[^\w\s]', ' ', name)

        # Remove extra spaces
        name = ' '.join(name.split())

        return name.strip()

    def tokenize(self, name: str) -> List[str]:
        """Split name into tokens."""
        normalized = self.normalize(name)
        return normalized.split()

    def jaro_winkler(self, s1: str, s2: str) -> float:
        """Jaro-Winkler similarity."""
        if not s1 or not s2:
            return 0.0
        if s1 == s2:
            return 1.0

        s1, s2 = s1.lower(), s2.lower()
        len1, len2 = len(s1), len(s2)

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

        prefix = 0
        for i in range(min(4, len1, len2)):
            if s1[i] == s2[i]:
                prefix += 1
            else:
                break

        return jaro + prefix * 0.1 * (1 - jaro)

    def levenshtein_distance(self, s1: str, s2: str) -> int:
        """Levenshtein distance."""
        if len(s1) < len(s2):
            return self.levenshtein_distance(s2, s1)
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

    def levenshtein_similarity(self, s1: str, s2: str) -> float:
        """Levenshtein similarity (0-1)."""
        if not s1 and not s2:
            return 1.0
        if not s1 or not s2:
            return 0.0
        max_len = max(len(s1), len(s2))
        return 1.0 - (self.levenshtein_distance(s1, s2) / max_len)

    def soundex(self, name: str) -> str:
        """Soundex phonetic encoding."""
        if not name:
            return ""

        name = name.upper()
        soundex = name[0]

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

    def is_nickname(self, name1: str, name2: str) -> bool:
        """Check if two names are nickname variants."""
        n1 = name1.lower()
        n2 = name2.lower()

        for full_name, nicknames in self.NICKNAMES.items():
            all_names = [full_name] + nicknames
            if n1 in all_names and n2 in all_names:
                return True

        return False

    def match(self, name_a: str, name_b: str, algorithm: str = "combined") -> NameMatchResult:
        """
        Match two names.

        Args:
            name_a: First name
            name_b: Second name
            algorithm: "exact", "jaro", "levenshtein", "phonetic", "token", "combined"

        Returns:
            NameMatchResult
        """
        if not name_a or not name_b:
            return NameMatchResult(name_a, name_b, 0.0, algorithm, "Empty name", False)

        norm_a = self.normalize(name_a)
        norm_b = self.normalize(name_b)

        if algorithm == "exact":
            score = 1.0 if norm_a == norm_b else 0.0
            details = "Exact match" if score == 1.0 else "No exact match"

        elif algorithm == "jaro":
            score = self.jaro_winkler(norm_a, norm_b)
            details = f"Jaro-Winkler: {score:.3f}"

        elif algorithm == "levenshtein":
            score = self.levenshtein_similarity(norm_a, norm_b)
            details = f"Levenshtein: {score:.3f}"

        elif algorithm == "phonetic":
            sdx_a = self.soundex(norm_a)
            sdx_b = self.soundex(norm_b)
            score = 1.0 if sdx_a == sdx_b else 0.0
            details = f"Soundex: {sdx_a} vs {sdx_b}"

        elif algorithm == "token":
            tokens_a = set(self.tokenize(name_a))
            tokens_b = set(self.tokenize(name_b))

            if not tokens_a or not tokens_b:
                score = 0.0
                details = "No tokens"
            else:
                intersection = tokens_a & tokens_b
                union = tokens_a | tokens_b
                score = len(intersection) / len(union) if union else 0.0
                details = f"Token overlap: {len(intersection)}/{len(union)}"

                # Check nicknames
                for ta in tokens_a:
                    for tb in tokens_b:
                        if self.is_nickname(ta, tb):
                            score = max(score, 0.9)
                            details += f" (nickname: {ta}~{tb})"
                            break

        elif algorithm == "combined":
            # Run multiple algorithms dan combine
            jw_score = self.jaro_winkler(norm_a, norm_b)
            lev_score = self.levenshtein_similarity(norm_a, norm_b)

            sdx_a = self.soundex(norm_a)
            sdx_b = self.soundex(norm_b)
            phonetic_score = 1.0 if sdx_a == sdx_b else 0.0

            # Token-based
            tokens_a = set(self.tokenize(name_a))
            tokens_b = set(self.tokenize(name_b))
            token_score = 0.0
            if tokens_a and tokens_b:
                intersection = tokens_a & tokens_b
                union = tokens_a | tokens_b
                token_score = len(intersection) / len(union) if union else 0.0

                # Nickname bonus
                for ta in tokens_a:
                    for tb in tokens_b:
                        if self.is_nickname(ta, tb):
                            token_score = max(token_score, 0.9)
                            break

            # Weighted combination
            score = (jw_score * 0.35) + (lev_score * 0.25) + (phonetic_score * 0.15) + (token_score * 0.25)
            details = f"Combined: JW={jw_score:.2f}, LEV={lev_score:.2f}, PHON={phonetic_score:.2f}, TOK={token_score:.2f}"

        else:
            score = 0.0
            details = "Unknown algorithm"

        is_match = score >= self.threshold

        return NameMatchResult(
            name_a=name_a,
            name_b=name_b,
            score=round(score, 3),
            algorithm=algorithm,
            details=details,
            is_match=is_match
        )

    def find_best_match(self, target: str, candidates: List[str], algorithm: str = "combined") -> Optional[NameMatchResult]:
        """Find best matching candidate."""
        if not candidates:
            return None

        results = [self.match(target, candidate, algorithm) for candidate in candidates]
        results.sort(key=lambda x: x.score, reverse=True)

        return results[0] if results else None

    def find_all_matches(self, target: str, candidates: List[str], 
                         algorithm: str = "combined", min_score: float = 0.5) -> List[NameMatchResult]:
        """Find all candidates yang match threshold."""
        results = []
        for candidate in candidates:
            match = self.match(target, candidate, algorithm)
            if match.score >= min_score:
                results.append(match)

        results.sort(key=lambda x: x.score, reverse=True)
        return results

    def group_similar_names(self, names: List[str], threshold: float = 0.8) -> List[List[str]]:
        """
        Group similar names together.

        Returns:
            List of name groups
        """
        if not names:
            return []

        groups: List[Set[str]] = []
        used: Set[str] = set()

        for name in names:
            if name in used:
                continue

            group = {name}
            used.add(name)

            for other in names:
                if other in used:
                    continue

                result = self.match(name, other, "combined")
                if result.score >= threshold:
                    group.add(other)
                    used.add(other)

            groups.append(group)

        return [sorted(list(g)) for g in groups]