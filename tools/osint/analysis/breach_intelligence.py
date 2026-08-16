import re
import json
import time
import logging
import urllib.request
import urllib.error
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime
from urllib.parse import quote

logger = logging.getLogger("osint.breach_intel")


@dataclass
class BreachRecord:
    """Single breach record."""
    email: str
    breach_name: str
    breach_date: Optional[str] = None
    added_date: Optional[str] = None
    modified_date: Optional[str] = None
    description: Optional[str] = None
    data_classes: List[str] = field(default_factory=list)
    is_verified: bool = False
    is_fabricated: bool = False
    is_sensitive: bool = False
    is_retired: bool = False
    is_spam_list: bool = False
    password: Optional[str] = None  # From DeHashed (hashed/plain)
    hash_type: Optional[str] = None
    source: str = "unknown"  # "hibp" atau "dehashed"
    
    def to_dict(self) -> dict:
        return asdict(self)
    
    @property
    def severity(self) -> str:
        """Calculate breach severity."""
        if self.is_sensitive or "passwords" in [c.lower() for c in self.data_classes]:
            return "critical"
        elif "email addresses" in [c.lower() for c in self.data_classes]:
            return "high"
        elif self.is_verified:
            return "medium"
        return "low"


@dataclass
class BreachAnalysis:
    """Analysis hasil breach check."""
    email: str
    total_breaches: int = 0
    verified_breaches: int = 0
    sensitive_breaches: int = 0
    password_exposed: bool = False
    password_hash_types: List[str] = field(default_factory=list)
    earliest_breach: Optional[str] = None
    latest_breach: Optional[str] = None
    most_severe_breach: Optional[str] = None
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return asdict(self)


class BreachIntelligence:
    """
    Breach intelligence engine.
    Check credentials against known data breaches.
    """
    
    HIBP_API_BASE = "https://haveibeenpwned.com/api/v3"
    DEHASHED_API_BASE = "https://api.dehashed.com"
    
    # Common password patterns
    WEAK_PATTERNS = [
        r"^123456", r"^password", r"^qwerty", r"^abc123",
        r"^letmein", r"^welcome", r"^monkey", r"^dragon",
        r"^master", r"^sunshine", r"^princess", r"^admin",
        r"^login", r"^football", r"^baseball", r"^iloveyou",
    ]
    
    def __init__(self, 
                 hibp_api_key: Optional[str] = None,
                 dehashed_api_key: Optional[str] = None,
                 dehashed_username: Optional[str] = None,
                 rate_limit_delay: float = 1.6):
        """
        Initialize breach intelligence.
        
        Args:
            hibp_api_key: Have I Been Pwned API key
            dehashed_api_key: DeHashed API key
            dehashed_username: DeHashed username
            rate_limit_delay: Delay antara requests (HIBP requires 1.5s)
        """
        self.hibp_api_key = hibp_api_key
        self.dehashed_api_key = dehashed_api_key
        self.dehashed_username = dehashed_username
        self.rate_limit_delay = rate_limit_delay
    
    def _hibp_request(self, endpoint: str) -> Optional[Dict]:
        """Make authenticated request ke HIBP API."""
        if not self.hibp_api_key:
            logger.warning("HIBP API key not configured")
            return None
        
        url = f"{self.HIBP_API_BASE}/{endpoint}"
        headers = {
            "hibp-api-key": self.hibp_api_key,
            "User-Agent": "OSINT-Engine-v3.0",
        }
        
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=15) as response:
                return json.loads(response.read().decode())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return []  # No breaches found
            elif e.code == 429:
                logger.warning("HIBP rate limited, waiting...")
                time.sleep(5)
                return self._hibp_request(endpoint)
            logger.error(f"HIBP HTTP {e.code}: {e.reason}")
            return None
        except Exception as e:
            logger.error(f"HIBP request error: {e}")
            return None
    
    def _dehashed_request(self, query: str) -> Optional[Dict]:
        """Make authenticated request ke DeHashed API."""
        if not self.dehashed_api_key or not self.dehashed_username:
            logger.warning("DeHashed credentials not configured")
            return None
        
        import base64
        credentials = base64.b64encode(
            f"{self.dehashed_username}:{self.dehashed_api_key}".encode()
        ).decode()
        
        url = f"{self.DEHASHED_API_BASE}/search?query={quote(query)}"
        headers = {
            "Authorization": f"Basic {credentials}",
            "Accept": "application/json",
        }
        
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=15) as response:
                return json.loads(response.read().decode())
        except Exception as e:
            logger.error(f"DeHashed request error: {e}")
            return None
    
    def check_email_hibp(self, email: str) -> List[BreachRecord]:
        """
        Check email against Have I Been Pwned.
        
        Args:
            email: Email address to check
            
        Returns:
            List of BreachRecord objects
        """
        logger.info(f"[Breach] Checking HIBP for: {email}")
        
        data = self._hibp_request(f"breachedaccount/{quote(email)}")
        
        if data is None:
            return []
        
        if not isinstance(data, list):
            data = [data] if data else []
        
        records = []
        for breach in data:
            record = BreachRecord(
                email=email,
                breach_name=breach.get("Name", "Unknown"),
                breach_date=breach.get("BreachDate"),
                added_date=breach.get("AddedDate"),
                modified_date=breach.get("ModifiedDate"),
                description=breach.get("Description"),
                data_classes=breach.get("DataClasses", []),
                is_verified=breach.get("IsVerified", False),
                is_fabricated=breach.get("IsFabricated", False),
                is_sensitive=breach.get("IsSensitive", False),
                is_retired=breach.get("IsRetired", False),
                is_spam_list=breach.get("IsSpamList", False),
                source="hibp"
            )
            records.append(record)
        
        logger.info(f"[Breach] HIBP found {len(records)} breaches for {email}")
        time.sleep(self.rate_limit_delay)
        return records
    
    def check_email_dehashed(self, email: str) -> List[BreachRecord]:
        """
        Check email against DeHashed.
        
        Returns:
            List of BreachRecord objects
        """
        logger.info(f"[Breach] Checking DeHashed for: {email}")
        
        data = self._dehashed_request(f"email:{email}")
        
        if not data or "entries" not in data:
            return []
        
        records = []
        for entry in data.get("entries", []):
            record = BreachRecord(
                email=email,
                breach_name=entry.get("database_name", "Unknown"),
                breach_date=entry.get("breach_date"),
                password=entry.get("password"),
                hash_type=entry.get("hash_type"),
                source="dehashed"
            )
            records.append(record)
        
        logger.info(f"[Breach] DeHashed found {len(records)} records for {email}")
        return records
    
    def check_username(self, username: str) -> List[BreachRecord]:
        """
        Check username against breaches.
        
        Returns:
            List of BreachRecord objects
        """
        logger.info(f"[Breach] Checking username: {username}")
        
        # DeHashed supports username search
        records = []
        if self.dehashed_api_key:
            data = self._dehashed_request(f"username:{username}")
            if data and "entries" in data:
                for entry in data.get("entries", []):
                    record = BreachRecord(
                        email=entry.get("email", ""),
                        breach_name=entry.get("database_name", "Unknown"),
                        password=entry.get("password"),
                        hash_type=entry.get("hash_type"),
                        source="dehashed"
                    )
                    records.append(record)
        
        logger.info(f"[Breach] Found {len(records)} breaches for username {username}")
        return records
    
    def analyze_email(self, email: str, use_dehashed: bool = True) -> BreachAnalysis:
        """
        Comprehensive breach analysis untuk email.
        
        Args:
            email: Email to analyze
            use_dehashed: Also check DeHashed
            
        Returns:
            BreachAnalysis object
        """
        all_records = []
        
        # HIBP
        hibp_records = self.check_email_hibp(email)
        all_records.extend(hibp_records)
        
        # DeHashed
        if use_dehashed and self.dehashed_api_key:
            dehashed_records = self.check_email_dehashed(email)
            all_records.extend(dehashed_records)
        
        # Analyze
        analysis = BreachAnalysis(email=email)
        analysis.total_breaches = len(all_records)
        analysis.verified_breaches = sum(1 for r in all_records if r.is_verified)
        analysis.sensitive_breaches = sum(1 for r in all_records if r.is_sensitive)
        analysis.password_exposed = any(r.password for r in all_records)
        analysis.password_hash_types = list(set(
            r.hash_type for r in all_records if r.hash_type
        ))
        
        # Find dates
        dates = []
        for r in all_records:
            if r.breach_date:
                try:
                    dates.append(datetime.strptime(r.breach_date, "%Y-%m-%d"))
                except ValueError:
                    pass
        
        if dates:
            analysis.earliest_breach = min(dates).strftime("%Y-%m-%d")
            analysis.latest_breach = max(dates).strftime("%Y-%m-%d")
        
        # Most severe
        severity_order = {"critical": 3, "high": 2, "medium": 1, "low": 0}
        most_severe = max(
            all_records,
            key=lambda r: severity_order.get(r.severity, 0),
            default=None
        )
        if most_severe:
            analysis.most_severe_breach = most_severe.breach_name
        
        # Recommendations
        analysis.recommendations = self._generate_recommendations(analysis, all_records)
        
        return analysis
    
    def _generate_recommendations(self, analysis: BreachAnalysis, 
                                   records: List[BreachRecord]) -> List[str]:
        """Generate security recommendations."""
        recommendations = []
        
        if analysis.password_exposed:
            recommendations.append("CHANGE PASSWORD IMMEDIATELY - Password exposed in breach")
        
        if analysis.sensitive_breaches > 0:
            recommendations.append("Sensitive data exposed - review account security")
        
        if analysis.total_breaches > 5:
            recommendations.append("High breach count - consider using unique passwords per site")
        
        if not any("2fa" in str(r.data_classes).lower() for r in records):
            recommendations.append("Enable 2FA on all accounts")
        
        recommendations.append("Use a password manager untuk generate unique passwords")
        recommendations.append("Monitor accounts untuk suspicious activity")
        
        return recommendations
    
    def check_password_strength(self, password: str) -> Dict[str, Any]:
        """
        Analyze password strength.
        
        Returns:
            Dict dengan strength analysis
        """
        analysis = {
            "password": "*" * len(password),
            "length": len(password),
            "has_upper": bool(re.search(r"[A-Z]", password)),
            "has_lower": bool(re.search(r"[a-z]", password)),
            "has_digit": bool(re.search(r"\\d", password)),
            "has_special": bool(re.search(r"[!@#$%^&*(),.?\\\"{}|<>]", password)),
            "is_common": False,
            "patterns_found": [],
            "score": 0,
            "strength": "unknown"
        }
        
        # Check common patterns
        for pattern in self.WEAK_PATTERNS:
            if re.search(pattern, password, re.IGNORECASE):
                analysis["is_common"] = True
                analysis["patterns_found"].append(pattern)
        
        # Calculate score
        score = 0
        if analysis["length"] >= 12:
            score += 2
        elif analysis["length"] >= 8:
            score += 1
        
        if analysis["has_upper"]:
            score += 1
        if analysis["has_lower"]:
            score += 1
        if analysis["has_digit"]:
            score += 1
        if analysis["has_special"]:
            score += 1
        if not analysis["is_common"]:
            score += 2
        
        analysis["score"] = score
        
        if score >= 6:
            analysis["strength"] = "strong"
        elif score >= 4:
            analysis["strength"] = "moderate"
        elif score >= 2:
            analysis["strength"] = "weak"
        else:
            analysis["strength"] = "very_weak"
        
        return analysis
    
    def get_breach_details(self, breach_name: str) -> Optional[Dict[str, Any]]:
        """
        Get details about specific breach.
        
        Args:
            breach_name: Name of breach
            
        Returns:
            Breach details atau None
        """
        if not self.hibp_api_key:
            return None
        
        data = self._hibp_request(f"breach/{quote(breach_name)}")
        return data
    
    def export_analysis(self, analysis: BreachAnalysis, filepath: str) -> str:
        """Export breach analysis ke JSON."""
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(analysis.to_dict(), f, indent=2, ensure_ascii=False)
        return filepath