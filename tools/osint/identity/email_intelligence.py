import re
import json
import hashlib
import logging
import urllib.request
import urllib.error
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime

logger = logging.getLogger("osint.email_intel")


@dataclass
class EmailProfile:
    """Profile analysis untuk satu email address."""
    email: str
    domain: str
    local_part: str = ""
    gravatar_url: Optional[str] = None
    gravatar_hash: Optional[str] = None
    display_name: Optional[str] = None
    gravatar_exists: bool = False
    mx_records: List[str] = field(default_factory=list)
    mx_valid: bool = False
    domain_age: Optional[str] = None
    domain_registrar: Optional[str] = None
    is_disposable: bool = False
    is_role_account: bool = False
    pattern_type: str = ""  # "firstname.lastname", "f.lastname", "flastname", etc.
    confidence: float = 0.0
    
    def to_dict(self) -> dict:
        return asdict(self)


class EmailIntelligence:
    """
    Email intelligence analysis engine.
    """
    
    # Disposable email domains
    DISPOSABLE_DOMAINS = {
        "tempmail.com", "throwaway.com", "mailinator.com", "guerrillamail.com",
        "10minutemail.com", "yopmail.com", "sharklasers.com", "getairmail.com",
        "burnermail.io", "temp-mail.org", "fakeinbox.com", "getnada.com",
        "mailnesia.com", "tempinbox.com", "spamgourmet.com", "trashmail.com",
        "mytrashmail.com", "mailcatch.com", "incognitomail.com", "emailondeck.com",
        "tempmailaddress.com", "burneremail.com", "dispostable.com", "maildrop.cc",
    }
    
    # Role account patterns
    ROLE_PATTERNS = [
        r"^admin@", r"^support@", r"^info@", r"^contact@", r"^help@",
        r"^sales@", r"^marketing@", r"^billing@", r"^abuse@", r"^noc@",
        r"^security@", r"^postmaster@", r"^hostmaster@", r"^webmaster@",
        r"^root@", r"^postmaster@", r"^hostmaster@", r"^usenet@",
        r"^uucp@", r"^ftp@", r"^www@", r"^mail@", r"^news@",
    ]
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
    
    def _generate_gravatar_hash(self, email: str) -> str:
        """Generate Gravatar MD5 hash dari email."""
        return hashlib.md5(email.lower().strip().encode()).hexdigest()
    
    def _check_gravatar(self, email_hash: str) -> Tuple[bool, Optional[str]]:
        """
        Check if Gravatar exists untuk email hash.
        
        Returns:
            Tuple of (exists, display_name)
        """
        gravatar_url = f"https://www.gravatar.com/avatar/{email_hash}?s=200&d=404"
        
        try:
            req = urllib.request.Request(
                gravatar_url,
                method="HEAD",
                headers={"User-Agent": "Mozilla/5.0"},
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                if response.status == 200:
                    # Coba ambil display name dari profile
                    profile_url = f"https://www.gravatar.com/{email_hash}.json"
                    try:
                        profile_req = urllib.request.Request(
                            profile_url,
                            headers={"User-Agent": "Mozilla/5.0"},
                        )
                        with urllib.request.urlopen(profile_req, timeout=self.timeout) as profile_resp:
                            data = json.loads(profile_resp.read().decode())
                            entry = data.get("entry", [{}])[0]
                            display_name = entry.get("displayName") or entry.get("name", {}).get("formatted")
                            return True, display_name
                    except Exception:
                        return True, None
                return False, None
        except Exception:
            return False, None
    
    def _lookup_mx(self, domain: str) -> List[str]:
        """Lookup MX records for a domain using public DNS resolvers for reliability."""
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            # Use well‑known public DNS servers
            resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
            mx_records = []
            answers = resolver.resolve(domain, "MX")
            for rdata in answers:
                mx_records.append(str(rdata.exchange).rstrip("."))
            return mx_records
        except ImportError:
            logger.debug("dnspython not available for MX lookup")
            return []
        except Exception as e:
            logger.debug(f"MX lookup failed for {domain}: {e}")
            return []
    
    def _get_domain_info(self, domain: str) -> Dict[str, Any]:
        """Get domain registration info via WHOIS."""
        info = {
            "domain": domain,
            "age": None,
            "registrar": None
        }
        
        try:
            # Simple WHOIS query
            import socket
            whois_server = self._get_whois_server(domain)
            if whois_server:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((whois_server, 43))
                sock.send(f"{domain}\\r\\n".encode())
                
                response = b""
                while True:
                    data = sock.recv(4096)
                    if not data:
                        break
                    response += data
                sock.close()
                
                text = response.decode("utf-8", errors="replace")
                
                # Extract creation date
                date_match = re.search(r"Creation Date:\\s*(\\d{4}-\\d{2}-\\d{2})", text)
                if date_match:
                    created = datetime.strptime(date_match.group(1), "%Y-%m-%d")
                    age_days = (datetime.now() - created).days
                    info["age"] = f"{age_days // 365} years, {(age_days % 365) // 30} months"
                
                # Extract registrar
                reg_match = re.search(r"Registrar:\\s*([A-Za-z\\s\\.]+)", text)
                if reg_match:
                    info["registrar"] = reg_match.group(1).strip()
        except Exception as e:
            logger.debug(f"Domain info lookup failed: {e}")
        
        return info
    
    def _get_whois_server(self, domain: str) -> Optional[str]:
        """Get WHOIS server untuk domain TLD."""
        tld = domain.split(".")[-1].lower()
        servers = {
            "com": "whois.verisign-grs.com",
            "net": "whois.verisign-grs.com",
            "org": "whois.pir.org",
            "io": "whois.nic.io",
            "co": "whois.nic.co",
            "id": "whois.id",
            "info": "whois.afilias.net",
        }
        return servers.get(tld)
    
    def _detect_pattern(self, local_part: str) -> str:
        """
        Detect email username pattern.
        
        Patterns:
        - firstname.lastname
        - f.lastname
        - firstname_lastname
        - firstname_lastname
        - flastname
        - firstname
        - firstinitiallastname
        """
        if "." in local_part:
            parts = local_part.split(".")
            if len(parts) == 2:
                if len(parts[0]) > 1 and len(parts[1]) > 1:
                    return "firstname.lastname"
                elif len(parts[0]) == 1:
                    return "f.lastname"
        
        if "_" in local_part:
            parts = local_part.split("_")
            if len(parts) == 2:
                return "firstname_lastname"
        
        if "-" in local_part:
            parts = local_part.split("-")
            if len(parts) == 2:
                return "firstname-lastname"
        
        # Check flastname pattern
        if len(local_part) > 2 and local_part[1:].isalpha():
            return "flastname"
        
        # Check numeric suffix
        if re.search(r"\\d+$", local_part):
            return "name_with_number"
        
        return "unknown"
    
    def analyze(self, email: str) -> EmailProfile:
        """
        Analyze single email address.
        
        Args:
            email: Email address to analyze
            
        Returns:
            EmailProfile dengan analysis results
        """
        logger.info(f"[EmailIntel] Analyzing: {email}")
        
        # Parse email
        if "@" not in email:
            logger.error(f"Invalid email: {email}")
            return EmailProfile(email=email, domain="", confidence=0.0)
        
        local_part, domain = email.rsplit("@", 1)
        
        profile = EmailProfile(
            email=email,
            domain=domain,
            local_part=local_part
        )
        
        # Check Gravatar
        gravatar_hash = self._generate_gravatar_hash(email)
        profile.gravatar_hash = gravatar_hash
        profile.gravatar_url = f"https://www.gravatar.com/avatar/{gravatar_hash}?s=200"
        
        has_gravatar, display_name = self._check_gravatar(gravatar_hash)
        profile.gravatar_exists = has_gravatar
        profile.display_name = display_name
        
        # Check MX records
        profile.mx_records = self._lookup_mx(domain)
        profile.mx_valid = len(profile.mx_records) > 0
        
        # Domain info
        domain_info = self._get_domain_info(domain)
        profile.domain_age = domain_info.get("age")
        profile.domain_registrar = domain_info.get("registrar")
        
        # Check disposable
        profile.is_disposable = domain.lower() in self.DISPOSABLE_DOMAINS
        
        # Check role account
        for pattern in self.ROLE_PATTERNS:
            if re.match(pattern, email, re.IGNORECASE):
                profile.is_role_account = True
                break
        
        # Detect pattern
        profile.pattern_type = self._detect_pattern(local_part)
        
        # Calculate confidence
        confidence = 0.0
        if has_gravatar:
            confidence += 30.0
        if display_name:
            confidence += 20.0
        if profile.mx_valid:
            confidence += 15.0
        if profile.domain_age:
            confidence += 10.0
        if not profile.is_disposable:
            confidence += 10.0
        if not profile.is_role_account:
            confidence += 5.0
        
        profile.confidence = min(confidence, 100.0)
        
        logger.info(f"[EmailIntel] Gravatar: {has_gravatar}, MX: {profile.mx_valid}, "
                   f"Confidence: {profile.confidence}")
        
        return profile
    
    def analyze_multiple(self, emails: List[str]) -> List[EmailProfile]:
        """Analyze multiple emails."""
        profiles = []
        for email in emails:
            try:
                profile = self.analyze(email)
                profiles.append(profile)
            except Exception as e:
                logger.error(f"Email analysis error for {email}: {e}")
        return profiles
    
    def find_related_emails(self, base_email: str, patterns: Optional[List[str]] = None) -> List[str]:
        """
        Generate related email variants berdasarkan pattern.
        
        Args:
            base_email: Base email address
            patterns: List of pattern types to generate
            
        Returns:
            List of related email addresses
        """
        if "@" not in base_email:
            return []
        
        local, domain = base_email.rsplit("@", 1)
        
        if patterns is None:
            patterns = ["firstname.lastname", "f.lastname", "firstname_lastname", "flastname"]
        
        # This would require knowing the person's name
        # For now, return empty - would be populated dengan name data
        return []
    
    def check_breach(self, email: str) -> Dict[str, Any]:
        """
        Check if email appears in known breaches.
        Placeholder - requires V3 breach intelligence module.
        
        Returns:
            Dict dengan breach info
        """
        return {
            "email": email,
            "breached": None,
            "message": "Requires V3 Breach Intelligence module",
            "sources": []
        }
    
    def export_profiles(self, profiles: List[EmailProfile], filepath: str) -> str:
        """Export email profiles ke JSON."""
        data = {
            "total_analyzed": len(profiles),
            "profiles": [p.to_dict() for p in profiles]
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return filepath

    def investigate(self, email: str) -> str:
        """
        Investigate single email address and return a beautifully formatted report.
        """
        profile = self.analyze(email)
        lines = [
            f"╔══════════════════════════════════════════════════════════════╗",
            f"║                   EMAIL INTELLIGENCE REPORT                  ║",
            f"╠══════════════════════════════════════════════════════════════╣",
            f"  Email Address  : {profile.email}",
            f"  Domain         : {profile.domain}",
            f"  MX Valid       : {'YES' if profile.mx_valid else 'NO'}",
        ]
        if profile.mx_records:
            lines.append(f"  MX Servers     : {', '.join(profile.mx_records[:3])}")
            
        lines.append(f"  Gravatar Found : {'YES' if profile.gravatar_exists else 'NO'}")
        if profile.display_name:
            lines.append(f"  Display Name   : {profile.display_name}")
            
        if profile.domain_registrar:
            lines.append(f"  Registrar      : {profile.domain_registrar}")
        if profile.domain_age:
            lines.append(f"  Domain Age     : {profile.domain_age}")
            
        lines.extend([
            f"  Disposable Mail: {'YES' if profile.is_disposable else 'NO'}",
            f"  Role Account   : {'YES' if profile.is_role_account else 'NO'}",
            f"  Pattern Type   : {profile.pattern_type}",
            f"  Confidence Score: {profile.confidence}%",
            f"╚══════════════════════════════════════════════════════════════╝"
        ])
        return "\n".join(lines)