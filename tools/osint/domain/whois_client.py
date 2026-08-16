"""
WHOIS Client v1.0
Domain WHOIS lookup dengan structured parsing.
Supports registrar info, dates, nameservers, contact info extraction.
"""

import re
import json
import socket
import logging
from typing import Dict, Optional, List, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime
from urllib.parse import quote

logger = logging.getLogger("osint.whois")


@dataclass
class WhoisRecord:
    """Structured WHOIS record."""
    domain: str
    raw_text: str = ""
    registrar: Optional[str] = None
    registrar_url: Optional[str] = None
    registrar_iana_id: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    updated_date: Optional[str] = None
    status: List[str] = field(default_factory=list)
    name_servers: List[str] = field(default_factory=list)
    dnssec: Optional[str] = None

    # Contact info
    registrant_name: Optional[str] = None
    registrant_org: Optional[str] = None
    registrant_email: Optional[str] = None
    registrant_phone: Optional[str] = None
    registrant_country: Optional[str] = None

    admin_name: Optional[str] = None
    admin_org: Optional[str] = None
    admin_email: Optional[str] = None
    admin_phone: Optional[str] = None

    tech_name: Optional[str] = None
    tech_org: Optional[str] = None
    tech_email: Optional[str] = None
    tech_phone: Optional[str] = None

    # Analysis
    domain_age_days: Optional[int] = None
    days_until_expiry: Optional[int] = None
    privacy_protected: bool = False

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def is_expired(self) -> bool:
        """Check if domain is expired."""
        if not self.expiration_date:
            return False
        try:
            expiry = datetime.strptime(self.expiration_date, "%Y-%m-%d")
            return expiry < datetime.now()
        except ValueError:
            return False

    @property
    def is_recently_registered(self) -> bool:
        """Check if domain was registered within last 30 days."""
        if not self.creation_date:
            return False
        try:
            created = datetime.strptime(self.creation_date, "%Y-%m-%d")
            days = (datetime.now() - created).days
            return days <= 30
        except ValueError:
            return False


class WhoisClient:
    """
    WHOIS client dengan multiple lookup methods:
    1. Socket-based WHOIS protocol (direct)
    2. whois.com web scraping (fallback)
    3. who.is web scraping (fallback)
    """

    # WHOIS servers untuk TLDs
    WHOIS_SERVERS = {
        "com": "whois.verisign-grs.com",
        "net": "whois.verisign-grs.com",
        "org": "whois.pir.org",
        "io": "whois.nic.io",
        "co": "whois.nic.co",
        "id": "whois.id",
        "info": "whois.afilias.net",
        "biz": "whois.biz",
        "me": "whois.nic.me",
        "tv": "whois.nic.tv",
        "cc": "whois.nic.cc",
        "us": "whois.nic.us",
        "uk": "whois.nic.uk",
        "de": "whois.denic.de",
        "fr": "whois.nic.fr",
        "nl": "whois.sidn.nl",
        "eu": "whois.eu",
        "ru": "whois.tcinet.ru",
        "jp": "whois.jprs.jp",
        "cn": "whois.cnnic.cn",
        "br": "whois.registro.br",
        "au": "whois.auda.org.au",
        "in": "whois.registry.in",
    }

    # Regex patterns untuk parse WHOIS text
    PATTERNS = {
        "registrar": [
            r"Registrar:\s*(.+)",
            r" registrar_name:\s*(.+)",
            r"Sponsoring Registrar:\s*(.+)",
        ],
        "registrar_url": [
            r"Registrar URL:\s*(.+)",
            r" registrar_url:\s*(.+)",
        ],
        "creation_date": [
            r"Creation Date:\s*(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z?)",
            r"Creation Date:\s*(\d{4}-\d{2}-\d{2})",
            r"Created On:\s*(\d{4}-\d{2}-\d{2})",
            r"Domain Registration Date:\s*(.+)",
            r"created:\s*(\d{4}-\d{2}-\d{2})",
        ],
        "expiration_date": [
            r"Registry Expiry Date:\s*(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z?)",
            r"Expiration Date:\s*(\d{4}-\d{2}-\d{2})",
            r"Expires On:\s*(\d{4}-\d{2}-\d{2})",
            r"paid-till:\s*(\d{4}-\d{2}-\d{2})",
        ],
        "updated_date": [
            r"Updated Date:\s*(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z?)",
            r"Updated Date:\s*(\d{4}-\d{2}-\d{2})",
            r"Last Updated On:\s*(\d{4}-\d{2}-\d{2})",
            r"last-update:\s*(\d{4}-\d{2}-\d{2})",
        ],
        "name_servers": [
            r"Name Server:\s*(.+)",
            r"nserver:\s*(.+)",
            r"Nameserver:\s*(.+)",
        ],
        "status": [
            r"Domain Status:\s*(.+)",
            r"status:\s*(.+)",
        ],
        "dnssec": [
            r"DNSSEC:\s*(.+)",
        ],
        "registrant_name": [
            r"Registrant Name:\s*(.+)",
            r"Registrant:\s*(.+)",
        ],
        "registrant_org": [
            r"Registrant Organization:\s*(.+)",
            r"Registrant Org:\s*(.+)",
            r"org:\s*(.+)",
        ],
        "registrant_email": [
            r"Registrant Email:\s*(.+)",
            r" registrant_email:\s*(.+)",
        ],
        "registrant_phone": [
            r"Registrant Phone:\s*(.+)",
        ],
        "registrant_country": [
            r"Registrant Country:\s*(.+)",
            r"Country:\s*(.+)",
        ],
        "admin_email": [
            r"Admin Email:\s*(.+)",
        ],
        "tech_email": [
            r"Tech Email:\s*(.+)",
        ],
    }

    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    def _get_whois_server(self, domain: str) -> Optional[str]:
        """Determine WHOIS server berdasarkan TLD."""
        parts = domain.lower().split(".")
        if len(parts) >= 2:
            tld = parts[-1]
            return self.WHOIS_SERVERS.get(tld)
        return None

    def _whois_socket(self, domain: str, server: str) -> Optional[str]:
        """Query WHOIS via socket connection."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((server, 43))

            query = f"{domain}\r\n"
            sock.send(query.encode())

            response = b""
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data

            sock.close()
            return response.decode("utf-8", errors="replace")
        except Exception as e:
            logger.debug(f"WHOIS socket error: {e}")
            return None

    def _whois_web_fallback(self, domain: str) -> Optional[str]:
        """Fallback ke whois.com web scraping."""
        try:
            import urllib.request
            url = f"https://www.whois.com/whois/{quote(domain)}"
            headers = {"User-Agent": "Mozilla/5.0"}
            req = urllib.request.Request(url, headers=headers)

            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                html = resp.read().decode("utf-8", errors="replace")

            # Extract WHOIS data dari pre tag
            match = re.search(r'<pre[^>]*class="df-raw"[^>]*>(.*?)</pre>', html, re.DOTALL)
            if match:
                return match.group(1)

            return None
        except Exception as e:
            logger.debug(f"WHOIS web fallback error: {e}")
            return None

    def _parse_whois_text(self, domain: str, text: str) -> WhoisRecord:
        """Parse raw WHOIS text menjadi structured record."""
        record = WhoisRecord(domain=domain, raw_text=text)

        # Extract fields menggunakan regex patterns
        for field, patterns in self.PATTERNS.items():
            for pattern in patterns:
                matches = re.findall(pattern, text, re.IGNORECASE)
                if matches:
                    value = matches[0].strip()

                    if field == "name_servers":
                        record.name_servers = [m.strip().lower().rstrip(".") for m in matches]
                    elif field == "status":
                        record.status = [m.strip() for m in matches]
                    else:
                        setattr(record, field, value)
                    break

        # Parse dates
        for date_field in ["creation_date", "expiration_date", "updated_date"]:
            date_str = getattr(record, date_field)
            if date_str:
                # Normalize date format
                date_str = self._normalize_date(date_str)
                setattr(record, date_field, date_str)

        # Calculate domain age
        if record.creation_date:
            try:
                created = datetime.strptime(record.creation_date, "%Y-%m-%d")
                record.domain_age_days = (datetime.now() - created).days
            except ValueError:
                pass

        # Calculate days until expiry
        if record.expiration_date:
            try:
                expiry = datetime.strptime(record.expiration_date, "%Y-%m-%d")
                record.days_until_expiry = (expiry - datetime.now()).days
            except ValueError:
                pass

        # Detect privacy protection
        privacy_keywords = [
            "privacy", "whoisguard", "domains by proxy", "namecheap",
            "cloudflare", "redacted", "gdpr masked", "data protected",
            "not disclosed", "withheld", "private"
        ]
        text_lower = text.lower()
        record.privacy_protected = any(kw in text_lower for kw in privacy_keywords)

        return record

    def _normalize_date(self, date_str: str) -> str:
        """Normalize various date formats ke YYYY-MM-DD."""
        formats = [
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d",
            "%d-%b-%Y",
            "%d-%B-%Y",
            "%Y.%m.%d",
            "%Y/%m/%d",
        ]

        for fmt in formats:
            try:
                dt = datetime.strptime(date_str.strip(), fmt)
                return dt.strftime("%Y-%m-%d")
            except ValueError:
                continue

        return date_str

    def lookup(self, domain: str) -> Optional[WhoisRecord]:
        """
        Lookup WHOIS untuk domain.

        Args:
            domain: Domain name (e.g., "example.com")

        Returns:
            WhoisRecord atau None jika gagal
        """
        logger.info(f"[WHOIS] Looking up: {domain}")

        # Method 1: Socket-based WHOIS
        whois_server = self._get_whois_server(domain)
        if whois_server:
            text = self._whois_socket(domain, whois_server)
            if text:
                record = self._parse_whois_text(domain, text)
                logger.info(f"[WHOIS] Retrieved via socket from {whois_server}")
                return record

        # Method 2: Web fallback
        text = self._whois_web_fallback(domain)
        if text:
            record = self._parse_whois_text(domain, text)
            logger.info("[WHOIS] Retrieved via web fallback")
            return record

        logger.warning(f"[WHOIS] Failed to retrieve data for {domain}")
        return None

    def bulk_lookup(self, domains: List[str]) -> Dict[str, Optional[WhoisRecord]]:
        """Lookup multiple domains."""
        results = {}
        for domain in domains:
            results[domain] = self.lookup(domain)
            time.sleep(0.5)  # Rate limiting
        return results

    def get_domain_age(self, domain: str) -> Optional[int]:
        """Get domain age in days."""
        record = self.lookup(domain)
        return record.domain_age_days if record else None

    def check_expiry(self, domain: str, warning_days: int = 30) -> Dict[str, Any]:
        """
        Check domain expiry status.

        Returns:
            Dict dengan expiry info dan warnings
        """
        record = self.lookup(domain)
        if not record:
            return {"domain": domain, "error": "WHOIS lookup failed"}

        result = {
            "domain": domain,
            "expired": record.is_expired,
            "expiry_date": record.expiration_date,
            "days_until_expiry": record.days_until_expiry,
            "warning": False,
            "warning_message": None
        }

        if record.days_until_expiry is not None:
            if record.days_until_expiry < 0:
                result["warning"] = True
                result["warning_message"] = "Domain has EXPIRED"
            elif record.days_until_expiry <= warning_days:
                result["warning"] = True
                result["warning_message"] = f"Domain expires in {record.days_until_expiry} days"

        return result

    def export_record(self, record: WhoisRecord, filepath: str) -> str:
        """Export WHOIS record ke JSON."""
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(record.to_dict(), f, indent=2, ensure_ascii=False)
        return filepath