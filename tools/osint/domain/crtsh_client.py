"""
crt.sh Client v1.0
Query Certificate Transparency logs untuk subdomain discovery
dan certificate history analysis.
"""

import json
import logging
import urllib.request
import urllib.error
from typing import List, Dict, Optional, Set, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime
from urllib.parse import quote

logger = logging.getLogger("osint.crtsh")


@dataclass
class CertificateRecord:
    """Single certificate record dari crt.sh."""
    id: int
    logged_at: Optional[str] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    common_name: Optional[str] = None
    name_value: Optional[str] = None
    issuer_name: Optional[str] = None
    serial_number: Optional[str] = None
    san_list: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def is_expired(self) -> bool:
        """Check if certificate is expired."""
        if not self.not_after:
            return False
        try:
            expiry = datetime.strptime(self.not_after, "%Y-%m-%dT%H:%M:%S")
            return expiry < datetime.now()
        except ValueError:
            return False

    @property
    def domains(self) -> Set[str]:
        """Extract all domains from certificate."""
        domains = set()
        if self.common_name:
            domains.add(self.common_name.lower())
        if self.name_value:
            domains.add(self.name_value.lower())
        for san in self.san_list:
            domains.add(san.lower())
        return domains


class CrtShClient:
    """
    Client untuk crt.sh Certificate Transparency log.

    Features:
    - Query by domain untuk subdomain discovery
    - Query by identity untuk certificate history
    - Extract SANs (Subject Alternative Names)
    - Certificate validity analysis
    """

    BASE_URL = "https://crt.sh"

    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.last_results: List[CertificateRecord] = []

    def _make_request(self, url: str) -> Optional[str]:
        """Make HTTP request ke crt.sh."""
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json,text/html",
        }

        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                return response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            logger.error(f"crt.sh HTTP {e.code}: {e.reason}")
            return None
        except Exception as e:
            logger.error(f"crt.sh request error: {e}")
            return None

    def query_domain(
        self, 
        domain: str,
        exclude_expired: bool = True,
        deduplicate: bool = True
    ) -> List[CertificateRecord]:
        """
        Query certificates untuk sebuah domain.
        Returns semua certificates yang mencakup domain tersebut.

        Args:
            domain: Domain to query (e.g., "example.com")
            exclude_expired: Skip expired certificates
            deduplicate: Remove duplicate certificates

        Returns:
            List of CertificateRecord objects
        """
        logger.info(f"[crt.sh] Querying domain: {domain}")

        # Build query URL
        encoded_domain = quote(f"%.{domain}", safe="")
        url = f"{self.BASE_URL}/?q={encoded_domain}&output=json"

        response = self._make_request(url)
        if not response:
            logger.warning(f"[crt.sh] No response for {domain}")
            return []

        try:
            data = json.loads(response)
        except json.JSONDecodeError:
            logger.error(f"[crt.sh] Invalid JSON response")
            return []

        records = []
        seen_ids: Set[int] = set()

        for entry in data:
            cert_id = entry.get("id")
            if not cert_id or (deduplicate and cert_id in seen_ids):
                continue
            seen_ids.add(cert_id)

            # Parse SANs dari name_value
            san_list = []
            name_value = entry.get("name_value", "")
            if name_value:
                san_list = [s.strip().lower() for s in name_value.split("\n") if s.strip()]

            record = CertificateRecord(
                id=cert_id,
                logged_at=entry.get("entry_timestamp"),
                not_before=entry.get("not_before"),
                not_after=entry.get("not_after"),
                common_name=entry.get("common_name"),
                name_value=name_value,
                issuer_name=entry.get("issuer_name"),
                serial_number=entry.get("serial_number"),
                san_list=san_list
            )

            if exclude_expired and record.is_expired:
                continue

            records.append(record)

        self.last_results = records
        logger.info(f"[crt.sh] Found {len(records)} certificates for {domain}")
        return records

    def get_subdomains(self, domain: str, wildcard: bool = True) -> Set[str]:
        """
        Extract unique subdomains dari certificate records.

        Args:
            domain: Base domain
            wildcard: Include wildcard certificates (*.domain.com)

        Returns:
            Set of unique subdomains
        """
        records = self.query_domain(domain)

        subdomains: Set[str] = set()
        base_domain = domain.lower()

        for record in records:
            for san in record.san_list:
                san = san.lower().strip()

                # Skip if not related to target domain
                if base_domain not in san:
                    continue

                # Handle wildcards
                if san.startswith("*."):
                    if wildcard:
                        subdomains.add(san)
                    # Also add without wildcard
                    clean = san[2:]
                    if clean != base_domain:
                        subdomains.add(clean)
                else:
                    if san != base_domain:
                        subdomains.add(san)

        logger.info(f"[crt.sh] Extracted {len(subdomains)} subdomains for {domain}")
        return subdomains

    def get_certificate_history(self, domain: str) -> Dict[str, Any]:
        """
        Get certificate history analysis untuk domain.

        Returns:
            Dict dengan statistics dan timeline
        """
        records = self.query_domain(domain, exclude_expired=False)

        if not records:
            return {"domain": domain, "total_certificates": 0}

        # Analyze
        issuers: Dict[str, int] = {}
        first_seen = None
        last_seen = None
        expired_count = 0
        all_domains: Set[str] = set()

        for r in records:
            if r.issuer_name:
                issuers[r.issuer_name] = issuers.get(r.issuer_name, 0) + 1

            if r.is_expired:
                expired_count += 1

            all_domains.update(r.domains)

            if r.logged_at:
                try:
                    dt = datetime.strptime(r.logged_at, "%Y-%m-%dT%H:%M:%S.%f")
                    if first_seen is None or dt < first_seen:
                        first_seen = dt
                    if last_seen is None or dt > last_seen:
                        last_seen = dt
                except ValueError:
                    pass

        return {
            "domain": domain,
            "total_certificates": len(records),
            "active_certificates": len(records) - expired_count,
            "expired_certificates": expired_count,
            "unique_issuers": len(issuers),
            "top_issuers": dict(sorted(issuers.items(), key=lambda x: x[1], reverse=True)[:5]),
            "first_seen": first_seen.isoformat() if first_seen else None,
            "last_seen": last_seen.isoformat() if last_seen else None,
            "discovered_domains": sorted(all_domains),
            "total_discovered_domains": len(all_domains)
        }

    def query_by_identity(self, identity: str) -> List[CertificateRecord]:
        """
        Query certificates by identity (organization name, etc).
        Useful untuk find all domains owned by same organization.

        Args:
            identity: Organization or identity name

        Returns:
            List of CertificateRecord objects
        """
        logger.info(f"[crt.sh] Querying identity: {identity}")

        encoded = quote(identity, safe="")
        url = f"{self.BASE_URL}/?q={encoded}&output=json"

        response = self._make_request(url)
        if not response:
            return []

        try:
            data = json.loads(response)
        except json.JSONDecodeError:
            return []

        records = []
        for entry in data:
            cert_id = entry.get("id")
            if not cert_id:
                continue

            san_list = []
            name_value = entry.get("name_value", "")
            if name_value:
                san_list = [s.strip().lower() for s in name_value.split("\n") if s.strip()]

            record = CertificateRecord(
                id=cert_id,
                logged_at=entry.get("entry_timestamp"),
                not_before=entry.get("not_before"),
                not_after=entry.get("not_after"),
                common_name=entry.get("common_name"),
                name_value=name_value,
                issuer_name=entry.get("issuer_name"),
                serial_number=entry.get("serial_number"),
                san_list=san_list
            )
            records.append(record)

        logger.info(f"[crt.sh] Found {len(records)} certificates for identity {identity}")
        return records

    def export_results(self, records: List[CertificateRecord], filepath: str) -> str:
        """Export certificate records ke JSON."""
        data = {
            "query_time": datetime.now().isoformat(),
            "total_records": len(records),
            "records": [r.to_dict() for r in records]
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        logger.info(f"[crt.sh] Exported {len(records)} records to {filepath}")
        return filepath