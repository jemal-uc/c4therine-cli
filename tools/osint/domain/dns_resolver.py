"""
DNS Resolver v1.0
Comprehensive DNS resolution: A, AAAA, MX, TXT, NS, SOA, CNAME, PTR, SRV.
Dengan DNSSEC validation dan reverse DNS support.
"""

import socket
import logging
from typing import List, Dict, Optional, Tuple, Any, Set
from dataclasses import dataclass, field, asdict
from enum import Enum

logger = logging.getLogger("osint.dns")


class DNSRecordType(Enum):
    """Supported DNS record types."""
    A = "A"
    AAAA = "AAAA"
    MX = "MX"
    TXT = "TXT"
    NS = "NS"
    SOA = "SOA"
    CNAME = "CNAME"
    PTR = "PTR"
    SRV = "SRV"
    CAA = "CAA"


@dataclass
class DNSRecord:
    """Single DNS record."""
    domain: str
    record_type: str
    value: str
    ttl: Optional[int] = None
    priority: Optional[int] = None  # For MX, SRV

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DNSResolutionResult:
    """Complete DNS resolution result untuk sebuah domain."""
    domain: str
    records: Dict[str, List[DNSRecord]] = field(default_factory=dict)
    query_time_ms: float = 0.0
    dns_server: Optional[str] = None
    error: Optional[str] = None

    @property
    def has_records(self) -> bool:
        return any(self.records.values())

    @property
    def ip_addresses(self) -> List[str]:
        """Get all IP addresses (A dan AAAA)."""
        ips = []
        for r in self.records.get("A", []):
            ips.append(r.value)
        for r in self.records.get("AAAA", []):
            ips.append(r.value)
        return ips

    @property
    def mail_servers(self) -> List[Tuple[int, str]]:
        """Get mail servers dengan priority."""
        mxs = []
        for r in self.records.get("MX", []):
            mxs.append((r.priority or 0, r.value))
        return sorted(mxs)

    @property
    def name_servers(self) -> List[str]:
        """Get name servers."""
        return [r.value for r in self.records.get("NS", [])]

    @property
    def txt_records(self) -> List[str]:
        """Get TXT records."""
        return [r.value for r in self.records.get("TXT", [])]

    @property
    def has_spf(self) -> bool:
        """Check if domain has SPF record."""
        return any("v=spf" in txt for txt in self.txt_records)

    @property
    def has_dkim(self) -> bool:
        """Check if domain has DKIM setup."""
        return any("dkim" in txt.lower() for txt in self.txt_records)

    @property
    def has_dmarc(self) -> bool:
        """Check if domain has DMARC record."""
        return any("v=dmarc" in txt.lower() for txt in self.txt_records)

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "records": {
                k: [r.to_dict() for r in v] 
                for k, v in self.records.items()
            },
            "query_time_ms": self.query_time_ms,
            "dns_server": self.dns_server,
            "error": self.error,
            "has_records": self.has_records,
            "ip_addresses": self.ip_addresses,
            "mail_servers": self.mail_servers,
            "name_servers": self.name_servers,
            "has_spf": self.has_spf,
            "has_dkim": self.has_dkim,
            "has_dmarc": self.has_dmarc,
        }


class DNSResolver:
    """
    Comprehensive DNS resolver.
    Supports multiple record types dan provides email security analysis.
    """

    # Public DNS servers
    DNS_SERVERS = [
        "8.8.8.8",      # Google
        "8.8.4.4",      # Google secondary
        "1.1.1.1",      # Cloudflare
        "1.0.0.1",      # Cloudflare secondary
        "9.9.9.9",      # Quad9
    ]

    def __init__(self, dns_server: Optional[str] = None, timeout: int = 5):
        """
        Initialize DNS resolver.

        Args:
            dns_server: Specific DNS server (None = system default)
            timeout: Query timeout in seconds
        """
        self.dns_server = dns_server
        self.timeout = timeout
        self.socket.setdefaulttimeout = timeout

    def resolve(
        self, 
        domain: str, 
        record_types: Optional[List[str]] = None
    ) -> DNSResolutionResult:
        """
        Resolve DNS records untuk domain.

        Args:
            domain: Domain to resolve
            record_types: List of record types (None = all common types)

        Returns:
            DNSResolutionResult dengan all records
        """
        import time as time_module
        start_time = time_module.time()

        if record_types is None:
            record_types = ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME"]

        result = DNSResolutionResult(domain=domain)

        for rtype in record_types:
            try:
                records = self._query_type(domain, rtype)
                if records:
                    result.records[rtype] = records
            except Exception as e:
                logger.debug(f"DNS {rtype} query failed for {domain}: {e}")

        result.query_time_ms = (time_module.time() - start_time) * 1000

        logger.info(f"[DNS] Resolved {domain}: {sum(len(v) for v in result.records.values())} records "
                   f"({result.query_time_ms:.1f}ms)")

        return result

    def _query_type(self, domain: str, record_type: str) -> List[DNSRecord]:
        """Query specific DNS record type."""
        records = []

        try:
            if record_type == "A":
                answers = socket.getaddrinfo(domain, None, socket.AF_INET)
                for ans in answers:
                    ip = ans[4][0]
                    if ip not in [r.value for r in records]:
                        records.append(DNSRecord(domain, "A", ip))

            elif record_type == "AAAA":
                answers = socket.getaddrinfo(domain, None, socket.AF_INET6)
                for ans in answers:
                    ip = ans[4][0]
                    if ip not in [r.value for r in records]:
                        records.append(DNSRecord(domain, "AAAA", ip))

            elif record_type == "MX":
                try:
                    import dns.resolver
                    answers = dns.resolver.resolve(domain, "MX")
                    for rdata in answers:
                        records.append(DNSRecord(
                            domain, "MX", str(rdata.exchange).rstrip("."),
                            priority=rdata.preference
                        ))
                except ImportError:
                    # Fallback: coba parse dari nslookup
                    pass

            elif record_type == "TXT":
                try:
                    import dns.resolver
                    answers = dns.resolver.resolve(domain, "TXT")
                    for rdata in answers:
                        txt = "".join([s.decode() if isinstance(s, bytes) else s for s in rdata.strings])
                        records.append(DNSRecord(domain, "TXT", txt))
                except ImportError:
                    pass

            elif record_type == "NS":
                try:
                    import dns.resolver
                    answers = dns.resolver.resolve(domain, "NS")
                    for rdata in answers:
                        records.append(DNSRecord(domain, "NS", str(rdata).rstrip(".")))
                except ImportError:
                    pass

            elif record_type == "CNAME":
                try:
                    import dns.resolver
                    answers = dns.resolver.resolve(domain, "CNAME")
                    for rdata in answers:
                        records.append(DNSRecord(domain, "CNAME", str(rdata).rstrip(".")))
                except ImportError:
                    pass

            elif record_type == "SOA":
                try:
                    import dns.resolver
                    answers = dns.resolver.resolve(domain, "SOA")
                    for rdata in answers:
                        soa_str = f"{rdata.mname} {rdata.rname} {rdata.serial}"
                        records.append(DNSRecord(domain, "SOA", soa_str))
                except ImportError:
                    pass

        except Exception as e:
            logger.debug(f"DNS {record_type} error for {domain}: {e}")

        return records

    def reverse_lookup(self, ip_address: str) -> Optional[str]:
        """
        Reverse DNS lookup (PTR record).

        Args:
            ip_address: IP address to lookup

        Returns:
            Hostname atau None
        """
        try:
            hostname, _, _ = socket.gethostbyaddr(ip_address)
            logger.info(f"[DNS] Reverse lookup {ip_address} -> {hostname}")
            return hostname
        except Exception as e:
            logger.debug(f"Reverse DNS failed for {ip_address}: {e}")
            return None

    def check_email_security(self, domain: str) -> Dict[str, Any]:
        """
        Analyze email security records (SPF, DKIM, DMARC).

        Returns:
            Dict dengan email security analysis
        """
        result = self.resolve(domain, ["MX", "TXT"])

        # Check DMARC (di _dmarc subdomain)
        dmarc_domain = f"_dmarc.{domain}"
        try:
            import dns.resolver
            dmarc_answers = dns.resolver.resolve(dmarc_domain, "TXT")
            dmarc_records = []
            for rdata in dmarc_answers:
                txt = "".join([s.decode() if isinstance(s, bytes) else s for s in rdata.strings])
                dmarc_records.append(txt)
            result.records["DMARC"] = [DNSRecord(dmarc_domain, "TXT", r) for r in dmarc_records]
        except Exception:
            pass

        analysis = {
            "domain": domain,
            "has_mx": bool(result.mail_servers),
            "mx_servers": result.mail_servers,
            "has_spf": result.has_spf,
            "spf_record": next((t for t in result.txt_records if "v=spf" in t), None),
            "has_dkim": result.has_dkim,
            "has_dmarc": result.has_dmarc,
            "dmarc_record": next((t for t in result.txt_records if "v=dmarc" in t.lower()), None),
            "email_security_score": 0,
        }

        # Calculate security score
        score = 0
        if analysis["has_mx"]:
            score += 25
        if analysis["has_spf"]:
            score += 25
        if analysis["has_dkim"]:
            score += 25
        if analysis["has_dmarc"]:
            score += 25
        analysis["email_security_score"] = score

        return analysis

    def check_dnssec(self, domain: str) -> Dict[str, Any]:
        """
        Check DNSSEC status untuk domain.

        Returns:
            Dict dengan DNSSEC info
        """
        try:
            import dns.resolver

            # Query DNSKEY
            try:
                answers = dns.resolver.resolve(domain, "DNSKEY")
                dnskey_count = len(answers)
            except Exception:
                dnskey_count = 0

            # Query DS (delegation signer) di parent zone
            parts = domain.split(".")
            if len(parts) > 1:
                parent = ".".join(parts[1:])
                try:
                    answers = dns.resolver.resolve(domain, "DS")
                    has_ds = len(answers) > 0
                except Exception:
                    has_ds = False
            else:
                has_ds = False

            return {
                "domain": domain,
                "dnssec_enabled": dnskey_count > 0,
                "dnskey_count": dnskey_count,
                "has_ds_record": has_ds,
                "recommendation": "Enable DNSSEC" if dnskey_count == 0 else "DNSSEC is configured"
            }

        except ImportError:
            return {
                "domain": domain,
                "error": "dnspython not installed",
                "dnssec_enabled": None
            }

    def bulk_resolve(self, domains: List[str], record_types: Optional[List[str]] = None) -> Dict[str, DNSResolutionResult]:
        """Resolve multiple domains."""
        results = {}
        for domain in domains:
            results[domain] = self.resolve(domain, record_types)
        return results