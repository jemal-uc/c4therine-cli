"""
Subdomain Enumerator v1.0
Subdomain discovery via:
1. Certificate Transparency logs (crt.sh)
2. Wordlist brute-force
3. DNS permutation/alteration
4. API integration (VirusTotal, SecurityTrails - V3)

Output: discovered subdomains dengan DNS resolution.
"""

import re
import json
import logging
from typing import List, Dict, Optional, Set, Tuple, Any
from dataclasses import dataclass, field, asdict
from pathlib import Path

from .crtsh_client import CrtShClient
from .dns_resolver import DNSResolver

logger = logging.getLogger("osint.subdomain")


@dataclass
class SubdomainResult:
    """Single subdomain discovery result."""
    subdomain: str
    source: str  # "crtsh", "wordlist", "permutation", "api"
    is_resolvable: bool = False
    ip_addresses: List[str] = field(default_factory=list)
    record_types: List[str] = field(default_factory=list)
    http_status: Optional[int] = None
    http_title: Optional[str] = None
    technologies: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


class SubdomainEnumerator:
    """
    Subdomain enumeration engine.
    Combines multiple discovery methods untuk comprehensive coverage.
    """

    # Default wordlist - common subdomain prefixes
    DEFAULT_WORDLIST = [
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
        "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "ns3", "m", "imap",
        "test", "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn",
        "ns4", "www1", "imap4", "smtp3", "login", "shop", "ftp2", "mysql", "search",
        "api", "test2", "monitor", "web2", "mx", "docs", "cdn", "images", "css",
        "js", "static", "media", "assets", "img", "staging", "www3", "www4", "www5",
        "video", "audio", "download", "downloads", "app", "apps", "mobile", "mobi",
        "wap", "sms", "git", "svn", "cvs", "webdav", "web", "old", "new", "beta",
        "alpha", "demo", "secure", "support", "help", "kb", "wiki", "portal",
        "intranet", "extranet", "remote", "host", "server", "client", "proxy",
        "firewall", "router", "switch", "gateway", "dns", "dhcp", "ntp", "ldap",
        "ad", "dc", "exchange", "sharepoint", "teams", "onedrive", "office",
        "owa", "autodiscover", "lync", "skype", "sip", "xmpp", "jabber",
        "jenkins", "gitlab", "github", "bitbucket", "jira", "confluence",
        "nagios", "zabbix", "cacti", "munin", "grafana", "prometheus",
        "kibana", "elasticsearch", "logstash", "redis", "memcached", "mongo",
        "postgres", "mysql", "mariadb", "oracle", "mssql", "db", "database",
        "backup", "backups", "archive", "archives", "storage", "s3", "bucket",
        "cloud", "azure", "aws", "gcp", "heroku", "vercel", "netlify",
        "staging", "production", "prod", "live", "www-dev", "www-test",
        "dev-api", "api-dev", "api-test", "api-staging", "api-prod",
        "graphql", "rest", "soap", "rpc", "grpc", "websocket", "socket",
        "ws", "wss", "sse", "events", "pubsub", "queue", "mq", "rabbitmq",
        "kafka", "zookeeper", "etcd", "consul", "vault", "nomad", "terraform",
        "ansible", "puppet", "chef", "salt", "vagrant", "docker", "kubernetes",
        "k8s", "openshift", "rancher", "swarm", "compose", "registry",
        "harbor", "nexus", "artifactory", "sonar", "nexus", "maven",
        "npm", "pypi", "rubygems", "composer", "nuget", "chocolatey",
        "brew", "apt", "yum", "dnf", "pacman", "apk", "portage",
        "cp", "controlpanel", "panel", "pma", "phpmyadmin", "adminer",
        "dbadmin", "sql", "phpinfo", "info", "status", "health", "ping",
        "metrics", "stats", "analytics", "tracking", "pixel", "beacon",
        "tag", "gtm", "ga", "analytics", "segment", "mixpanel", "amplitude",
        "sentry", "bugsnag", "rollbar", "airbrake", "honeybadger",
        "newrelic", "datadog", "dynatrace", "appdynamics", "splunk",
        "sumologic", "elk", "elastic", "apm", "tracing", "jaeger",
        "zipkin", "opencensus", "opentelemetry", "otel", "otelcol",
        "collector", "agent", "daemon", "service", "worker", "cron",
        "scheduler", "job", "task", "pipeline", "workflow", "orchestrator",
        "controller", "manager", "master", "slave", "replica", "primary",
        "secondary", "standby", "failover", "cluster", "node", "pod",
        "container", "vm", "instance", "host", "baremetal", "metal",
        "edge", "cdn", "cache", "proxy", "lb", "loadbalancer", "balancer",
        "ingress", "egress", "gateway", "api-gateway", "apigw", "gw",
        "router", "switch", "hub", "bridge", "repeater", "modem",
        "firewall", "ids", "ips", "waf", "siem", "soc", "noc",
        "helpdesk", "ticketing", "itsm", "servicedesk", "sd",
        "chat", "livechat", "chatbot", "bot", "ai", "ml", "nlp",
        "ocr", "cv", "vision", "speech", "voice", "tts", "asr",
        "translate", "translation", "localization", "l10n", "i18n",
        "access", "sso", "oauth", "oidc", "saml", "ldap", "adfs",
        "okta", "auth0", "onelogin", "ping", "keycloak", "cas",
        "shibboleth", "simplesaml", "phpsaml", "miniorange",
        "mfa", "2fa", "totp", "hotp", "u2f", "webauthn", "fido",
        "password", "pass", "pwd", "secret", "token", "key", "cert",
        "certificate", "ca", "pki", "tls", "ssl", "https", "http",
        "ftp", "sftp", "ftps", "scp", "rsync", "nfs", "smb", "cifs",
        "afp", "webdav", "dav", "caldav", "carddav", "imap", "imaps",
        "pop3", "pop3s", "smtp", "smtps", "submission", "submit",
        "mx", "mx1", "mx2", "mx3", "mxbackup", "backupmx", "mail1",
        "mail2", "mail3", "email", "e-mail", "webmail", "webmail2",
        "owa", "outlook", "exchange", "ex", "exch", "exmail",
        "gmail", "googlemail", "yahoo", "ymail", "hotmail", "live",
        "msn", "aol", "icloud", "me", "mac", "fastmail", "proton",
        "tutanota", "startmail", "runbox", "mailbox", "posteo",
        "kolab", "zimbra", "roundcube", "squirrelmail", "horde",
        "atmail", "openxchange", "ox", "kopano", "zarafa", "mailcow",
        "mailinabox", "mailu", "modoboa", "iredmail", "poste",
        "docker-mailserver", "mailserver", "mta", "msa", "mda",
        "dovecot", "courier", "cyrus", "uw-imap", "z-push", "activesync",
        "eas", "mapi", "rpc", "rpc-over-http", "rpc-http", "ncacn",
        "ncalrpc", "ncacn-ip-tcp", "ncadg-ip-udp", "ncacn-spx",
        "ncacn-nb-tcp", "ncacn-nb-ipx", "ncacn-nb-nb", "ncacn-at-dsp",
        "ncacn-vns-spp", "ncacn-osi-dna", "ncadg-at-dsp", "ncadg-ipx",
        "ncadg-spx", "ncalrpc", "ncacn-http", "ncacn-px", "ncacn-ip",
        "ncacn-np", "ncacn-netbios", "ncacn-vns-sna", "ncacn-at-novell",
        "ncacn-dnet-nsp", "ncacn-osi-llc", "ncacn-osi- snap",
        "ncacn-osi-tp4", "ncacn-osi-clns", "ncacn-osi-tp", "ncacn-osi",
        "ncacn-dll", "ncacn-lrpc", "ncacn-ixs", "ncacn-spx", "ncacn-ipx",
        "ncacn-nb-ipx", "ncacn-at-novell", "ncacn-vns-sna", "ncacn-dnet-nsp",
    ]

    # Permutation patterns untuk subdomain alteration
    PERMUTATION_SEPARATORS = ["-", "_", ""]
    PERMUTATION_PREFIXES = ["dev", "test", "staging", "prod", "api", "app", "web"]
    PERMUTATION_SUFFIXES = ["1", "2", "3", "01", "02", "03", "v1", "v2", "v3"]

    def __init__(
        self,
        wordlist: Optional[List[str]] = None,
        threads: int = 20,
        timeout: int = 5,
        resolve_dns: bool = True,
        check_http: bool = False
    ):
        """
        Initialize subdomain enumerator.

        Args:
            wordlist: Custom wordlist (None = default)
            threads: Concurrent threads
            timeout: Request timeout
            resolve_dns: Resolve DNS untuk discovered subdomains
            check_http: Check HTTP status untuk discovered subdomains
        """
        self.wordlist = wordlist or self.DEFAULT_WORDLIST
        self.threads = threads
        self.timeout = timeout
        self.resolve_dns = resolve_dns
        self.check_http = check_http

        self.crtsh = CrtShClient(timeout=timeout)
        self.dns = DNSResolver(timeout=timeout)

        self.discovered: Set[str] = set()
        self.results: List[SubdomainResult] = []

    def enumerate(
        self,
        domain: str,
        methods: Optional[List[str]] = None,
        max_results: Optional[int] = None
    ) -> List[SubdomainResult]:
        """
        Run full subdomain enumeration.

        Args:
            domain: Target domain (e.g., "example.com")
            methods: List of methods ["crtsh", "wordlist", "permutation"]
            max_results: Limit results

        Returns:
            List of SubdomainResult objects
        """
        if methods is None:
            methods = ["crtsh", "wordlist", "permutation"]

        logger.info(f"[Subdomain] Starting enumeration for: {domain}")
        logger.info(f"[Subdomain] Methods: {methods}")

        self.discovered.clear()
        self.results.clear()

        # Method 1: Certificate Transparency
        if "crtsh" in methods:
            self._enumerate_crtsh(domain)

        # Method 2: Wordlist brute-force
        if "wordlist" in methods:
            self._enumerate_wordlist(domain)

        # Method 3: Permutation/alteration
        if "permutation" in methods:
            self._enumerate_permutation(domain)

        # Resolve dan enrich results
        if self.resolve_dns:
            self._resolve_all(domain)

        # Sort by subdomain name
        self.results.sort(key=lambda x: x.subdomain)

        if max_results:
            self.results = self.results[:max_results]

        logger.info(f"[Subdomain] Found {len(self.results)} unique subdomains for {domain}")
        return self.results

    def _enumerate_crtsh(self, domain: str) -> None:
        """Enumerate via crt.sh Certificate Transparency logs."""
        logger.info(f"[Subdomain] Checking crt.sh...")

        try:
            subdomains = self.crtsh.get_subdomains(domain, wildcard=False)

            for sub in subdomains:
                if sub not in self.discovered:
                    self.discovered.add(sub)
                    self.results.append(SubdomainResult(
                        subdomain=sub,
                        source="crtsh"
                    ))

            logger.info(f"[Subdomain] crt.sh found {len(subdomains)} subdomains")
        except Exception as e:
            logger.error(f"[Subdomain] crt.sh error: {e}")

    def _enumerate_wordlist(self, domain: str) -> None:
        """Enumerate via wordlist brute-force."""
        logger.info(f"[Subdomain] Running wordlist ({len(self.wordlist)} entries)...")

        import concurrent.futures
        import socket

        def check_subdomain(word: str) -> Optional[str]:
            subdomain = f"{word}.{domain}"
            try:
                socket.gethostbyname(subdomain)
                return subdomain
            except socket.gaierror:
                return None

        found = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(check_subdomain, word): word for word in self.wordlist}

            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result and result not in self.discovered:
                    self.discovered.add(result)
                    self.results.append(SubdomainResult(
                        subdomain=result,
                        source="wordlist",
                        is_resolvable=True
                    ))
                    found += 1

        logger.info(f"[Subdomain] Wordlist found {found} subdomains")

    def _enumerate_permutation(self, domain: str) -> None:
        """Enumerate via subdomain permutation/alteration."""
        logger.info(f"[Subdomain] Running permutation...")

        import concurrent.futures
        import socket

        permutations: Set[str] = set()

        # Generate permutations dari discovered subdomains
        base_subs = [s.split(".")[0] for s in self.discovered if s.endswith(domain)]
        if not base_subs:
            base_subs = ["www", "mail", "ftp", "admin", "api"]

        for base in base_subs:
            for sep in self.PERMUTATION_SEPARATORS:
                for prefix in self.PERMUTATION_PREFIXES:
                    permutations.add(f"{prefix}{sep}{base}")
                    permutations.add(f"{base}{sep}{prefix}")
                for suffix in self.PERMUTATION_SUFFIXES:
                    permutations.add(f"{base}{sep}{suffix}")
                    permutations.add(f"{suffix}{sep}{base}")

        def check_subdomain(word: str) -> Optional[str]:
            subdomain = f"{word}.{domain}"
            try:
                socket.gethostbyname(subdomain)
                return subdomain
            except socket.gaierror:
                return None

        found = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(check_subdomain, word): word for word in permutations}

            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result and result not in self.discovered:
                    self.discovered.add(result)
                    self.results.append(SubdomainResult(
                        subdomain=result,
                        source="permutation",
                        is_resolvable=True
                    ))
                    found += 1

        logger.info(f"[Subdomain] Permutation found {found} subdomains")

    def _resolve_all(self, domain: str) -> None:
        """Resolve DNS untuk semua discovered subdomains."""
        logger.info(f"[Subdomain] Resolving DNS for {len(self.results)} subdomains...")

        for result in self.results:
            try:
                dns_result = self.dns.resolve(result.subdomain, ["A", "AAAA", "CNAME"])

                if dns_result.has_records:
                    result.is_resolvable = True
                    result.ip_addresses = dns_result.ip_addresses
                    result.record_types = list(dns_result.records.keys())

            except Exception as e:
                logger.debug(f"DNS resolve failed for {result.subdomain}: {e}")

    def get_live_subdomains(self) -> List[SubdomainResult]:
        """Get only resolvable subdomains."""
        return [r for r in self.results if r.is_resolvable]

    def get_by_source(self, source: str) -> List[SubdomainResult]:
        """Get subdomains dari specific source."""
        return [r for r in self.results if r.source == source]

    def export_results(self, filepath: str, format: str = "json") -> str:
        """Export results ke file."""
        if format == "json":
            data = {
                "total_discovered": len(self.results),
                "resolvable": len(self.get_live_subdomains()),
                "by_source": {
                    source: len(self.get_by_source(source))
                    for source in set(r.source for r in self.results)
                },
                "subdomains": [r.to_dict() for r in self.results]
            }
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

        elif format == "txt":
            with open(filepath, "w", encoding="utf-8") as f:
                for r in self.results:
                    f.write(f"{r.subdomain}\n")

        elif format == "csv":
            import csv
            with open(filepath, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Subdomain", "Source", "Resolvable", "IPs", "Record Types"])
                for r in self.results:
                    writer.writerow([
                        r.subdomain, r.source, r.is_resolvable,
                        ", ".join(r.ip_addresses),
                        ", ".join(r.record_types)
                    ])

        logger.info(f"[Subdomain] Exported to {filepath}")
        return filepath

    def load_wordlist(self, filepath: str) -> None:
        """Load custom wordlist dari file."""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                self.wordlist = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            logger.info(f"[Subdomain] Loaded {len(self.wordlist)} words from {filepath}")
        except Exception as e:
            logger.error(f"Failed to load wordlist: {e}")