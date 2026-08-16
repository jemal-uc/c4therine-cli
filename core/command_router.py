import sys
import os
import time
import csv
import re
from core.memory import MemoryManager
from core.usage_tracker import UsageTracker
from core.ai_engine import AIEngine
from core.tool_registry import ToolRegistry

# ================================================================
# [REVISI OSINT] Catherine V4 Imports
# ================================================================
try:
    import asyncio
    from typing import Dict, Any, List, Optional
    from tools.osint.intelligence_orchestrator import (
        IntelligenceOrchestrator,
        OrchestratorConfig,
        OrchestratorMode,
        SourceMetadata,
    )
    from tools.osint.reporting.report_generator import (
        ReportGenerator,
        ReportRequest,
        ReportFormat,
        ReportType,
    )
    CATHERINE_V4_AVAILABLE = True
except ImportError as e:
    CATHERINE_V4_AVAILABLE = False
    CATHERINE_V4_ERROR = str(e)

# Fallback legacy OSINT
try:
    from tools.osint.osint_engine import AdvancedOSINTLookup
    OSINT_LEGACY_AVAILABLE = True
except ImportError:
    OSINT_LEGACY_AVAILABLE = False


class CommandRouter:
    def __init__(self, memory: MemoryManager, tracker: UsageTracker, engine: AIEngine, registry: ToolRegistry):
        self.memory = memory
        self.tracker = tracker
        self.engine = engine
        self.registry = registry
        self.version = "v0.0.1"

        # ================================================================
        # [REVISI OSINT] Inisialisasi Catherine V4 Orchestrator
        # ================================================================
        self._osint_orchestrator: Optional[Any] = None
        self._last_intelligence_product: Optional[Any] = None
        self._register_osint_v4()

    # ================================================================
    # [REVISI OSINT] V4 Orchestrator Setup
    # ================================================================
    def _register_osint_v4(self) -> None:
        """Register Catherine V4 OSINT engine ke registry."""
        if not CATHERINE_V4_AVAILABLE:
            return

        try:
            orch_config = OrchestratorConfig(
                mode=OrchestratorMode.HYBRID,
                enable_anomaly_detection=True,
                enable_hypothesis_generation=True,
                enable_auto_report=True,
                max_concurrent_pipelines=3,
            )
            self._osint_orchestrator = IntelligenceOrchestrator(config=orch_config)
            self._osint_orchestrator.initialize()
            self.registry.register("osint_v4", self._osint_orchestrator)
        except Exception as e:
            print(f"\033[93m[OSINT V4] Initialization warning: {e}\033[0m")

    # ================================================================
    # [REVISI OSINT] Helper Methods
    # ================================================================
    def _get_osint_engine(self):
        """Get OSINT engine dari registry (legacy atau V4)."""
        if self._osint_orchestrator is not None:
            return self._osint_orchestrator
        return self.registry.get("osint")

    def _run_async(self, coro):
        """Helper untuk run async function dari sync context."""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    future = pool.submit(asyncio.run, coro)
                    return future.result()
            return loop.run_until_complete(coro)
        except RuntimeError:
            return asyncio.run(coro)

    # ================================================================
    # [REVISI OSINT] V4 Command Handlers
    # ================================================================
    def _cmd_osint_v4_ingest(self, args: list) -> str:
        """Ingest data ke Catherine V4 pipeline."""
        if not CATHERINE_V4_AVAILABLE or self._osint_orchestrator is None:
            return "[ERROR] Catherine V4 not available. Using legacy OSINT."

        if not args:
            return (
                "[ERROR] Syntax salah.\n"
                "Format: /osint-ingest <data_json> [--source <name>] [--type <type>]\n"
                "Contoh: /osint-ingest '{\"ip\":\"1.2.3.4\"}' --source shodan"
            )

        data_str = args[0]
        source_name = "cli_manual"
        source_type = "manual"

        if "--source" in args:
            idx = args.index("--source")
            if idx + 1 < len(args):
                source_name = args[idx + 1]
        if "--type" in args:
            idx = args.index("--type")
            if idx + 1 < len(args):
                source_type = args[idx + 1]

        try:
            import json
            data_content = json.loads(data_str) if data_str.startswith("{") else {"raw": data_str}

            metadata = SourceMetadata(
                source_id=f"cli_{int(time.time())}",
                source_type=source_type,
                source_name=source_name,
            )

            data_obj = self._run_async(
                self._osint_orchestrator.ingest_data(data_content, metadata)
            )

            return (
                f"✅ Data ingested ke Catherine V4\n"
                f"  Data ID : {data_obj.data_id}\n"
                f"  Checksum: {data_obj.checksum}\n"
                f"  Source  : {source_name} ({source_type})\n"
                f"\nNext: Run /osint-pipeline untuk analisis"
            )

        except json.JSONDecodeError:
            return "[ERROR] Invalid JSON data. Pastikan data dalam format JSON valid."
        except Exception as e:
            return f"[ERROR] Ingest failed: {str(e)}"

    def _cmd_osint_v4_pipeline(self, args: list) -> str:
        """Run full intelligence pipeline (Catherine V4)."""
        if not CATHERINE_V4_AVAILABLE or self._osint_orchestrator is None:
            return "[ERROR] Catherine V4 not available."

        if not args:
            return (
                "[ERROR] Syntax salah.\n"
                "Format: /osint-pipeline <target> [--case-id <id>]\n"
                "Contoh: /osint-pipeline evil.com --case-id CASE-001"
            )

        target = args[0]
        case_id = f"CLI-{int(time.time())}"

        if "--case-id" in args:
            idx = args.index("--case-id")
            if idx + 1 < len(args):
                case_id = args[idx + 1]

        try:
            metadata = SourceMetadata(
                source_id=f"cli_{int(time.time())}",
                source_type="cli",
                source_name="Catherine CLI",
            )

            print(f"\033[92m[SYSTEM] Ingesting target: {target}...\033[0m")
            data_obj = self._run_async(
                self._osint_orchestrator.ingest_data({"target": target}, metadata)
            )

            print(f"\033[92m[SYSTEM] Running intelligence pipeline (Case: {case_id})...\033[0m")
            product = self._run_async(
                self._osint_orchestrator.run_pipeline(data_obj, case_id=case_id)
            )

            self._last_intelligence_product = product

            summary = [
                f"\n{'='*60}",
                f"🎯 INTELLIGENCE PIPELINE COMPLETE",
                f"\n{'='*60}",
                f"  Case ID      : {product.case_id}",
                f"  Product ID   : {product.product_id}",
                f"  Entities     : {len(product.entities)}",
                f"  Relationships: {len(product.relationships)}",
                f"  Anomalies    : {len(product.anomalies)}",
                f"  Hypotheses   : {len(product.hypotheses)}",
            ]

            if product.confidence_scores:
                overall = product.confidence_scores.get('overall_confidence', 'N/A')
                summary.append(f"  Confidence   : {overall}")

            if product.export_paths:
                summary.append(f"\n  Exports:")
                for fmt, path in product.export_paths.items():
                    summary.append(f"    • {fmt}: {path}")

            summary.extend([
                f"\n{'='*60}",
                f"Commands selanjutnya:",
                f"  /osint-report      → Generate narrative report",
                f"  /osint-visualize   → Generate graph visualization",
                f"  /osint-export      → Export ke berbagai format",
                f"  /osint-query       → Query entities dari graph",
                f"\n{'='*60}"
            ])

            return "\n".join(summary)

        except Exception as e:
            return f"[ERROR] Pipeline failed: {str(e)}"

    def _cmd_osint_v4_report(self, args: list) -> str:
        """Generate narrative report dari last product."""
        if not CATHERINE_V4_AVAILABLE:
            return "[ERROR] Catherine V4 not available."

        if self._last_intelligence_product is None:
            return (
                "[ERROR] Tidak ada intelligence product.\n"
                "Jalankan /osint-pipeline terlebih dahulu."
            )

        try:
            formats = ["markdown"]
            if args:
                formats = [f.strip() for f in args[0].split(",")]

            format_enums = []
            for f in formats:
                try:
                    format_enums.append(ReportFormat(f.lower()))
                except ValueError:
                    return f"[ERROR] Format tidak dikenal: {f}. Gunakan: markdown, html, json, csv, stix, misp"

            result = self._run_async(
                self._async_generate_report(format_enums)
            )

            if result.success:
                lines = [f"📄 Reports generated ({len(result.generated_files)} format):"]
                for fmt, path in result.generated_files.items():
                    lines.append(f"  • {fmt.value}: {path}")
                return "\n".join(lines)
            else:
                errors = "\n".join(result.errors)
                return f"[ERROR] Report generation failed:\n{errors}"

        except Exception as e:
            return f"[ERROR] Report failed: {str(e)}"

    async def _async_generate_report(self, formats: list) -> Any:
        """Async wrapper untuk report generation."""
        request = ReportRequest(
            product=self._last_intelligence_product.to_dict(),
            formats=formats,
            output_dir="./storage/reports",
            filename_prefix=f"report_{self._last_intelligence_product.case_id}",
        )
        generator = ReportGenerator()
        return generator.generate(request)

    def _cmd_osint_v4_visualize(self, args: list) -> str:
        """Generate graph visualization."""
        if not CATHERINE_V4_AVAILABLE or self._osint_orchestrator is None:
            return "[ERROR] Catherine V4 not available."

        try:
            output_path = args[0] if args else f"./storage/reports/graph_{int(time.time())}.html"
            viz_path = self._osint_orchestrator.visualize_graph(output_path=output_path)

            return (
                f"📊 Graph visualization generated\n"
                f"  Path: {viz_path}\n"
                f"\nBuka file di browser untuk melihat interactive graph."
            )

        except Exception as e:
            return f"[ERROR] Visualization failed: {str(e)}"

    def _cmd_osint_v4_query(self, args: list) -> str:
        """Query entities dari graph database."""
        if not CATHERINE_V4_AVAILABLE or self._osint_orchestrator is None:
            return "[ERROR] Catherine V4 not available."

        if not args:
            return (
                "[ERROR] Syntax salah.\n"
                "Format: /osint-query <entity_type> [property=value ...]\n"
                "Contoh: /osint-query person name=John\n"
                "        /osint-query * (semua entity)"
            )

        entity_type = args[0]
        properties = {}

        for arg in args[1:]:
            if "=" in arg:
                k, v = arg.split("=", 1)
                properties[k] = v

        try:
            entities = self._osint_orchestrator.query_entities(
                entity_type=entity_type if entity_type != "*" else None,
                properties=properties if properties else None,
                limit=50,
            )

            if not entities:
                return f"❌ No entities found for type: {entity_type}"

            lines = [f"🔍 Found {len(entities)} entities:"]
            for e in entities[:15]:
                name = e.get("name", e.get("label", "Unnamed"))
                eid = e.get("id", "N/A")
                etype = e.get("type", "unknown")
                lines.append(f"  • [{etype}] {name} (ID: {eid})")

            if len(entities) > 15:
                lines.append(f"  ... and {len(entities) - 15} more")

            return "\n".join(lines)

        except Exception as e:
            return f"[ERROR] Query failed: {str(e)}"

    def _cmd_osint_v4_export(self, args: list) -> str:
        """Export last intelligence product."""
        if not CATHERINE_V4_AVAILABLE:
            return "[ERROR] Catherine V4 not available."

        if self._last_intelligence_product is None:
            return (
                "[ERROR] Tidak ada intelligence product.\n"
                "Jalankan /osint-pipeline terlebih dahulu."
            )

        fmt = args[0] if args else "json"
        output_path = args[1] if len(args) > 1 else None

        try:
            try:
                fmt_enum = ReportFormat(fmt.lower())
            except ValueError:
                return f"[ERROR] Format tidak dikenal: {fmt}. Gunakan: json, html, csv, markdown, stix, misp, maltego"

            result = self._run_async(
                self._async_export(fmt_enum, output_path)
            )

            return f"📤 Exported to: {result}"

        except Exception as e:
            return f"[ERROR] Export failed: {str(e)}"

    async def _async_export(self, fmt: Any, output_path: Optional[str]) -> str:
        """Async wrapper untuk export."""
        from tools.osint.reporting.report_generator import quick_export
        return quick_export(
            product=self._last_intelligence_product.to_dict(),
            fmt=fmt.value,
            output_path=output_path,
        )

    def _cmd_osint_v4_status(self, args: list) -> str:
        """Get orchestrator status."""
        if not CATHERINE_V4_AVAILABLE or self._osint_orchestrator is None:
            return "[ERROR] Catherine V4 not available."

        try:
            status = self._osint_orchestrator.get_status()
            lines = ["🛡️ Catherine V4 Status:"]

            for k, v in status.items():
                if isinstance(v, dict):
                    lines.append(f"  {k}:")
                    for sk, sv in v.items():
                        icon = "✅" if sv else "❌"
                        lines.append(f"    {icon} {sk}")
                else:
                    lines.append(f"  {k}: {v}")

            return "\n".join(lines)

        except Exception as e:
            return f"[ERROR] Status check failed: {str(e)}"

    def _cmd_osint_v4_stats(self, args: list) -> str:
        """Get pipeline statistics."""
        if not CATHERINE_V4_AVAILABLE or self._osint_orchestrator is None:
            return "[ERROR] Catherine V4 not available."

        try:
            stats = self._osint_orchestrator.get_statistics()
            lines = ["📊 Pipeline Statistics:"]

            for k, v in stats.items():
                lines.append(f"  {k}: {v}")

            return "\n".join(lines)

        except Exception as e:
            return f"[ERROR] Stats failed: {str(e)}"

    # ================================================================
    # [REVISI OSINT] Domain Recon Commands
    # ================================================================
    def _cmd_domain_recon(self, args: list) -> str:
        """Full domain reconnaissance."""
        if not args:
            return (
                "[ERROR] Syntax salah.\n"
                "Format: /domain-recon <domain>\n"
                "Contoh: /domain-recon example.com"
            )

        domain = args[0]
        results = []

        try:
            # DNS Lookup
            try:
                from tools.osint.domain.dns_resolver import DNSResolver, DNSRecordType
                resolver = DNSResolver()
                dns_results = resolver.resolve(domain)
                results.append(f"🌐 DNS Records:\n{dns_results}")
            except Exception as e:
                results.append(f"🌐 DNS: {e}")

            # WHOIS
            try:
                from tools.osint.domain.whois_client import WhoisClient, WhoisRecord
                client = WhoisClient()
                whois_result = client.lookup(domain)
                results.append(f"📋 WHOIS:\n{whois_result}")
            except Exception as e:
                results.append(f"📋 WHOIS: {e}")

            # Subdomain Enum
            try:
                from tools.osint.domain.subdomain_enum import SubdomainEnumerator, SubdomainResult
                enumerator = SubdomainEnumerator()
                subdomains = enumerator.enumerate(domain)
                results.append(f"🔎 Subdomains ({len(subdomains)} found):\n" + "\n".join(f"  • {s}" for s in subdomains[:20]))
            except Exception as e:
                results.append(f"🔎 Subdomains: {e}")

            # Certificate Search
            try:
                from tools.osint.domain.crtsh_client import CrtShClient, CertificateRecord
                client = CrtShClient()
                certs = client.search(domain)
                results.append(f"🔒 Certificates ({len(certs)} found):\n" + "\n".join(f"  • {c}" for c in certs[:10]))
            except Exception as e:
                results.append(f"🔒 Certificates: {e}")

            return f"\n{'='*60}\n".join([
                f"🔍 DOMAIN RECON: {domain}",
                f"{'='*60}"
            ] + results)

        except Exception as e:
            return f"[ERROR] Domain recon failed: {str(e)}"

    def _cmd_dns_lookup(self, args: list) -> str:
        """DNS lookup."""
        if not args:
            return "[ERROR] Syntax: /dns-lookup <domain>"

        try:
            from tools.osint.domain.dns_resolver import DNSResolver, DNSRecordType
            resolver = DNSResolver()
            results = resolver.resolve(args[0])
            return f"🌐 DNS Results for {args[0]}:\n{results}"
        except Exception as e:
            return f"[ERROR] DNS lookup failed: {str(e)}"

    def _cmd_whois(self, args: list) -> str:
        """WHOIS lookup."""
        if not args:
            return "[ERROR] Syntax: /whois <domain>"

        try:
            from tools.osint.domain.whois_client import WhoisClient, WhoisRecord
            client = WhoisClient()
            result = client.lookup(args[0])
            return f"📋 WHOIS for {args[0]}:\n{result}"
        except Exception as e:
            return f"[ERROR] WHOIS failed: {str(e)}"

    def _cmd_subdomain_enum(self, args: list) -> str:
        """Subdomain enumeration."""
        if not args:
            return "[ERROR] Syntax: /subdomain <domain>"

        try:
            from tools.osint.domain.subdomain_enum import SubdomainEnumerator, SubdomainResult
            enumerator = SubdomainEnumerator()
            results = enumerator.enumerate(args[0])
            return f"🔎 Subdomains for {args[0]} ({len(results)} found):\n" + "\n".join(f"  • {r}" for r in results[:30])
        except Exception as e:
            return f"[ERROR] Subdomain enum failed: {str(e)}"

    def _cmd_cert_search(self, args: list) -> str:
        """Certificate transparency search."""
        if not args:
            return "[ERROR] Syntax: /cert-search <domain>"

        try:
            from tools.osint.domain.crtsh_client import CrtShClient, CertificateRecord
            client = CrtShClient()
            results = client.search(args[0])
            return f"🔒 Certificates for {args[0]} ({len(results)} found):\n" + "\n".join(f"  • {r}" for r in results[:20])
        except Exception as e:
            return f"[ERROR] Cert search failed: {str(e)}"

    # ================================================================
    # [REVISI OSINT] Identity Commands
    # ================================================================
    def _cmd_email_osint(self, args: list) -> str:
        """Email intelligence."""
        if not args:
            return "[ERROR] Syntax: /email-osint <email>"

        try:
            from tools.osint.identity.email_intelligence import EmailIntelligence, EmailProfile
            intel = EmailIntelligence()
            result = intel.investigate(args[0])
            return f"📧 Email OSINT for {args[0]}:\n{result}"
        except Exception as e:
            return f"[ERROR] Email OSINT failed: {str(e)}"

    def _cmd_username_osint(self, args: list) -> str:
        """Username correlation."""
        if not args:
            return "[ERROR] Syntax: /username-osint <username>"

        try:
            from tools.osint.identity.username_correlator import UsernameCorrelator, UsernameProfile
            correlator = UsernameCorrelator()
            profiles = correlator.correlate(args[0])
            if not profiles:
                return f"👤 Username correlation for {args[0]}:\nNo profiles found on any platform."
            
            lines = [
                f"╔══════════════════════════════════════════════════════════════╗",
                f"║                 USERNAME CORRELATION REPORT                  ║",
                f"╠══════════════════════════════════════════════════════════════╣",
                f"  Target Username: {args[0]}",
                f"  Matches Found  : {len(profiles)}",
                f"================================================================",
            ]
            for i, p in enumerate(profiles, 1):
                lines.append(f"  [{i}] {p.platform.upper()}: {p.url} (Confidence: {p.confidence}%)")
                if p.profile_data.get("page_title"):
                    lines.append(f"      Title: {p.profile_data['page_title']}")
            
            lines.append("╚══════════════════════════════════════════════════════════════╝")
            return "\n".join(lines)
        except Exception as e:
            return f"[ERROR] Username OSINT failed: {str(e)}"

    def _cmd_face_search(self, args: list) -> str:
        """Face correlation search."""
        if not args:
            return "[ERROR] Syntax: /face-search <image_path_or_url>\nContoh: /face-search \"C:\\backup cath\\DJBH5183.JPG\""

        # Reconstruct path dari args (handle spasi di path)
        image_path = " ".join(args)
        
        # Remove quotes kalau ada
        image_path = image_path.strip('"').strip("'")

        try:
            from tools.osint.analysis.face_correlation import FaceCorrelationEngine, CorrelationResult
            engine = FaceCorrelationEngine()
            result = engine.correlate_faces(image_path, search_database=True, extract_metadata=True)

            lines = [
                f"🎭 Face Correlation Result",
                f"{'='*50}",
                f"Source Image : {result.query_image_path}",
                f"Faces Found  : {result.query_face_count}",
                f"Matches      : {len(result.matched_faces)}",
                f"Processing   : {result.processing_time:.2f}s",
                f"",
            ]

            if result.metadata:
                meta = result.metadata
                lines.extend([
                    f"📷 Metadata:",
                    f"  File    : {meta.filename}",
                    f"  Size    : {meta.dimensions[0]}x{meta.dimensions[1]}",
                    f"  Camera  : {meta.camera_info or 'Unknown'}",
                    f"  GPS     : {meta.gps_coordinates or 'Not available'}",
                    f"  Date    : {meta.capture_date or 'Unknown'}",
                    f"",
                ])

            if result.matched_faces:
                lines.append("🔍 Matches:")
                for i, match in enumerate(result.matched_faces[:5], 1):
                    lines.append(
                        f"  [{i}] {match.correlation_level.value.upper()} "
                        f"({match.similarity_score:.1%}) - "
                        f"{match.match_details.get('person_name', 'Unknown')}"
                    )
            else:
                lines.append("❌ No matches found in database.")

            return "\n".join(lines)

        except Exception as e:
            return f"[ERROR] Face search failed: {str(e)}"

    # ================================================================
    # [REVISI OSINT] Analysis Commands
    # ================================================================
    def _cmd_anomaly_check(self, args: list) -> str:
        """Run anomaly detection."""
        if not CATHERINE_V4_AVAILABLE or self._osint_orchestrator is None:
            return "[ERROR] Catherine V4 not available."

        try:
            from tools.osint.analysis.anomaly_detector import AnomalyDetector, AnomalyType, SeverityLevel
            detector = AnomalyDetector()
            # Anomaly detection memerlukan entities/relationships
            return "🔬 Anomaly detection requires ingested data. Use /osint-pipeline first."
        except Exception as e:
            return f"[ERROR] Anomaly check failed: {str(e)}"

    def _cmd_confidence_score(self, args: list) -> str:
        """Calculate confidence scores."""
        if not CATHERINE_V4_AVAILABLE or self._osint_orchestrator is None:
            return "[ERROR] Catherine V4 not available."

        try:
            from tools.osint.analysis.confidence_engine import ConfidenceEngine, SourceReliability
            engine = ConfidenceEngine()
            return "📊 Confidence scoring requires ingested data. Use /osint-pipeline first."
        except Exception as e:
            return f"[ERROR] Confidence score failed: {str(e)}"

    def _cmd_generate_hypothesis(self, args: list) -> str:
        """Generate hypotheses."""
        if not CATHERINE_V4_AVAILABLE or self._osint_orchestrator is None:
            return "[ERROR] Catherine V4 not available."

        try:
            from tools.osint.analysis.hypothesis_generator import HypothesisGenerator, Hypothesis
            generator = HypothesisGenerator()
            return "💡 Hypothesis generation requires ingested data. Use /osint-pipeline first."
        except Exception as e:
            return f"[ERROR] Hypothesis generation failed: {str(e)}"

    def _cmd_github_intelligence(self, args: list) -> str:
        """GitHub intelligence lookup."""
        if not args:
            return "[ERROR] Syntax: /github-intel <username>"

        try:
            from tools.osint.analysis.github_intelligence import GitHubIntelligence, GitHubProfile
            intel = GitHubIntelligence()
            result = intel.lookup(args[0])
            return f"🐙 GitHub Intelligence for {args[0]}:\n{result}"
        except Exception as e:
            return f"[ERROR] GitHub intelligence failed: {str(e)}"

    def _cmd_breach_check(self, args: list) -> str:
        """Breach intelligence check."""
        if not args:
            return "[ERROR] Syntax: /breach-check <email>"

        try:
            from tools.osint.analysis.breach_intelligence import BreachIntelligence, BreachRecord
            intel = BreachIntelligence()
            result = intel.check(args[0])
            return f"🔓 Breach Intelligence for {args[0]}:\n{result}"
        except Exception as e:
            return f"[ERROR] Breach check failed: {str(e)}"

    # ================================================================
    # [REVISI OSINT] Export Shortcuts
    # ================================================================
    def _cmd_export_csv(self, args: list) -> str:
        return self._cmd_osint_v4_export(["csv"] + args)

    def _cmd_export_html(self, args: list) -> str:
        return self._cmd_osint_v4_export(["html"] + args)

    def _cmd_export_json(self, args: list) -> str:
        return self._cmd_osint_v4_export(["json"] + args)

    def _cmd_export_stix(self, args: list) -> str:
        return self._cmd_osint_v4_export(["stix"] + args)

    def _cmd_export_misp(self, args: list) -> str:
        return self._cmd_osint_v4_export(["misp"] + args)

    def _cmd_export_maltego(self, args: list) -> str:
        return self._cmd_osint_v4_export(["maltego"] + args)

    def handle(self, command: str) -> str:
        parts = command.strip().split()
        if not parts:
            return "Invalid command. Type /help for hints."

        cmd = parts[0].lower()
        args = parts[1:]

        # ================================================================
        # [REVISI OSINT] OSINT V4 Commands
        # ================================================================

        # Catherine V4 Pipeline Commands
        if cmd == "/osint-ingest":
            return self._cmd_osint_v4_ingest(args)

        elif cmd == "/osint-pipeline":
            return self._cmd_osint_v4_pipeline(args)

        elif cmd == "/osint-report":
            return self._cmd_osint_v4_report(args)

        elif cmd == "/osint-visualize":
            return self._cmd_osint_v4_visualize(args)

        elif cmd == "/osint-query":
            return self._cmd_osint_v4_query(args)

        elif cmd == "/osint-export":
            return self._cmd_osint_v4_export(args)

        elif cmd == "/osint-status":
            return self._cmd_osint_v4_status(args)

        elif cmd == "/osint-stats":
            return self._cmd_osint_v4_stats(args)

        # Domain Recon Commands
        elif cmd == "/domain-recon":
            return self._cmd_domain_recon(args)

        elif cmd == "/dns-lookup":
            return self._cmd_dns_lookup(args)

        elif cmd == "/whois":
            return self._cmd_whois(args)

        elif cmd == "/subdomain":
            return self._cmd_subdomain_enum(args)

        elif cmd == "/cert-search":
            return self._cmd_cert_search(args)

        # Identity Commands
        elif cmd == "/email-osint":
            return self._cmd_email_osint(args)

        elif cmd == "/username-osint":
            return self._cmd_username_osint(args)

        elif cmd == "/face-search":
            return self._cmd_face_search(args)

        # Analysis Commands
        elif cmd == "/anomaly-check":
            return self._cmd_anomaly_check(args)

        elif cmd == "/confidence-score":
            return self._cmd_confidence_score(args)

        elif cmd == "/generate-hypothesis":
            return self._cmd_generate_hypothesis(args)

        elif cmd == "/github-intel":
            return self._cmd_github_intelligence(args)

        elif cmd == "/breach-check":
            return self._cmd_breach_check(args)

        # Export Shortcuts
        elif cmd == "/export-csv":
            return self._cmd_export_csv(args)

        elif cmd == "/export-html":
            return self._cmd_export_html(args)

        elif cmd == "/export-json":
            return self._cmd_export_json(args)

        elif cmd == "/export-stix":
            return self._cmd_export_stix(args)

        elif cmd == "/export-misp":
            return self._cmd_export_misp(args)

        elif cmd == "/export-maltego":
            return self._cmd_export_maltego(args)

        # ================================================================
        # [END REVISI OSINT]
        # ================================================================

        # ================================================================
        # /HELP
        # ================================================================
        if cmd == "/help":
            base_help = (
                "╔══════════════════════════════════════════════════════════════╗\n"
                "║              C4THERINE TERMINAL AI - COMMANDS                ║\n"
                "╠══════════════════════════════════════════════════════════════╣\n"
                "║  SYSTEM                                                      ║\n"
                "║    /help      - Menampilkan daftar command                   ║\n"
                "║    /history   - Menampilkan riwayat chat                     ║\n"
                "║    /save      - Simpan chat ke file                          ║\n"
                "║    /clear     - Bersihkan layar terminal                     ║\n"
                "║    /restart   - Reset session                                ║\n"
                "║    /status    - Status sistem + API                          ║\n"
                "║    /version   - Versi aplikasi                               ║\n"
                "║    /exit      - Keluar aplikasi                              ║\n"
                "║                                                              ║\n"
                "║  AI & USAGE                                                  ║\n"
                "║    /model     - Info model AI                                ║\n"
                "║    /usage     - Token & estimasi biaya                       ║\n"
                "║    /budget    - Lihat / set limit biaya                      ║\n"
                "║    /ping      - Test API latency                             ║\n"
                "║                                                              ║\n"
                "║  DATA EXTRACTION                                             ║\n"
                "║    /scraping  - Ekstrak data dari website                    ║\n"
                "║    /search    - Cari data dari web (Bing)                    ║\n"
                "║                                                              ║\n"
                "║  SECURITY                                                    ║\n"
                "║    /scan      - Security audit website                       ║\n"
                "║                                                              ║\n"
            )

            osint_help = (
                "║  OSINT - CATHERINE V4 INTELLIGENCE PLATFORM                  ║\n"
                "║    /osint           - Legacy OSINT lookup (nama)             ║\n"
                "║    /osint-ingest    - Ingest data ke pipeline                ║\n"
                "║    /osint-pipeline  - Run full intelligence pipeline         ║\n"
                "║    /osint-report    - Generate narrative report              ║\n"
                "║    /osint-visualize - Generate graph visualization           ║\n"
                "║    /osint-query     - Query entities dari graph              ║\n"
                "║    /osint-export    - Export product (json/html/csv/stix)    ║\n"
                "║    /osint-status    - Status orchestrator                    ║\n"
                "║    /osint-stats     - Pipeline statistics                    ║\n"
                "║                                                              ║\n"
                "║  OSINT - DOMAIN RECON                                        ║\n"
                "║    /domain-recon    - Full domain reconnaissance             ║\n"
                "║    /dns-lookup      - DNS resolution                         ║\n"
                "║    /whois           - WHOIS lookup                           ║\n"
                "║    /subdomain       - Subdomain enumeration                  ║\n"
                "║    /cert-search     - Certificate transparency search        ║\n"
                "║                                                              ║\n"
                "║  OSINT - IDENTITY                                            ║\n"
                "║    /email-osint     - Email intelligence                     ║\n"
                "║    /username-osint  - Username correlation                   ║\n"
                "║    /face-search     - Face correlation search                ║\n"
                "║                                                              ║\n"
                "║  OSINT - ANALYSIS                                            ║\n"
                "║    /anomaly-check   - Detect anomalies                       ║\n"
                "║    /confidence-score- Calculate confidence                   ║\n"
                "║    /generate-hypothesis - Generate hypotheses                ║\n"
                "║    /github-intel    - GitHub intelligence                    ║\n"
                "║    /breach-check    - Breach intelligence check              ║\n"
                "║                                                              ║\n"
                "║  OSINT - EXPORT SHORTCUTS                                    ║\n"
                "║    /export-csv      - Export to CSV                          ║\n"
                "║    /export-html     - Export to HTML                         ║\n"
                "║    /export-json     - Export to JSON                         ║\n"
                "║    /export-stix     - Export to STIX 2.1                     ║\n"
                "║    /export-misp     - Export to MISP                         ║\n"
                "║    /export-maltego  - Export to Maltego                      ║\n"
                "║                                                              ║\n"
            )

            end_help = (
                "║  INFO                                                        ║\n"
                "║    /about     - Info aplikasi                                ║\n"
                "╚══════════════════════════════════════════════════════════════╝\n\n"
                "Usage Examples:\n"
                "  /scraping https://news.yahoo.com/ h3 100\n"
                "  /search pembubaran ibadah 50\n"
                "  /osint Ahmad Syaifudin Hostama\n"
                "  /osint-pipeline evil.com --case-id CASE-001\n"
                "  /domain-recon example.com\n"
                "  /face-search ./photo.jpg\n"
                "  /github-intel johndoe\n"
                "  /breach-check email@example.com\n"
                "  /export-html\n"
                "  /budget 10.00"
            )

            return base_help + osint_help + end_help

        # ================================================================
        # /HISTORY
        # ================================================================
        elif cmd == "/history":
            history = self.memory.get_context()
            if not history:
                return "History empty."
            lines = []
            for msg in history:
                role = msg.get("role", "unknown").upper()
                content = msg.get("content", "")
                lines.append(f"[{role}] {content}")
            return "\n".join(lines)

        # ================================================================
        # /SAVE
        # ================================================================
        elif cmd == "/save":
            os.makedirs("storage/memory", exist_ok=True)
            with open("storage/memory/chat_history.txt", "w") as f:
                for msg in self.memory.get_context():
                    f.write(f"[{msg['role'].upper()}] {msg['content']}\n")
            return "Chat saved to storage/memory/chat_history.txt"

        elif cmd == "/profile":
            if len(parts) < 3:
                profile_data = self.memory.profile
                out = "[USER PROFILE]\n"
                for k, v in profile_data.items():
                    out += f"- {k.capitalize()}: {v}\n"
                out += "\nCara ubah: /profile set [key] [value]\nContoh: /profile set name Berto"
                return out

            subcmd = parts[1]
            if subcmd == "set":
                key = parts[2]
                value = " ".join(parts[3:])

                if key not in ["name", "profession", "preference"]:
                    return "Key tidak valid. Gunakan: name, profession, atau preference."

                self.memory.update_profile(key, value)
                return f"Profile '{key}' berhasil diubah menjadi: {value}"

            return "Syntax Error pada command /profile."

        # ================================================================
        # /CLEAR
        # ================================================================
        elif cmd == "/clear":
            os.system("cls" if os.name == "nt" else "clear")
            return ""

        # ================================================================
        # /RESTART
        # ================================================================
        elif cmd == "/restart":
            self.memory.clear()
            self._last_intelligence_product = None
            return "Session restarted. Memory wiped."

        # ================================================================
        # /STATUS
        # ================================================================
        elif cmd == "/status":
            v4_status = "READY" if CATHERINE_V4_AVAILABLE else "NOT LOADED"
            return (
                "System Status:\n"
                "  [OK] System    : ONLINE\n"
                "  [OK] Memory    : ACTIVE\n"
                "  [OK] API       : CONNECTED\n"
                "  [OK] Scraper   : READY\n"
                f"  [{'OK' if CATHERINE_V4_AVAILABLE else 'WARN'}] OSINT V4  : {v4_status}\n"
                "  [OK] OSINT     : READY"
            )

        # ================================================================
        # /MODEL
        # ================================================================
        elif cmd == "/model":
            return f"Current Model: {getattr(self.engine, 'model', 'Unknown')}"

        # ================================================================
        # /USAGE
        # ================================================================
        elif cmd == "/usage":
            total = getattr(self.tracker, "total_tokens", 0)
            inp = getattr(self.tracker, "input_tokens", 0)
            out = getattr(self.tracker, "output_tokens", 0)
            cost = getattr(self.tracker, "estimated_cost", 0.0)
            return (
                f"Token Usage:\n"
                f"  Total : {total}\n"
                f"  Input : {inp}\n"
                f"  Output: {out}\n"
                f"  Cost  : ${cost:.6f}"
            )

        # ================================================================
        # /BUDGET
        # ================================================================
        elif cmd == "/budget":
            if len(parts) > 1:
                try:
                    limit = float(parts[1])
                    self.tracker.set_budget(limit)
                    return f"Budget set to ${limit:.2f}"
                except ValueError:
                    return "Invalid budget format. Use: /budget 10.00"
            current = getattr(self.tracker, "budget_limit", None)
            if current is None:
                return "Current Budget Limit: No Limit"
            return f"Current Budget Limit: ${current:.2f}"

        # ================================================================
        # /ABOUT
        # ================================================================
        elif cmd == "/about":
            return (
                "C4therine Terminal AI\n"
                "A cinematic AI CLI Simulator with OSINT capabilities made bye J3MAL.\n"
                "Version: " + self.version
            )

        # ================================================================
        # /PING
        # ================================================================
        elif cmd == "/ping":
            start = time.time()
            time.sleep(0.1)
            latency = (time.time() - start) * 1000
            return f"API Latency: {latency:.2f}ms"

        # ================================================================
        # /SCRAPING
        # ================================================================
        elif cmd == "/scraping":
            if len(parts) < 4:
                return (
                    "[ERROR] Syntax salah.\n"
                    "Format: /scraping [URL] [CSS_Selector] [Jumlah_Export]\n"
                    "Contoh: /scraping https://news.yahoo.com/ h3 100"
                )

            url = parts[1]
            try:
                max_limit = int(parts[-1])
                selector = " ".join(parts[2:-1])
            except ValueError:
                return "Syntax Error. Parameter terakhir harus berupa angka."

            print(f"\033[92m[SYSTEM] Memulai ekstraksi dari {url}...\033[0m")
            result = self.registry.execute("scrape", url=url, target_element=selector, max_export=max_limit)

            if result["status"] == "error":
                return f"[SCRAPING FAILED] {result['message']}"

            extracted_data = result["data"]

            print(f"\n[DATA EXTRACTION COMPLETE]")
            print(f"Target      : {url}")
            print(f"Total Found : {result['total_found']}")
            print(f"Extracted   : {result['exported']}\n")

            print("--- PREVIEW (TOP 10) ---")
            for i, item in enumerate(result['preview']):
                print(f"[{i+1}] {item[:100]}...")

            choice = input("\n\033[93mSimpan hasil scraping ke CSV? (y/n): \033[0m").strip().lower()
            if choice == 'y':
                import csv
                import os
                import re

                topic = input("\033[93mMasukkan nama topik (contoh: berita_ibadah): \033[0m").strip()
                if not topic:
                    topic = "untitled"

                os.makedirs("storage/datasets", exist_ok=True)
                safe_filename = re.sub(r'[\\/*?:"<>|]', "", topic).replace(" ", "_")
                csv_path = f"storage/datasets/scraping_{safe_filename}.csv"

                with open(csv_path, mode='w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(["Scraped Content"])
                    for item in extracted_data:
                        writer.writerow([item])
                return f"Data berhasil diekspor ke {csv_path}"
            else:
                return "Export dibatalkan. Kembali ke sesi chat."


        elif cmd == "/scan":
            if len(parts) < 2:
                return "Syntax Error.\nFormat: /scan [URL]\nContoh: /scan https://example.com"

            url = parts[1]
            print(f"\033[92m[SYSTEM] Menginisialisasi Security Audit (V4) untuk: {url}\033[0m")

            choice = input("\033[91m[CRITICAL] Peringatan Legal. Anda diwajibkan memiliki otorisasi eksplisit terhadap target ini. Konfirmasi otorisasi? (y/n): \033[0m").strip().lower()
            if choice != 'y':
                return "Operasi digagalkan. Otorisasi tidak dikonfirmasi."

            print("\033[92m[SYSTEM] Mengeksekusi modul V1-V3 (Recon, Web, Vuln)...\033[0m")
            result = self.registry.execute("security", url=url)

            if result.get("status") == "error":
                return f"[SCAN FAILED] {result.get('message')}"

            raw_data = result["data"]
            print("\033[92m[SYSTEM] Pengumpulan data selesai. Mengirim telemetry ke AI Core untuk Analisis (V4)...\033[0m")

            ai_prompt = (
                f"Kamu adalah Lead Security Auditor. Analisis telemetry JSON ini secara klinis: {raw_data}\n\n"
                "ATURAN MUTLAK:\n"
                "1. DILARANG berhalusinasi atau menebak klasifikasi. Gunakan 'PANDUAN MAPPING WAJIB' di bawah ini untuk menentukan Severity, OWASP, dan Dampak.\n"
                "2. Jangan rekomendasikan pembaruan SSL jika statusnya sudah VALID.\n"
                "3. Sertakan Evidence dari JSON secara eksplisit (sebutkan nama header atau URL target).\n\n"
                "PANDUAN MAPPING WAJIB (Jangan menyimpang dari daftar ini):\n"
                "- Missing Content-Security-Policy (CSP) -> Severity: Medium | OWASP: A05:2021-Security Misconfiguration | Impact: Menghilangkan lapisan pertahanan utama terhadap serangan Cross-Site Scripting (XSS) dan data injection.\n"
                "- Missing X-Frame-Options -> Severity: Medium | OWASP: A05:2021-Security Misconfiguration | Impact: Membuka celah serangan Clickjacking dimana attacker dapat memanipulasi interaksi UI (iframe) pengguna.\n"
                "- Missing Strict-Transport-Security (HSTS) -> Severity: Medium | OWASP: A05:2021-Security Misconfiguration | Impact: Memungkinkan serangan Man-in-the-Middle (MitM) melalui teknik SSL Stripping.\n"
                "- Missing X-Content-Type-Options -> Severity: Low | OWASP: A05:2021-Security Misconfiguration | Impact: Memungkinkan serangan MIME-sniffing oleh browser yang dapat berujung pada eksekusi skrip berbahaya.\n"
                "- Missing Referrer-Policy -> Severity: Low | OWASP: A05:2021-Security Misconfiguration | Impact: Berisiko membocorkan parameter URL sensitif (seperti token sesi atau reset password) ke domain pihak ketiga melalui header Referer.\n"
                "- Open Redirect -> Severity: Medium | OWASP: A01:2021-Broken Access Control | Impact: Attacker dapat memanipulasi parameter URL untuk mengalihkan korban ke situs phishing, mencuri kredensial, atau menghindari filter keamanan.\n"
                "- Missing CSRF Token -> Severity: High | OWASP: A01:2021-Broken Access Control | Impact: Attacker dapat memaksa browser pengguna yang terautentikasi untuk mengeksekusi transaksi atau aksi yang tidak diinginkan secara sepihak.\n\n"
                "FORMAT LAPORAN MARKDOWN WAJIB:\n\n"
                "# 🛡️ SECURITY AUDIT REPORT\n"
                "**Scan Metadata:**\n"
                "- Target: [Dari JSON]\n"
                "- Date: [Dari JSON]\n"
                "- Scanner: [Dari JSON]\n"
                "- Duration: [Dari JSON] seconds\n\n"
                "## 1. EXECUTIVE SUMMARY\n"
                "(Analisis tingkat tinggi yang objektif. Nyatakan jika status aman hanya bersifat indikatif, bukan absolut.)\n\n"
                "## 2. RISK MATRIX SUMMARY\n"
                "- 🔴 HIGH: [Jumlah temuan HIGH]\n"
                "- 🟠 MEDIUM: [Jumlah temuan MEDIUM]\n"
                "- 🟡 LOW: [Jumlah temuan LOW]\n"
                "- 🔵 INFO: [Jumlah temuan INFO/NA]\n\n"
                "## 3. SECURITY SCORE BREAKDOWN\n"
                "- **Overall Score**: [Dari JSON] / 100\n"
                "- SSL/TLS: [Dari JSON]\n"
                "- Security Headers: [Dari JSON]\n"
                "- Vulnerability: [Dari JSON]\n"
                "- Cookie Security: [Dari JSON]\n"
                "- Configuration: [Dari JSON]\n"
                "- Info Exposure: [Dari JSON]\n\n"
                "## 4. TARGET PROFILING & TECH STACK\n"
                "(Daftar teknologi yang terdeteksi dari array tech_stack JSON)\n\n"
                "## 5. TECHNICAL FINDINGS\n"
                "(Gunakan PANDUAN MAPPING WAJIB untuk mengisi data di bawah ini. JIKA AMAN/NA, tuliskan di kategori INFO)\n"
                "### [SEC-00X] [Nama Kerentanan / Missing Header]\n"
                "- **Severity**: (Dari Panduan Mapping)\n"
                "- **OWASP Mapping**: (Dari Panduan Mapping)\n"
                "- **Confidence Level**: (Tingkat keyakinan deteksi)\n"
                "- **Business Impact**: (Dari Panduan Mapping)\n"
                "- **Evidence**: (Bukti teknis dari JSON)\n"
                "- **Actionable Mitigation**: (Perintah teknis perbaikan)\n\n"
                "## 6. STRATEGIC RECOMMENDATIONS\n"
                "(Langkah prioritas perbaikan berdasarkan Risk Matrix. Fokus pada aksi teknis yang terukur.)"
            )

            ai_report = self.engine.generate_response(ai_prompt)

            import os
            import re
            os.makedirs("storage/exports", exist_ok=True)
            safe_filename = re.sub(r'[\\/*?:"<>|]', "", url).replace("https", "").replace("http", "").strip("/")
            report_path = f"storage/exports/Security_Report_{safe_filename}.md"

            with open(report_path, "w", encoding="utf-8") as f:
                f.write(ai_report)

            print(f"\n\033[93m[SUCCESS] Laporan AI berhasil dirender dan disimpan di: {report_path}\033[0m\n")

            return ai_report

        # ================================================================
        # /SEARCH
        # ================================================================
        elif cmd == "/search":
            if len(parts) < 3:
                return (
                    "[ERROR] Syntax salah.\n"
                    "Format: /search [Keyword] [Jumlah]\n"
                    "Contoh: /search pembubaran ibadah 50"
                )

            try:
                max_limit = int(parts[-1])
                query = " ".join(parts[1:-1])
            except ValueError:
                return "Syntax Error. Parameter terakhir harus berupa angka (Jumlah_Export)."

            print(f"\033[92m[SYSTEM] Mencari '{query}' di Web Search (Target: {max_limit} data)...\033[0m")
            result = self.registry.execute("search", query=query, max_results=max_limit)

            if result["status"] == "error":
                return f"[SEARCH FAILED] {result['message']}"

            data = result.get("data", [])
            if not data:
                return "Tidak ada hasil ditemukan."

            print(f"\n[DATA EXTRACTION COMPLETE]")
            print(f"Target      : {query}")
            print(f"Total Found : {len(data)}\n")

            print("--- PREVIEW (TOP 5) ---")
            for i, item in enumerate(data[:5]):
                print(f"[{i+1}] {item['title']}")

            choice = input("\n\033[93mSimpan hasil search ke CSV? (y/n): \033[0m").strip().lower()
            if choice == 'y':
                import csv
                import os
                import re
                os.makedirs("storage/datasets", exist_ok=True)

                safe_filename = re.sub(r'[\\/*?:"<>|]', "", query).replace(" ", "_")
                csv_path = f"storage/datasets/search_{safe_filename}.csv"

                with open(csv_path, mode='w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(["Title", "Link", "Snippet"])
                    for item in data:
                        writer.writerow([item["title"], item["link"], item["snippet"]])
                return f"Data berhasil diekspor ke {csv_path}"
            else:
                return "Export dibatalkan. Kembali ke sesi chat."

        # ================================================================
        # /OSINT (LEGACY)
        # ================================================================
        elif cmd == "/osint":
            if len(parts) < 2:
                return (
                    "[ERROR] Syntax salah.\n"
                    "Format: /osint [Nama Lengkap]\n"
                    "Contoh: /osint Ahmad Syaifudin Hostama\n\n"
                    "Tips:\n"
                    "  - Gunakan nama lengkap untuk akurasi tinggi\n"
                    "  - Engine akan mencari exact match, bukan partial\n\n"
                    "CATHERINE V4 Commands:\n"
                    "  /osint-ingest    - Ingest data ke pipeline\n"
                    "  /osint-pipeline  - Run full intelligence pipeline\n"
                    "  /osint-report    - Generate narrative report\n"
                    "  /osint-visualize - Generate graph visualization\n"
                    "  /osint-query     - Query entities dari graph\n"
                    "  /osint-export    - Export ke berbagai format"
                )

            target_name = " ".join(parts[1:])

            result = self.registry.execute("osint", target=target_name)

            if result.get("status") == "error":
                return f"[OSINT FAILED] {result.get('message', 'Unknown error')}"

            profile = result.get("profile", {})
            results = profile.get("all_results", [])

            if not results:
                return (
                    f"[OSINT REPORT] Tidak ditemukan jejak publik untuk '{target_name}'.\n"
                    "Coba gunakan nama lengkap atau varian penulisan lain."
                )

            output_lines = [
                "╔══════════════════════════════════════════════════════════════╗",
                "║                    ADVANCED OSINT REPORT                     ║",
                "╠══════════════════════════════════════════════════════════════╣",
                f"  Target Name      : {result.get('target', 'N/A')}",
                f"  Normalized       : {result.get('normalized_name', 'N/A')}",
                f"  Variants Searched: {', '.join(result.get('name_variants_searched', []))}",
                f"  Platforms        : {', '.join(result.get('platforms_searched', []))}",
                f"  Total Matches    : {result.get('total_exact_matches', 0)}",
                f"  Confidence Score : {result.get('confidence_score', 0)}%",
                ""
            ]

            usernames = profile.get("usernames_found", [])
            if usernames:
                output_lines.append(f"  Usernames Found  : {', '.join(usernames)}")

            emails = profile.get("emails_found", [])
            if emails:
                output_lines.append(f"  Emails Found     : {', '.join(emails)}")

            output_lines.append("")
            output_lines.append("--- TOP RESULTS ---")
            output_lines.append("")

            for i, res in enumerate(results[:10], 1):
                output_lines.append(f"[{i}] {res.get('title', 'N/A')}")
                output_lines.append(f"    Source : {res.get('source', 'N/A')}")
                output_lines.append(f"    Link   : {res.get('href', 'N/A')}")
                output_lines.append(f"    Match  : {res.get('match_type', 'N/A')}")
                output_lines.append(f"    Score  : {res.get('relevance_score', 0):.1f}")
                output_lines.append(f"    Snippet: {res.get('body', '')[:120]}...")
                output_lines.append("")

            social = profile.get("social_profiles", {})
            if social:
                output_lines.append("--- PER-PLATFORM BREAKDOWN ---")
                for platform, items in social.items():
                    output_lines.append(f"  [{platform.upper()}] {len(items)} result(s)")
                output_lines.append("")

            output_lines.append("╚══════════════════════════════════════════════════════════════╝")

            return "\n".join(output_lines)

        # ================================================================
        # /VERSION
        # ================================================================
        elif cmd == "/version":
            return f"C4therine Terminal AI {self.version}"

        # ================================================================
        # /EXIT
        # ================================================================
        elif cmd == "/exit":
            if CATHERINE_V4_AVAILABLE and self._osint_orchestrator is not None:
                self._osint_orchestrator.shutdown()
            sys.exit(0)

        # ================================================================
        # UNKNOWN COMMAND
        # ================================================================
        else:
            return f"Unknown command '{cmd}'. Type /help for available commands."