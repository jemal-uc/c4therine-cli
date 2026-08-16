import sys
if sys.platform.startswith('win'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

from config.settings import GROQ_API_KEY
from core.memory import MemoryManager
from core.cache import CacheSystem
from core.usage_tracker import UsageTracker
from core.ai_engine import AIEngine
from core.command_router import CommandRouter
from core.tool_registry import ToolRegistry
from ui.renderer import UIRenderer

# Tool Imports
from tools.scraper import ScraperTool
from tools.search import SearchTool
from tools.security.website_scanner import WebsiteScanner

# ================================================================
# [REVISI OSINT] Import OSINT Engines
# ================================================================
# 1. Legacy OSINT (untuk /osint command)
try:
    from tools.osint.osint_engine import AdvancedOSINTLookup
    OSINT_LEGACY = AdvancedOSINTLookup()
    print("[OSINT] Legacy engine loaded")
except ImportError:
    OSINT_LEGACY = None
    print("[OSINT] Legacy engine not available")

# 2. Catherine V4 Orchestrator (untuk /osint-pipeline, dll)
try:
    from tools.osint.intelligence_orchestrator import (
        IntelligenceOrchestrator,
        OrchestratorConfig,
        OrchestratorMode,
    )
    orch_config = OrchestratorConfig(
        mode=OrchestratorMode.HYBRID,
        enable_anomaly_detection=True,
        enable_hypothesis_generation=True,
        enable_auto_report=True,
    )
    OSINT_V4 = IntelligenceOrchestrator(config=orch_config)
    OSINT_V4.initialize()
    print("[OSINT] Catherine V4 orchestrator loaded")
except ImportError as e:
    OSINT_V4 = None
    print(f"[OSINT] V4 not available: {e}")

def main():
    if not GROQ_API_KEY:
        print("ERROR: GROQ_API_KEY is missing in .env")
        sys.exit(1)

    # Inisialisasi Modul
    memory = MemoryManager()
    cache = CacheSystem()
    tracker = UsageTracker()
    engine = AIEngine(memory, cache, tracker)
    
    # Registrasi Alat (Tools)
    registry = ToolRegistry()
    registry.register("scrape", ScraperTool())
    registry.register("search", SearchTool())
    registry.register("security", WebsiteScanner())
    
    # ================================================================
    # [REVISI OSINT] Register OSINT Engines
    # ================================================================
    # Legacy OSINT untuk /osint command
    if OSINT_LEGACY:
        registry.register("osint", OSINT_LEGACY)
    else:
        # Dummy fallback
        class DummyOSINT:
            def execute(self, target, **kwargs):
                return {"status": "error", "message": "OSINT engine not available"}
        registry.register("osint", DummyOSINT())
    
    # Catherine V4 Orchestrator untuk commands V4
    if OSINT_V4:
        registry.register("osint_v4", OSINT_V4)
    
    # Inisialisasi Router
    router = CommandRouter(memory, tracker, engine, registry)
    
    # Menyalakan Tampilan CLI
    ui = UIRenderer()
    ui.boot_sequence()

    # Loop Terminal Utama
    while True:
        try:
            user_input = input("\033[92mYou > \033[0m").strip()
            
            if not user_input:
                continue

            if user_input.startswith("/"):
                response = router.handle(user_input)
                ui.print_system(response)
                continue

            ui.show_thinking()
            
            budget_status = tracker.check_budget()
            if budget_status == "warning":
                ui.print_system("[WARNING] Usage has reached 80% of budget limit.")

            ai_response = engine.generate_response(user_input)
            
            sys.stdout.write("\033[92mC4therine > \033[0m")
            ui.type_effect(ai_response)

        except KeyboardInterrupt:
            print("\n")
            ui.print_system("System interrupted. Exiting...")
            # Graceful shutdown V4
            if OSINT_V4 and hasattr(OSINT_V4, 'shutdown'):
                OSINT_V4.shutdown()
            sys.exit(0)
        except Exception as e:
            ui.print_system(f"System Error: {str(e)}")

if __name__ == "__main__":
    main()