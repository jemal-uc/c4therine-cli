#!/usr/bin/env python3
"""
intelligence_orchestrator.py — Intelligence Orchestrator Module
===============================================================
File terakhir V4 dari OSINT Intelligence Platform (Catherine).
Mengorkestrasi seluruh pipeline: data ingestion → analysis → 
confidence scoring → anomaly detection → hypothesis generation → 
narrative report generation.

Author: Catherine Team
Version: 4.0.0
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
from typing import (
    Any,
    Callable,
    Coroutine,
    Dict,
    Generic,
    List,
    Optional,
    Protocol,
    Set,
    TypeVar,
    Union,
)
from collections import defaultdict
import threading

# Internal module imports (semua modul V4 yang sudah dibuat)
try:
    from tools.osint.graph.neo4j_connector import Neo4jConnector, Neo4jConfig
    from tools.osint.graph.graph_builder import GraphBuilder, EntityNode, RelationshipEdge
    from tools.osint.graph.graph_exporter import GraphExporter, ExportFormat
    from tools.osint.reporting.maltego_export import MaltegoExporter
    from tools.osint.analysis.visualizer import GraphVisualizer, VisualizationConfig
    from tools.osint.analysis.confidence_engine import ConfidenceEngine, ConfidenceScore, ConfidenceFactors
    from tools.osint.analysis.anomaly_detector import AnomalyDetector, AnomalyResult, AnomalyType
    from tools.osint.analysis.hypothesis_generator import HypothesisGenerator, Hypothesis, HypothesisPriority
    from tools.osint.reporting.narrative_report import (
        NarrativeReportGenerator,
        ReportConfig,
        ReportTone,
        ReportSection,
    )
    MODULES_AVAILABLE = True
except ImportError as e:
    MODULES_AVAILABLE = False
    IMPORT_ERROR = str(e)

# ============================================================================
# Logging Configuration
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(name)-20s | %(levelname)-8s | %(message)s",
)
logger = logging.getLogger("Catherine.Orchestrator")


# ============================================================================
# Enums & Constants
# ============================================================================

class PipelineStage(Enum):
    """Stages dalam intelligence pipeline."""
    INGESTION = auto()
    NORMALIZATION = auto()
    ENRICHMENT = auto()
    GRAPH_BUILD = auto()
    CONFIDENCE_SCORING = auto()
    ANOMALY_DETECTION = auto()
    HYPOTHESIS_GENERATION = auto()
    REPORT_GENERATION = auto()
    EXPORT = auto()
    COMPLETED = auto()
    FAILED = auto()


class PipelinePriority(Enum):
    """Priority levels untuk pipeline execution."""
    CRITICAL = 1
    HIGH = 2
    NORMAL = 3
    LOW = 4


class OrchestratorMode(Enum):
    """Operating modes untuk orchestrator."""
    REALTIME = "realtime"
    BATCH = "batch"
    HYBRID = "hybrid"
    SCHEDULED = "scheduled"


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class SourceMetadata:
    """Metadata untuk data source."""
    source_id: str
    source_type: str  # e.g., "osint", "dark_web", "social_media", "humint"
    source_name: str
    reliability: float = 0.5  # 0.0 - 1.0
    credibility: float = 0.5   # 0.0 - 1.0
    collection_time: datetime = field(default_factory=datetime.utcnow)
    collection_method: str = "automated"
    operator_id: Optional[str] = None
    tags: Set[str] = field(default_factory=set)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_id": self.source_id,
            "source_type": self.source_type,
            "source_name": self.source_name,
            "reliability": self.reliability,
            "credibility": self.credibility,
            "collection_time": self.collection_time.isoformat(),
            "collection_method": self.collection_method,
            "operator_id": self.operator_id,
            "tags": list(self.tags),
        }


@dataclass
class RawData:
    """Raw data item yang masuk ke pipeline."""
    data_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    content: Any = None
    metadata: SourceMetadata = field(default_factory=lambda: SourceMetadata(
        source_id="unknown", source_type="unknown", source_name="unknown"
    ))
    raw_format: str = "json"
    ingestion_time: datetime = field(default_factory=datetime.utcnow)
    checksum: str = ""
    processing_status: str = "pending"
    pipeline_history: List[Dict[str, Any]] = field(default_factory=list)
    
    def __post_init__(self):
        if not self.checksum:
            self.checksum = self._calculate_checksum()
    
    def _calculate_checksum(self) -> str:
        """Calculate SHA-256 checksum dari content."""
        content_str = json.dumps(self.content, sort_keys=True, default=str)
        return hashlib.sha256(content_str.encode()).hexdigest()[:16]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "data_id": self.data_id,
            "content": self.content,
            "metadata": self.metadata.to_dict(),
            "raw_format": self.raw_format,
            "ingestion_time": self.ingestion_time.isoformat(),
            "checksum": self.checksum,
            "processing_status": self.processing_status,
            "pipeline_history": self.pipeline_history,
        }


@dataclass
class PipelineResult:
    """Hasil dari pipeline execution."""
    pipeline_id: str
    stage: PipelineStage
    status: str  # "success", "partial", "failed"
    data_id: str
    output: Any = None
    metrics: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    execution_time_ms: float = 0.0
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "pipeline_id": self.pipeline_id,
            "stage": self.stage.name,
            "status": self.status,
            "data_id": self.data_id,
            "output": self.output if isinstance(self.output, (dict, list, str, int, float, bool, type(None))) else str(self.output),
            "metrics": self.metrics,
            "errors": self.errors,
            "warnings": self.warnings,
            "execution_time_ms": self.execution_time_ms,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class IntelligenceProduct:
    """Final intelligence product dari pipeline."""
    product_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    case_id: str = ""
    title: str = ""
    classification: str = "UNCLASSIFIED"
    created_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    pipeline_results: List[PipelineResult] = field(default_factory=list)
    final_report: Optional[str] = None
    report_format: str = "markdown"
    entities: List[Dict[str, Any]] = field(default_factory=list)
    relationships: List[Dict[str, Any]] = field(default_factory=list)
    anomalies: List[Dict[str, Any]] = field(default_factory=list)
    hypotheses: List[Dict[str, Any]] = field(default_factory=list)
    confidence_scores: Dict[str, float] = field(default_factory=dict)
    export_paths: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "product_id": self.product_id,
            "case_id": self.case_id,
            "title": self.title,
            "classification": self.classification,
            "created_at": self.created_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "pipeline_results": [r.to_dict() for r in self.pipeline_results],
            "final_report": self.final_report,
            "report_format": self.report_format,
            "entities": self.entities,
            "relationships": self.relationships,
            "anomalies": self.anomalies,
            "hypotheses": self.hypotheses,
            "confidence_scores": self.confidence_scores,
            "export_paths": self.export_paths,
            "metadata": self.metadata,
        }


@dataclass
class OrchestratorConfig:
    """Konfigurasi untuk Intelligence Orchestrator."""
    mode: OrchestratorMode = OrchestratorMode.HYBRID
    max_concurrent_pipelines: int = 5
    enable_caching: bool = True
    cache_ttl_seconds: int = 3600
    enable_anomaly_detection: bool = True
    enable_hypothesis_generation: bool = True
    enable_auto_report: bool = True
    confidence_threshold: float = 0.6
    anomaly_threshold: float = 0.7
    neo4j_config: Optional[Neo4jConfig] = None
    report_config: Optional[ReportConfig] = None
    custom_plugins: List[str] = field(default_factory=list)
    notification_webhooks: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "mode": self.mode.value,
            "max_concurrent_pipelines": self.max_concurrent_pipelines,
            "enable_caching": self.enable_caching,
            "cache_ttl_seconds": self.cache_ttl_seconds,
            "enable_anomaly_detection": self.enable_anomaly_detection,
            "enable_hypothesis_generation": self.enable_hypothesis_generation,
            "enable_auto_report": self.enable_auto_report,
            "confidence_threshold": self.confidence_threshold,
            "anomaly_threshold": self.anomaly_threshold,
            "neo4j_config": self.neo4j_config.to_dict() if self.neo4j_config else None,
            "report_config": asdict(self.report_config) if self.report_config else None,
            "custom_plugins": self.custom_plugins,
            "notification_webhooks": self.notification_webhooks,
        }


# ============================================================================
# Event System
# ============================================================================

T = TypeVar('T')

class Event(Generic[T]):
    """Event dalam event-driven architecture."""
    def __init__(self, event_type: str, payload: T, source: str = "orchestrator"):
        self.event_type = event_type
        self.payload = payload
        self.source = source
        self.timestamp = datetime.utcnow()
        self.event_id = str(uuid.uuid4())
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "source": self.source,
            "timestamp": self.timestamp.isoformat(),
            "payload": self.payload if isinstance(self.payload, (dict, list, str, int, float, bool, type(None))) else str(self.payload),
        }


class EventBus:
    """Event bus untuk komunikasi antar komponen."""
    def __init__(self):
        self._subscribers: Dict[str, List[Callable[[Event], None]]] = defaultdict(list)
        self._lock = threading.Lock()
        self._event_history: List[Dict[str, Any]] = []
        self._max_history = 1000
    
    def subscribe(self, event_type: str, handler: Callable[[Event], None]) -> None:
        """Subscribe ke event type tertentu."""
        with self._lock:
            self._subscribers[event_type].append(handler)
        logger.debug(f"Handler subscribed to event type: {event_type}")
    
    def unsubscribe(self, event_type: str, handler: Callable[[Event], None]) -> None:
        """Unsubscribe handler dari event type."""
        with self._lock:
            if event_type in self._subscribers:
                self._subscribers[event_type] = [
                    h for h in self._subscribers[event_type] if h != handler
                ]
    
    def publish(self, event: Event) -> None:
        """Publish event ke semua subscribers."""
        with self._lock:
            self._event_history.append(event.to_dict())
            if len(self._event_history) > self._max_history:
                self._event_history = self._event_history[-self._max_history:]
        
        handlers = self._subscribers.get(event.event_type, [])
        for handler in handlers:
            try:
                handler(event)
            except Exception as e:
                logger.error(f"Error in event handler for {event.event_type}: {e}")
        
        # Also notify wildcard subscribers
        for handler in self._subscribers.get("*", []):
            try:
                handler(event)
            except Exception as e:
                logger.error(f"Error in wildcard handler: {e}")
    
    def get_history(self, event_type: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Get event history dengan optional filtering."""
        history = self._event_history
        if event_type:
            history = [e for e in history if e["event_type"] == event_type]
        return history[-limit:]


# ============================================================================
# Plugin System
# ============================================================================

class PluginProtocol(Protocol):
    """Protocol untuk custom plugins."""
    name: str
    version: str
    
    def initialize(self, config: Dict[str, Any]) -> None: ...
    def process(self, data: RawData) -> RawData: ...
    def shutdown(self) -> None: ...


class PluginManager:
    """Manager untuk custom plugins."""
    def __init__(self):
        self._plugins: Dict[str, PluginProtocol] = {}
        self._hooks: Dict[str, List[Callable]] = defaultdict(list)
    
    def register_plugin(self, plugin: PluginProtocol) -> None:
        """Register plugin baru."""
        self._plugins[plugin.name] = plugin
        logger.info(f"Plugin registered: {plugin.name} v{plugin.version}")
    
    def unregister_plugin(self, plugin_name: str) -> None:
        """Unregister plugin."""
        if plugin_name in self._plugins:
            self._plugins[plugin_name].shutdown()
            del self._plugins[plugin_name]
    
    def execute_hook(self, hook_name: str, data: Any) -> Any:
        """Execute semua hooks untuk hook name tertentu."""
        result = data
        for hook in self._hooks.get(hook_name, []):
            try:
                result = hook(result)
            except Exception as e:
                logger.error(f"Hook error in {hook_name}: {e}")
        return result
    
    def register_hook(self, hook_name: str, callback: Callable) -> None:
        """Register hook callback."""
        self._hooks[hook_name].append(callback)
    
    def process_with_plugins(self, data: RawData) -> RawData:
        """Process data melalui semua registered plugins."""
        result = data
        for plugin in self._plugins.values():
            try:
                result = plugin.process(result)
            except Exception as e:
                logger.error(f"Plugin error in {plugin.name}: {e}")
        return result


# ============================================================================
# Cache System
# ============================================================================

class ResultCache:
    """Simple cache untuk pipeline results."""
    def __init__(self, ttl_seconds: int = 3600):
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._ttl = ttl_seconds
        self._lock = threading.Lock()
    
    def _make_key(self, data: RawData, stage: PipelineStage) -> str:
        """Generate cache key dari data dan stage."""
        key_data = f"{data.checksum}:{stage.name}"
        return hashlib.md5(key_data.encode()).hexdigest()
    
    def get(self, data: RawData, stage: PipelineStage) -> Optional[Any]:
        """Get cached result jika masih valid."""
        key = self._make_key(data, stage)
        with self._lock:
            if key in self._cache:
                entry = self._cache[key]
                if time.time() - entry["timestamp"] < self._ttl:
                    logger.debug(f"Cache hit for {stage.name}")
                    return entry["result"]
                else:
                    del self._cache[key]
        return None
    
    def set(self, data: RawData, stage: PipelineStage, result: Any) -> None:
        """Cache result."""
        key = self._make_key(data, stage)
        with self._lock:
            self._cache[key] = {
                "result": result,
                "timestamp": time.time(),
                "data_id": data.data_id,
            }
    
    def invalidate(self, data_id: Optional[str] = None) -> None:
        """Invalidate cache entries."""
        with self._lock:
            if data_id:
                keys_to_remove = [
                    k for k, v in self._cache.items() 
                    if v.get("data_id") == data_id
                ]
                for k in keys_to_remove:
                    del self._cache[k]
            else:
                self._cache.clear()


# ============================================================================
# Core Orchestrator
# ============================================================================

class IntelligenceOrchestrator:
    """
    Core orchestrator untuk OSINT Intelligence Platform (Catherine) v4.
    
    Mengorkestrasi seluruh pipeline dari data ingestion sampai 
    intelligence product generation.
    """
    
    def __init__(self, config: Optional[OrchestratorConfig] = None):
        self.config = config or OrchestratorConfig()
        self.event_bus = EventBus()
        self.plugin_manager = PluginManager()
        self.cache = ResultCache(self.config.cache_ttl_seconds)
        
        # Module instances
        self._neo4j_connector: Optional[Neo4jConnector] = None
        self._graph_builder: Optional[GraphBuilder] = None
        self._graph_exporter: Optional[GraphExporter] = None
        self._maltego_exporter: Optional[MaltegoExporter] = None
        self._visualizer: Optional[GraphVisualizer] = None
        self._confidence_engine: Optional[ConfidenceEngine] = None
        self._anomaly_detector: Optional[AnomalyDetector] = None
        self._hypothesis_generator: Optional[HypothesisGenerator] = None
        self._report_generator: Optional[NarrativeReportGenerator] = None
        
        # Pipeline tracking
        self._active_pipelines: Dict[str, Dict[str, Any]] = {}
        self._pipeline_semaphore = asyncio.Semaphore(self.config.max_concurrent_pipelines)
        self._pipeline_counter = 0
        
        # Statistics
        self._stats = {
            "total_pipelines": 0,
            "successful_pipelines": 0,
            "failed_pipelines": 0,
            "total_entities": 0,
            "total_relationships": 0,
            "start_time": datetime.utcnow(),
        }
        
        # Status
        self._initialized = False
        self._running = False
        
        logger.info("IntelligenceOrchestrator instance created")
    
    # -------------------------------------------------------------------------
    # Initialization
    # -------------------------------------------------------------------------
    
    def initialize(self) -> None:
        """Initialize semua modules dan koneksi."""
        if self._initialized:
            logger.warning("Orchestrator already initialized")
            return
        
        if not MODULES_AVAILABLE:
            logger.warning(f"Some modules not available: {IMPORT_ERROR}")
            logger.warning("Running in limited mode")
        
        logger.info("Initializing IntelligenceOrchestrator...")
        
        # Initialize modules jika tersedia
        if MODULES_AVAILABLE:
            self._initialize_modules()
        
        # Register default event handlers
        self._register_default_handlers()
        
        self._initialized = True
        self._running = True
        logger.info("IntelligenceOrchestrator initialized successfully")
    
    def _initialize_modules(self) -> None:
        """Initialize semua Catherine v4 modules."""
        try:
            # Neo4j
            if self.config.neo4j_config:
                self._neo4j_connector = Neo4jConnector(self.config.neo4j_config)
                logger.info("Neo4jConnector initialized")
            
            # Graph Builder
            self._graph_builder = GraphBuilder(connector=self._neo4j_connector)
            logger.info("GraphBuilder initialized")
            
            # Exporters
            self._graph_exporter = GraphExporter(builder=self._graph_builder)
            self._maltego_exporter = MaltegoExporter(builder=self._graph_builder)
            logger.info("Exporters initialized")
            
            # Visualizer
            self._visualizer = GraphVisualizer()
            logger.info("GraphVisualizer initialized")
            
            # Analysis modules
            self._confidence_engine = ConfidenceEngine()
            self._anomaly_detector = AnomalyDetector()
            self._hypothesis_generator = HypothesisGenerator()
            logger.info("Analysis modules initialized")
            
            # Report generator
            report_config = self.config.report_config or ReportConfig()
            self._report_generator = NarrativeReportGenerator(config=report_config)
            logger.info("NarrativeReportGenerator initialized")
            
        except Exception as e:
            logger.error(f"Error initializing modules: {e}")
            raise
    
    def _register_default_handlers(self) -> None:
        """Register default event handlers."""
        self.event_bus.subscribe("pipeline.completed", self._on_pipeline_completed)
        self.event_bus.subscribe("pipeline.failed", self._on_pipeline_failed)
        self.event_bus.subscribe("anomaly.detected", self._on_anomaly_detected)
        self.event_bus.subscribe("hypothesis.generated", self._on_hypothesis_generated)
    
    def shutdown(self) -> None:
        """Graceful shutdown."""
        logger.info("Shutting down IntelligenceOrchestrator...")
        self._running = False
        
        # Shutdown plugins
        for plugin_name in list(self.plugin_manager._plugins.keys()):
            self.plugin_manager.unregister_plugin(plugin_name)
        
        # Close Neo4j connection
        if self._neo4j_connector:
            try:
                self._neo4j_connector.close()
                logger.info("Neo4j connection closed")
            except Exception as e:
                logger.error(f"Error closing Neo4j: {e}")
        
        self._initialized = False
        logger.info("IntelligenceOrchestrator shutdown complete")
    
    # -------------------------------------------------------------------------
    # Event Handlers
    # -------------------------------------------------------------------------
    
    def _on_pipeline_completed(self, event: Event) -> None:
        """Handler untuk pipeline completion."""
        payload = event.payload
        logger.info(f"Pipeline {payload.get('pipeline_id')} completed: {payload.get('status')}")
        self._stats["successful_pipelines"] += 1
    
    def _on_pipeline_failed(self, event: Event) -> None:
        """Handler untuk pipeline failure."""
        payload = event.payload
        logger.error(f"Pipeline {payload.get('pipeline_id')} failed: {payload.get('errors')}")
        self._stats["failed_pipelines"] += 1
    
    def _on_anomaly_detected(self, event: Event) -> None:
        """Handler untuk anomaly detection."""
        payload = event.payload
        logger.warning(f"Anomaly detected: {payload.get('anomaly_type')} - {payload.get('description')}")
    
    def _on_hypothesis_generated(self, event: Event) -> None:
        """Handler untuk hypothesis generation."""
        payload = event.payload
        logger.info(f"Hypothesis generated: {payload.get('title')} (priority: {payload.get('priority')})")
    
    # -------------------------------------------------------------------------
    # Core Pipeline Methods
    # -------------------------------------------------------------------------
    
    async def ingest_data(
        self,
        content: Any,
        metadata: Optional[SourceMetadata] = None,
        raw_format: str = "json",
    ) -> RawData:
        """
        Ingest raw data ke pipeline.
        
        Args:
            content: Raw data content
            metadata: Source metadata
            raw_format: Format data (json, csv, xml, etc.)
        
        Returns:
            RawData instance
        """
        metadata = metadata or SourceMetadata(
            source_id="manual", source_type="manual", source_name="Manual Input"
        )
        
        data = RawData(
            content=content,
            metadata=metadata,
            raw_format=raw_format,
        )
        
        # Apply plugins
        data = self.plugin_manager.process_with_plugins(data)
        
        # Log ingestion
        data.pipeline_history.append({
            "stage": PipelineStage.INGESTION.name,
            "timestamp": datetime.utcnow().isoformat(),
            "status": "completed",
        })
        
        self.event_bus.publish(Event("data.ingested", data.to_dict()))
        logger.info(f"Data ingested: {data.data_id} from {metadata.source_name}")
        
        return data
    
    async def run_pipeline(
        self,
        data: RawData,
        case_id: str = "",
        priority: PipelinePriority = PipelinePriority.NORMAL,
        skip_stages: Optional[List[PipelineStage]] = None,
    ) -> IntelligenceProduct:
        """
        Run full intelligence pipeline untuk single data item.
        
        Args:
            data: RawData yang sudah di-ingest
            case_id: Case/Investigation ID
            priority: Pipeline priority
            skip_stages: List stages yang akan di-skip
        
        Returns:
            IntelligenceProduct final
        """
        if not self._initialized:
            raise RuntimeError("Orchestrator not initialized. Call initialize() first.")
        
        if not self._running:
            raise RuntimeError("Orchestrator is not running")
        
        skip_stages = skip_stages or []
        self._pipeline_counter += 1
        pipeline_id = f"PIPE-{self._pipeline_counter:06d}"
        
        product = IntelligenceProduct(
            case_id=case_id or f"CASE-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}",
            title=f"Intelligence Product - {data.metadata.source_name}",
        )
        
        logger.info(f"Starting pipeline {pipeline_id} for data {data.data_id}")
        
        async with self._pipeline_semaphore:
            self._active_pipelines[pipeline_id] = {
                "data_id": data.data_id,
                "start_time": time.time(),
                "priority": priority.name,
                "status": "running",
            }
            
            try:
                # Stage 1: Normalization
                if PipelineStage.NORMALIZATION not in skip_stages:
                    result = await self._stage_normalization(data, pipeline_id)
                    product.pipeline_results.append(result)
                    if result.status == "failed":
                        raise PipelineError(f"Normalization failed: {result.errors}")
                
                # Stage 2: Enrichment
                if PipelineStage.ENRICHMENT not in skip_stages:
                    result = await self._stage_enrichment(data, pipeline_id)
                    product.pipeline_results.append(result)
                
                # Stage 3: Graph Build
                if PipelineStage.GRAPH_BUILD not in skip_stages and self._graph_builder:
                    result = await self._stage_graph_build(data, pipeline_id)
                    product.pipeline_results.append(result)
                    if result.output:
                        product.entities = result.output.get("entities", [])
                        product.relationships = result.output.get("relationships", [])
                
                # Stage 4: Confidence Scoring
                if PipelineStage.CONFIDENCE_SCORING not in skip_stages and self._confidence_engine:
                    result = await self._stage_confidence_scoring(data, pipeline_id, product)
                    product.pipeline_results.append(result)
                    if result.output:
                        product.confidence_scores = result.output
                
                # Stage 5: Anomaly Detection
                if (PipelineStage.ANOMALY_DETECTION not in skip_stages 
                    and self.config.enable_anomaly_detection 
                    and self._anomaly_detector):
                    result = await self._stage_anomaly_detection(data, pipeline_id, product)
                    product.pipeline_results.append(result)
                    if result.output:
                        product.anomalies = result.output
                
                # Stage 6: Hypothesis Generation
                if (PipelineStage.HYPOTHESIS_GENERATION not in skip_stages 
                    and self.config.enable_hypothesis_generation 
                    and self._hypothesis_generator):
                    result = await self._stage_hypothesis_generation(data, pipeline_id, product)
                    product.pipeline_results.append(result)
                    if result.output:
                        product.hypotheses = result.output
                
                # Stage 7: Report Generation
                if (PipelineStage.REPORT_GENERATION not in skip_stages 
                    and self.config.enable_auto_report 
                    and self._report_generator):
                    result = await self._stage_report_generation(data, pipeline_id, product)
                    product.pipeline_results.append(result)
                    if result.output:
                        product.final_report = result.output.get("report")
                        product.report_format = result.output.get("format", "markdown")
                
                # Stage 8: Export
                if PipelineStage.EXPORT not in skip_stages:
                    result = await self._stage_export(data, pipeline_id, product)
                    product.pipeline_results.append(result)
                
                # Complete
                product.completed_at = datetime.utcnow()
                self._stats["total_pipelines"] += 1
                
                self.event_bus.publish(Event(
                    "pipeline.completed",
                    {
                        "pipeline_id": pipeline_id,
                        "product_id": product.product_id,
                        "status": "success",
                        "stages_completed": len(product.pipeline_results),
                    }
                ))
                
                logger.info(f"Pipeline {pipeline_id} completed successfully")
                
            except Exception as e:
                product.completed_at = datetime.utcnow()
                self._stats["failed_pipelines"] += 1
                
                error_result = PipelineResult(
                    pipeline_id=pipeline_id,
                    stage=PipelineStage.FAILED,
                    status="failed",
                    data_id=data.data_id,
                    errors=[str(e)],
                )
                product.pipeline_results.append(error_result)
                
                self.event_bus.publish(Event(
                    "pipeline.failed",
                    {
                        "pipeline_id": pipeline_id,
                        "product_id": product.product_id,
                        "errors": [str(e)],
                    }
                ))
                
                logger.error(f"Pipeline {pipeline_id} failed: {e}")
            
            finally:
                if pipeline_id in self._active_pipelines:
                    del self._active_pipelines[pipeline_id]
        
        return product
    
    async def run_batch_pipeline(
        self,
        data_items: List[RawData],
        case_id: str = "",
        priority: PipelinePriority = PipelinePriority.NORMAL,
    ) -> List[IntelligenceProduct]:
        """
        Run pipeline untuk multiple data items secara concurrent.
        
        Args:
            data_items: List of RawData
            case_id: Case ID
            priority: Pipeline priority
        
        Returns:
            List of IntelligenceProduct
        """
        tasks = [
            self.run_pipeline(data, case_id=case_id, priority=priority)
            for data in data_items
        ]
        return await asyncio.gather(*tasks, return_exceptions=True)
    
    # -------------------------------------------------------------------------
    # Pipeline Stages (Private)
    # -------------------------------------------------------------------------
    
    async def _stage_normalization(self, data: RawData, pipeline_id: str) -> PipelineResult:
        """Normalize raw data ke format standar."""
        start_time = time.time()
        
        try:
            # Check cache
            if self.config.enable_caching:
                cached = self.cache.get(data, PipelineStage.NORMALIZATION)
                if cached:
                    return PipelineResult(
                        pipeline_id=pipeline_id,
                        stage=PipelineStage.NORMALIZATION,
                        status="success",
                        data_id=data.data_id,
                        output=cached,
                        execution_time_ms=(time.time() - start_time) * 1000,
                    )
            
            # Normalize content
            normalized = self._normalize_content(data.content, data.raw_format)
            
            # Update data
            data.content = normalized
            data.processing_status = "normalized"
            data.pipeline_history.append({
                "stage": PipelineStage.NORMALIZATION.name,
                "timestamp": datetime.utcnow().isoformat(),
                "status": "completed",
            })
            
            # Cache result
            if self.config.enable_caching:
                self.cache.set(data, PipelineStage.NORMALIZATION, {"normalized": True})
            
            return PipelineResult(
                pipeline_id=pipeline_id,
                stage=PipelineStage.NORMALIZATION,
                status="success",
                data_id=data.data_id,
                output={"normalized": True, "format": data.raw_format},
                execution_time_ms=(time.time() - start_time) * 1000,
            )
            
        except Exception as e:
            return PipelineResult(
                pipeline_id=pipeline_id,
                stage=PipelineStage.NORMALIZATION,
                status="failed",
                data_id=data.data_id,
                errors=[str(e)],
                execution_time_ms=(time.time() - start_time) * 1000,
            )
    
    def _normalize_content(self, content: Any, raw_format: str) -> Any:
        """Normalize content berdasarkan format."""
        if raw_format == "json" and isinstance(content, str):
            return json.loads(content)
        elif raw_format == "csv" and isinstance(content, str):
            # Simple CSV normalization
            lines = content.strip().split("\n")
            if len(lines) > 1:
                headers = lines[0].split(",")
                return [
                    dict(zip(headers, line.split(",")))
                    for line in lines[1:]
                ]
            return []
        return content
    
    async def _stage_enrichment(self, data: RawData, pipeline_id: str) -> PipelineResult:
        """Enrich data dengan additional context."""
        start_time = time.time()
        
        try:
            enriched_data = {
                "original": data.content,
                "enriched": True,
                "enrichment_timestamp": datetime.utcnow().isoformat(),
                "source_reliability": data.metadata.reliability,
                "source_credibility": data.metadata.credibility,
                "enrichment_factors": {
                    "temporal_context": self._extract_temporal_context(data.content),
                    "geospatial_context": self._extract_geospatial_context(data.content),
                    "entity_mentions": self._extract_entity_mentions(data.content),
                }
            }
            
            data.pipeline_history.append({
                "stage": PipelineStage.ENRICHMENT.name,
                "timestamp": datetime.utcnow().isoformat(),
                "status": "completed",
            })
            
            return PipelineResult(
                pipeline_id=pipeline_id,
                stage=PipelineStage.ENRICHMENT,
                status="success",
                data_id=data.data_id,
                output=enriched_data,
                execution_time_ms=(time.time() - start_time) * 1000,
            )
            
        except Exception as e:
            return PipelineResult(
                pipeline_id=pipeline_id,
                stage=PipelineStage.ENRICHMENT,
                status="failed",
                data_id=data.data_id,
                errors=[str(e)],
                execution_time_ms=(time.time() - start_time) * 1000,
            )
    
    def _extract_temporal_context(self, content: Any) -> List[str]:
        """Extract temporal references dari content."""
        # Placeholder - implementasi sebenarnya akan menggunakan NLP
        return []
    
    def _extract_geospatial_context(self, content: Any) -> List[str]:
        """Extract geospatial references dari content."""
        # Placeholder - implementasi sebenarnya akan menggunakan geocoding
        return []
    
    def _extract_entity_mentions(self, content: Any) -> List[str]:
        """Extract entity mentions dari content."""
        # Placeholder - implementasi sebenarnya akan menggunakan NER
        return []
    
    async def _stage_graph_build(
        self, 
        data: RawData, 
        pipeline_id: str
    ) -> PipelineResult:
        """Build graph dari normalized data."""
        start_time = time.time()
        
        try:
            if not self._graph_builder:
                return PipelineResult(
                    pipeline_id=pipeline_id,
                    stage=PipelineStage.GRAPH_BUILD,
                    status="partial",
                    data_id=data.data_id,
                    warnings=["GraphBuilder not available"],
                    execution_time_ms=(time.time() - start_time) * 1000,
                )
            
            # Extract entities dan relationships dari content
            entities = self._extract_entities_from_content(data.content)
            relationships = self._extract_relationships_from_content(data.content, entities)
            
            # Build graph
            for entity in entities:
                self._graph_builder.add_entity(entity)
            
            for rel in relationships:
                self._graph_builder.add_relationship(rel)
            
            result_data = {
                "entities": [e.to_dict() if hasattr(e, 'to_dict') else str(e) for e in entities],
                "relationships": [r.to_dict() if hasattr(r, 'to_dict') else str(r) for r in relationships],
                "graph_stats": self._graph_builder.get_stats() if hasattr(self._graph_builder, 'get_stats') else {},
            }
            
            self._stats["total_entities"] += len(entities)
            self._stats["total_relationships"] += len(relationships)
            
            return PipelineResult(
                pipeline_id=pipeline_id,
                stage=PipelineStage.GRAPH_BUILD,
                status="success",
                data_id=data.data_id,
                output=result_data,
                metrics={
                    "entities_created": len(entities),
                    "relationships_created": len(relationships),
                },
                execution_time_ms=(time.time() - start_time) * 1000,
            )
            
        except Exception as e:
            return PipelineResult(
                pipeline_id=pipeline_id,
                stage=PipelineStage.GRAPH_BUILD,
                status="failed",
                data_id=data.data_id,
                errors=[str(e)],
                execution_time_ms=(time.time() - start_time) * 1000,
            )
    
    def _extract_entities_from_content(self, content: Any) -> List[Any]:
        """Extract entities dari content."""
        # Placeholder - seharusnya menggunakan graph_builder entities
        return []
    
    def _extract_relationships_from_content(
        self, 
        content: Any, 
        entities: List[Any]
    ) -> List[Any]:
        """Extract relationships dari content."""
        # Placeholder - seharusnya menggunakan graph_builder relationships
        return []
    
    async def _stage_confidence_scoring(
        self,
        data: RawData,
        pipeline_id: str,
        product: IntelligenceProduct,
    ) -> PipelineResult:
        """Score confidence untuk entities dan findings."""
        start_time = time.time()
        
        try:
            if not self._confidence_engine:
                return PipelineResult(
                    pipeline_id=pipeline_id,
                    stage=PipelineStage.CONFIDENCE_SCORING,
                    status="partial",
                    data_id=data.data_id,
                    warnings=["ConfidenceEngine not available"],
                    execution_time_ms=(time.time() - start_time) * 1000,
                )
            
            # Score source reliability
            source_score = self._confidence_engine.score_source(
                reliability=data.metadata.reliability,
                credibility=data.metadata.credibility,
                corroboration=0.5,  # Placeholder
            )
            
            # Score entities
            entity_scores = {}
            for entity in product.entities:
                entity_id = entity.get("id", "unknown")
                score = self._confidence_engine.score_entity(
                    entity_data=entity,
                    source_reliability=data.metadata.reliability,
                )
                entity_scores[entity_id] = score.overall if hasattr(score, 'overall') else 0.5
            
            scores = {
                "source_confidence": source_score.overall if hasattr(source_score, 'overall') else 0.5,
                "entity_scores": entity_scores,
                "overall_confidence": sum(entity_scores.values()) / max(len(entity_scores), 1),
            }
            
            return PipelineResult(
                pipeline_id=pipeline_id,
                stage=PipelineStage.CONFIDENCE_SCORING,
                status="success",
                data_id=data.data_id,
                output=scores,
                execution_time_ms=(time.time() - start_time) * 1000,
            )
            
        except Exception as e:
            return PipelineResult(
                pipeline_id=pipeline_id,
                stage=PipelineStage.CONFIDENCE_SCORING,
                status="failed",
                data_id=data.data_id,
                errors=[str(e)],
                execution_time_ms=(time.time() - start_time) * 1000,
            )
    
    async def _stage_anomaly_detection(
        self,
        data: RawData,
        pipeline_id: str,
        product: IntelligenceProduct,
    ) -> PipelineResult:
        """Detect anomalies dalam data dan graph."""
        start_time = time.time()
        
        try:
            if not self._anomaly_detector:
                return PipelineResult(
                    pipeline_id=pipeline_id,
                    stage=PipelineStage.ANOMALY_DETECTION,
                    status="partial",
                    data_id=data.data_id,
                    warnings=["AnomalyDetector not available"],
                    execution_time_ms=(time.time() - start_time) * 1000,
                )
            
            anomalies = []
            
            # Detect behavioral anomalies
            behavioral = self._anomaly_detector.detect_behavioral_anomalies(
                entities=product.entities,
                relationships=product.relationships,
            )
            anomalies.extend(behavioral)
            
            # Detect temporal anomalies
            temporal = self._anomaly_detector.detect_temporal_anomalies(
                timeline_data=data.content if isinstance(data.content, list) else [],
            )
            anomalies.extend(temporal)
            
            # Detect network anomalies
            network = self._anomaly_detector.detect_network_anomalies(
                graph_data={
                    "entities": product.entities,
                    "relationships": product.relationships,
                }
            )
            anomalies.extend(network)
            
            # Filter by threshold
            significant_anomalies = [
                a for a in anomalies 
                if (a.score if hasattr(a, 'score') else 0) >= self.config.anomaly_threshold
            ]
            
            # Publish events untuk significant anomalies
            for anomaly in significant_anomalies:
                self.event_bus.publish(Event(
                    "anomaly.detected",
                    {
                        "anomaly_type": anomaly.anomaly_type if hasattr(anomaly, 'anomaly_type') else "unknown",
                        "description": anomaly.description if hasattr(anomaly, 'description') else str(anomaly),
                        "score": anomaly.score if hasattr(anomaly, 'score') else 0,
                    }
                ))
            
            anomaly_data = [
                {
                    "type": a.anomaly_type if hasattr(a, 'anomaly_type') else "unknown",
                    "description": a.description if hasattr(a, 'description') else str(a),
                    "score": a.score if hasattr(a, 'score') else 0,
                    "entities_involved": a.entities_involved if hasattr(a, 'entities_involved') else [],
                }
                for a in significant_anomalies
            ]
            
            return PipelineResult(
                pipeline_id=pipeline_id,
                stage=PipelineStage.ANOMALY_DETECTION,
                status="success",
                data_id=data.data_id,
                output=anomaly_data,
                metrics={
                    "total_anomalies": len(anomalies),
                    "significant_anomalies": len(significant_anomalies),
                },
                execution_time_ms=(time.time() - start_time) * 1000,
            )
            
        except Exception as e:
            return PipelineResult(
                pipeline_id=pipeline_id,
                stage=PipelineStage.ANOMALY_DETECTION,
                status="failed",
                data_id=data.data_id,
                errors=[str(e)],
                execution_time_ms=(time.time() - start_time) * 1000,
            )
    
    async def _stage_hypothesis_generation(
        self,
        data: RawData,
        pipeline_id: str,
        product: IntelligenceProduct,
    ) -> PipelineResult:
        """Generate hypotheses berdasarkan findings."""
        start_time = time.time()
        
        try:
            if not self._hypothesis_generator:
                return PipelineResult(
                    pipeline_id=pipeline_id,
                    stage=PipelineStage.HYPOTHESIS_GENERATION,
                    status="partial",
                    data_id=data.data_id,
                    warnings=["HypothesisGenerator not available"],
                    execution_time_ms=(time.time() - start_time) * 1000,
                )
            
            # Generate hypotheses dari anomalies dan patterns
            hypotheses = self._hypothesis_generator.generate_from_findings(
                entities=product.entities,
                relationships=product.relationships,
                anomalies=product.anomalies,
                confidence_scores=product.confidence_scores,
            )
            
            # Rank hypotheses
            ranked = self._hypothesis_generator.rank_hypotheses(hypotheses)
            
            # Publish events untuk high priority hypotheses
            for hyp in ranked:
                priority = hyp.priority if hasattr(hyp, 'priority') else "medium"
                if priority in ["critical", "high"]:
                    self.event_bus.publish(Event(
                        "hypothesis.generated",
                        {
                            "title": hyp.title if hasattr(hyp, 'title') else str(hyp),
                            "priority": priority,
                            "confidence": hyp.confidence if hasattr(hyp, 'confidence') else 0,
                        }
                    ))
            
            hypothesis_data = [
                {
                    "id": hyp.id if hasattr(hyp, 'id') else str(i),
                    "title": hyp.title if hasattr(hyp, 'title') else str(hyp),
                    "description": hyp.description if hasattr(hyp, 'description') else "",
                    "priority": hyp.priority if hasattr(hyp, 'priority') else "medium",
                    "confidence": hyp.confidence if hasattr(hyp, 'confidence') else 0,
                    "evidence": hyp.evidence if hasattr(hyp, 'evidence') else [],
                }
                for i, hyp in enumerate(ranked)
            ]
            
            return PipelineResult(
                pipeline_id=pipeline_id,
                stage=PipelineStage.HYPOTHESIS_GENERATION,
                status="success",
                data_id=data.data_id,
                output=hypothesis_data,
                metrics={
                    "total_hypotheses": len(hypotheses),
                    "high_priority": len([h for h in ranked if (h.priority if hasattr(h, 'priority') else "") in ["critical", "high"]]),
                },
                execution_time_ms=(time.time() - start_time) * 1000,
            )
            
        except Exception as e:
            return PipelineResult(
                pipeline_id=pipeline_id,
                stage=PipelineStage.HYPOTHESIS_GENERATION,
                status="failed",
                data_id=data.data_id,
                errors=[str(e)],
                execution_time_ms=(time.time() - start_time) * 1000,
            )
    
    async def _stage_report_generation(
        self,
        data: RawData,
        pipeline_id: str,
        product: IntelligenceProduct,
    ) -> PipelineResult:
        """Generate narrative intelligence report."""
        start_time = time.time()
        
        try:
            if not self._report_generator:
                return PipelineResult(
                    pipeline_id=pipeline_id,
                    stage=PipelineStage.REPORT_GENERATION,
                    status="partial",
                    data_id=data.data_id,
                    warnings=["NarrativeReportGenerator not available"],
                    execution_time_ms=(time.time() - start_time) * 1000,
                )
            
            # Prepare report data
            report_data = {
                "case_id": product.case_id,
                "title": product.title,
                "entities": product.entities,
                "relationships": product.relationships,
                "timeline": self._build_timeline_from_data(data),
                "anomalies": product.anomalies,
                "hypotheses": product.hypotheses,
                "confidence_scores": product.confidence_scores,
                "source_metadata": data.metadata.to_dict(),
            }
            
            # Generate report
            report = self._report_generator.generate_full_report(report_data)
            
            # Export ke multiple formats
            exports = {}
            if hasattr(self._report_generator, 'export_markdown'):
                exports["markdown"] = self._report_generator.export_markdown(report)
            if hasattr(self._report_generator, 'export_html'):
                exports["html"] = self._report_generator.export_html(report)
            if hasattr(self._report_generator, 'export_json'):
                exports["json"] = self._report_generator.export_json(report)
            
            return PipelineResult(
                pipeline_id=pipeline_id,
                stage=PipelineStage.REPORT_GENERATION,
                status="success",
                data_id=data.data_id,
                output={
                    "report": exports.get("markdown", str(report)),
                    "format": "markdown",
                    "available_formats": list(exports.keys()),
                    "sections_generated": len(report.sections) if hasattr(report, 'sections') else 0,
                },
                execution_time_ms=(time.time() - start_time) * 1000,
            )
            
        except Exception as e:
            return PipelineResult(
                pipeline_id=pipeline_id,
                stage=PipelineStage.REPORT_GENERATION,
                status="failed",
                data_id=data.data_id,
                errors=[str(e)],
                execution_time_ms=(time.time() - start_time) * 1000,
            )
    
    def _build_timeline_from_data(self, data: RawData) -> List[Dict[str, Any]]:
        """Build timeline events dari data."""
        timeline = []
        if isinstance(data.content, dict) and "events" in data.content:
            timeline = data.content["events"]
        elif isinstance(data.content, list):
            for item in data.content:
                if isinstance(item, dict) and "timestamp" in item:
                    timeline.append(item)
        return timeline
    
    async def _stage_export(
        self,
        data: RawData,
        pipeline_id: str,
        product: IntelligenceProduct,
    ) -> PipelineResult:
        """Export intelligence product ke berbagai formats."""
        start_time = time.time()
        export_paths = {}
        
        try:
            # Export graph
            if self._graph_exporter:
                try:
                    graph_path = f"/tmp/catherine_{product.case_id}_graph.json"
                    self._graph_exporter.export(
                        format=ExportFormat.JSON,
                        output_path=graph_path,
                    )
                    export_paths["graph_json"] = graph_path
                except Exception as e:
                    logger.warning(f"Graph export failed: {e}")
            
            # Export Maltego
            if self._maltego_exporter:
                try:
                    maltego_path = f"/tmp/catherine_{product.case_id}_maltego.mtgx"
                    self._maltego_exporter.export(maltego_path)
                    export_paths["maltego"] = maltego_path
                except Exception as e:
                    logger.warning(f"Maltego export failed: {e}")
            
            # Export report
            if product.final_report:
                report_path = f"/tmp/catherine_{product.case_id}_report.md"
                with open(report_path, "w") as f:
                    f.write(product.final_report)
                export_paths["report_markdown"] = report_path
            
            product.export_paths = export_paths
            
            return PipelineResult(
                pipeline_id=pipeline_id,
                stage=PipelineStage.EXPORT,
                status="success",
                data_id=data.data_id,
                output={"export_paths": export_paths},
                execution_time_ms=(time.time() - start_time) * 1000,
            )
            
        except Exception as e:
            return PipelineResult(
                pipeline_id=pipeline_id,
                stage=PipelineStage.EXPORT,
                status="partial",
                data_id=data.data_id,
                warnings=[str(e)],
                execution_time_ms=(time.time() - start_time) * 1000,
            )
    
    # -------------------------------------------------------------------------
    # Visualization & Export Methods
    # -------------------------------------------------------------------------
    
    def visualize_graph(
        self,
        output_path: Optional[str] = None,
        config: Optional[VisualizationConfig] = None,
    ) -> str:
        """
        Generate graph visualization.
        
        Args:
            output_path: Path untuk output file
            config: Visualization configuration
        
        Returns:
            Path ke generated visualization
        """
        if not self._visualizer:
            raise RuntimeError("GraphVisualizer not available")
        
        output_path = output_path or f"/tmp/catherine_graph_{int(time.time())}.html"
        self._visualizer.render(output_path=output_path, config=config)
        return output_path
    
    def export_to_maltego(self, output_path: str) -> str:
        """Export graph ke Maltego format."""
        if not self._maltego_exporter:
            raise RuntimeError("MaltegoExporter not available")
        
        self._maltego_exporter.export(output_path)
        return output_path
    
    # -------------------------------------------------------------------------
    # Query & Search Methods
    # -------------------------------------------------------------------------
    
    def query_entities(
        self,
        entity_type: Optional[str] = None,
        properties: Optional[Dict[str, Any]] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Query entities dari graph database."""
        if not self._neo4j_connector:
            raise RuntimeError("Neo4jConnector not available")
        
        # Build query
        query = "MATCH (e:Entity) "
        params = {}
        
        if entity_type:
            query += "WHERE e.type = $entity_type "
            params["entity_type"] = entity_type
        
        if properties:
            for key, value in properties.items():
                query += f"AND e.{key} = ${key} "
                params[key] = value
        
        query += f"RETURN e LIMIT {limit}"
        
        # Execute
        with self._neo4j_connector.session() as session:
            result = session.run(query, params)
            return [record["e"] for record in result]
    
    def find_paths(
        self,
        source_id: str,
        target_id: str,
        max_depth: int = 4,
    ) -> List[List[Dict[str, Any]]]:
        """Find paths antara dua entities."""
        if not self._neo4j_connector:
            raise RuntimeError("Neo4jConnector not available")
        
        query = """
        MATCH path = (source:Entity {id: $source_id})-[:RELATES_TO*1..%d]->(target:Entity {id: $target_id})
        RETURN path
        LIMIT 10
        """ % max_depth
        
        with self._neo4j_connector.session() as session:
            result = session.run(query, {"source_id": source_id, "target_id": target_id})
            paths = []
            for record in result:
                path = record["path"]
                paths.append([
                    {
                        "node": node.get("id", str(node)),
                        "type": node.get("type", "unknown"),
                    }
                    for node in path.nodes
                ])
            return paths
    
    # -------------------------------------------------------------------------
    # Monitoring & Statistics
    # -------------------------------------------------------------------------
    
    def get_status(self) -> Dict[str, Any]:
        """Get current orchestrator status."""
        return {
            "initialized": self._initialized,
            "running": self._running,
            "mode": self.config.mode.value,
            "active_pipelines": len(self._active_pipelines),
            "modules_available": MODULES_AVAILABLE,
            "modules_loaded": {
                "neo4j_connector": self._neo4j_connector is not None,
                "graph_builder": self._graph_builder is not None,
                "graph_exporter": self._graph_exporter is not None,
                "maltego_exporter": self._maltego_exporter is not None,
                "visualizer": self._visualizer is not None,
                "confidence_engine": self._confidence_engine is not None,
                "anomaly_detector": self._anomaly_detector is not None,
                "hypothesis_generator": self._hypothesis_generator is not None,
                "report_generator": self._report_generator is not None,
            },
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get pipeline statistics."""
        uptime = datetime.utcnow() - self._stats["start_time"]
        return {
            **self._stats,
            "uptime_seconds": uptime.total_seconds(),
            "uptime_formatted": str(uptime).split(".")[0],
            "success_rate": (
                self._stats["successful_pipelines"] / max(self._stats["total_pipelines"], 1)
            ),
            "active_pipeline_ids": list(self._active_pipelines.keys()),
        }
    
    def get_active_pipelines(self) -> Dict[str, Dict[str, Any]]:
        """Get currently running pipelines."""
        return self._active_pipelines.copy()
    
    # -------------------------------------------------------------------------
    # Configuration Management
    # -------------------------------------------------------------------------
    
    def update_config(self, config: OrchestratorConfig) -> None:
        """Update orchestrator configuration."""
        self.config = config
        self._pipeline_semaphore = asyncio.Semaphore(config.max_concurrent_pipelines)
        self.cache = ResultCache(config.cache_ttl_seconds)
        logger.info("Orchestrator configuration updated")
    
    def export_config(self, path: str) -> None:
        """Export configuration ke file."""
        with open(path, "w") as f:
            json.dump(self.config.to_dict(), f, indent=2, default=str)
        logger.info(f"Configuration exported to {path}")
    
    @classmethod
    def from_config_file(cls, path: str) -> "IntelligenceOrchestrator":
        """Load orchestrator dari config file."""
        with open(path, "r") as f:
            config_dict = json.load(f)
        
        # Parse config
        config = OrchestratorConfig(
            mode=OrchestratorMode(config_dict.get("mode", "hybrid")),
            max_concurrent_pipelines=config_dict.get("max_concurrent_pipelines", 5),
            enable_caching=config_dict.get("enable_caching", True),
            cache_ttl_seconds=config_dict.get("cache_ttl_seconds", 3600),
            enable_anomaly_detection=config_dict.get("enable_anomaly_detection", True),
            enable_hypothesis_generation=config_dict.get("enable_hypothesis_generation", True),
            enable_auto_report=config_dict.get("enable_auto_report", True),
            confidence_threshold=config_dict.get("confidence_threshold", 0.6),
            anomaly_threshold=config_dict.get("anomaly_threshold", 0.7),
        )
        
        return cls(config)


# ============================================================================
# Pipeline Error
# ============================================================================

class PipelineError(Exception):
    """Exception untuk pipeline errors."""
    pass


# ============================================================================
# Convenience Functions
# ============================================================================

async def run_intelligence_pipeline(
    content: Any,
    source_type: str = "manual",
    source_name: str = "Manual Input",
    case_id: str = "",
    config: Optional[OrchestratorConfig] = None,
) -> IntelligenceProduct:
    """
    Convenience function untuk run complete pipeline dalam satu call.
    
    Args:
        content: Data content
        source_type: Type of source
        source_name: Source name
        case_id: Case ID
        config: Optional orchestrator config
    
    Returns:
        IntelligenceProduct
    """
    orchestrator = IntelligenceOrchestrator(config=config)
    orchestrator.initialize()
    
    try:
        metadata = SourceMetadata(
            source_id=f"src_{int(time.time())}",
            source_type=source_type,
            source_name=source_name,
        )
        
        data = await orchestrator.ingest_data(content, metadata)
        product = await orchestrator.run_pipeline(data, case_id=case_id)
        
        return product
        
    finally:
        orchestrator.shutdown()


# ============================================================================
# CLI Interface
# ============================================================================

def main():
    """CLI entry point untuk testing."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Catherine Intelligence Orchestrator")
    parser.add_argument("--config", "-c", help="Path to config file")
    parser.add_argument("--mode", "-m", choices=["realtime", "batch", "hybrid"], default="hybrid")
    parser.add_argument("--ingest", "-i", help="Ingest data from file")
    parser.add_argument("--case-id", help="Case ID")
    parser.add_argument("--export", "-e", help="Export path")
    parser.add_argument("--visualize", "-v", action="store_true", help="Generate visualization")
    parser.add_argument("--stats", "-s", action="store_true", help="Show statistics")
    
    args = parser.parse_args()
    
    # Load config
    if args.config:
        orchestrator = IntelligenceOrchestrator.from_config_file(args.config)
    else:
        config = OrchestratorConfig(mode=OrchestratorMode(args.mode))
        orchestrator = IntelligenceOrchestrator(config=config)
    
    if args.stats:
        print(json.dumps(orchestrator.get_statistics(), indent=2))
        return
    
    orchestrator.initialize()
    
    try:
        if args.ingest:
            with open(args.ingest, "r") as f:
                content = json.load(f)
            
            metadata = SourceMetadata(
                source_id=f"file_{args.ingest}",
                source_type="file",
                source_name=args.ingest,
            )
            
            async def run():
                data = await orchestrator.ingest_data(content, metadata)
                product = await orchestrator.run_pipeline(
                    data, 
                    case_id=args.case_id or f"CLI-{int(time.time())}"
                )
                
                print(f"\n{'='*60}")
                print(f"Pipeline Complete: {product.product_id}")
                print(f"Case ID: {product.case_id}")
                print(f"Status: {'SUCCESS' if not product.pipeline_results[-1].errors else 'PARTIAL'}")
                print(f"Entities: {len(product.entities)}")
                print(f"Relationships: {len(product.relationships)}")
                print(f"Anomalies: {len(product.anomalies)}")
                print(f"Hypotheses: {len(product.hypotheses)}")
                print(f"{'='*60}")
                
                if args.export and product.final_report:
                    with open(args.export, "w") as f:
                        f.write(product.final_report)
                    print(f"Report exported to: {args.export}")
                
                if args.visualize:
                    viz_path = orchestrator.visualize_graph()
                    print(f"Visualization: {viz_path}")
            
            asyncio.run(run())
        
        else:
            print(f"Catherine Intelligence Orchestrator v4.0.0")
            print(f"Status: {json.dumps(orchestrator.get_status(), indent=2)}")
            print(f"\nUse --ingest <file> to process data")
    
    finally:
        orchestrator.shutdown()


if __name__ == "__main__":
    main()