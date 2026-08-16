"""
face_correlation.py - Advanced Face Correlation & Analysis Module
Part of OSINT Intelligence Platform v3
"""

import os
import io
import json
import base64
import hashlib
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, Set
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum
import asyncio
import aiohttp
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

# Image processing
import cv2
import numpy as np
from PIL import Image, ExifTags
import face_recognition

# Utilities
import exifread
from bs4 import BeautifulSoup
import dlib

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class CorrelationLevel(Enum):
    """Face correlation confidence levels."""
    EXACT = "exact"           # 99-100% match
    HIGH = "high"             # 90-99% match
    MEDIUM = "medium"         # 70-90% match
    LOW = "low"               # 50-70% match
    NO_MATCH = "no_match"     # <50% match


@dataclass
class FaceMetadata:
    """Metadata extracted from a face image."""
    filename: str
    file_hash: str
    dimensions: Tuple[int, int]
    format: str
    file_size: int
    capture_date: Optional[str] = None
    camera_info: Optional[Dict] = None
    gps_coordinates: Optional[Tuple[float, float]] = None
    software: Optional[str] = None
    created_at: str = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now().isoformat()


@dataclass
class FaceEncoding:
    """Face encoding data for recognition."""
    encoding: np.ndarray
    face_location: Tuple[int, int, int, int]
    face_image: np.ndarray
    confidence: float


@dataclass
class FaceMatch:
    """Face match result."""
    source_face_id: str
    target_face_id: str
    similarity_score: float
    correlation_level: CorrelationLevel
    matching_features: List[str]
    match_details: Dict


@dataclass
class CorrelationResult:
    """Complete correlation analysis result."""
    query_image_path: str
    query_face_count: int
    matched_faces: List[FaceMatch]
    metadata: FaceMetadata
    search_sources: List[str]
    processing_time: float
    timestamp: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        result = asdict(self)
        result['correlation_level'] = {
            match.correlation_level.value for match in self.matched_faces
        }
        return result


class FaceCorrelationEngine:
    """
    Advanced face correlation engine for OSINT investigations.
    Supports face recognition, reverse image search, and metadata analysis.
    """
    
    # Known face encodings database (in-memory for demo, use DB in production)
    _known_faces_db: Dict[str, Dict] = {}
    
    # Reverse image search APIs
    REVERSE_SEARCH_APIS = {
        'google_lens': 'https://lens.google.com/upload',
        'tineye': 'https://tineye.com/search',
        'yandex': 'https://yandex.com/images/search',
        'bing_visual': 'https://www.bing.com/images/search?view=detailv2'
    }
    
    def __init__(self, 
                 tolerance: float = 0.6,
                 model: str = "hog",
                 num_jitters: int = 1,
                 db_path: Optional[str] = None):
        """
        Initialize face correlation engine.
        
        Args:
            tolerance: Face matching tolerance (lower = stricter)
            model: Detection model ('hog' or 'cnn')
            num_jitters: Number of jitter passes for encoding
            db_path: Path to face database directory
        """
        self.tolerance = tolerance
        self.model = model
        self.num_jitters = num_jitters
        self.db_path = db_path or os.path.expanduser("~/.osint/faces_db")
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Ensure database directory exists
        os.makedirs(self.db_path, exist_ok=True)
        
        # Load existing database
        self._load_database()
        
        logger.info(f"FaceCorrelationEngine initialized (model={model}, tolerance={tolerance})")
    
    def _load_database(self):
        """Load face database from disk."""
        db_file = os.path.join(self.db_path, "faces_db.json")
        if os.path.exists(db_file):
            try:
                with open(db_file, 'r') as f:
                    data = json.load(f)
                    for face_id, face_data in data.items():
                        face_data['encoding'] = np.array(face_data['encoding'])
                        self._known_faces_db[face_id] = face_data
                logger.info(f"Loaded {len(self._known_faces_db)} faces from database")
            except Exception as e:
                logger.error(f"Error loading face database: {e}")
    
    def _save_database(self):
        """Save face database to disk."""
        db_file = os.path.join(self.db_path, "faces_db.json")
        try:
            save_data = {}
            for face_id, face_data in self._known_faces_db.items():
                save_data[face_id] = {
                    **face_data,
                    'encoding': face_data['encoding'].tolist()
                }
            with open(db_file, 'w') as f:
                json.dump(save_data, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving face database: {e}")
    
    def extract_metadata(self, image_path: str) -> FaceMetadata:
        """
        Extract comprehensive metadata from image file.
        
        Args:
            image_path: Path to image file
            
        Returns:
            FaceMetadata object with extracted information
        """
        path = Path(image_path)
        
        if not path.exists():
            raise FileNotFoundError(f"Image not found: {image_path}")
        
        # Basic file info
        file_hash = self._calculate_file_hash(image_path)
        file_size = path.stat().st_size
        
        # Open with PIL for basic info
        with Image.open(image_path) as img:
            dimensions = img.size
            img_format = img.format or "Unknown"
        
        # EXIF data extraction
        capture_date = None
        camera_info = {}
        gps_coords = None
        software = None
        
        try:
            with open(image_path, 'rb') as f:
                exif = exifread.process_file(f, details=False)
                
                # Date/Time
                if 'EXIF DateTimeOriginal' in exif:
                    capture_date = str(exif['EXIF DateTimeOriginal'])
                elif 'Image DateTime' in exif:
                    capture_date = str(exif['Image DateTime'])
                
                # Camera info
                if 'Image Make' in exif:
                    camera_info['make'] = str(exif['Image Make'])
                if 'Image Model' in exif:
                    camera_info['model'] = str(exif['Image Model'])
                if 'EXIF LensModel' in exif:
                    camera_info['lens'] = str(exif['EXIF LensModel'])
                
                # Software
                if 'Image Software' in exif:
                    software = str(exif['Image Software'])
                
                # GPS coordinates
                gps_coords = self._extract_gps(exif)
                
        except Exception as e:
            logger.warning(f"Error extracting EXIF from {image_path}: {e}")
        
        # Clean up empty values
        camera_info = camera_info if camera_info else None
        
        return FaceMetadata(
            filename=path.name,
            file_hash=file_hash,
            dimensions=dimensions,
            format=img_format,
            file_size=file_size,
            capture_date=capture_date,
            camera_info=camera_info,
            gps_coordinates=gps_coords,
            software=software
        )
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of file."""
        hash_sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    
    def _extract_gps(self, exif: Dict) -> Optional[Tuple[float, float]]:
        """Extract GPS coordinates from EXIF data."""
        try:
            if 'GPS GPSLatitude' in exif and 'GPS GPSLongitude' in exif:
                lat = self._convert_gps(exif['GPS GPSLatitude'], exif.get('GPS GPSLatitudeRef'))
                lon = self._convert_gps(exif['GPS GPSLongitude'], exif.get('GPS GPSLongitudeRef'))
                return (lat, lon)
        except Exception as e:
            logger.warning(f"GPS extraction error: {e}")
        return None
    
    def _convert_gps(self, coord, ref) -> float:
        """Convert GPS coordinate to decimal degrees."""
        degrees = float(coord.values[0])
        minutes = float(coord.values[1])
        seconds = float(coord.values[2])
        
        decimal = degrees + minutes / 60 + seconds / 3600
        
        if ref and str(ref) in ['S', 'W']:
            decimal = -decimal
            
        return decimal
    
    def detect_faces(self, image_path: str) -> List[FaceEncoding]:
        """
        Detect and encode faces in image.
        
        Args:
            image_path: Path to image file
            
        Returns:
            List of FaceEncoding objects
        """
        # Load image
        image = face_recognition.load_image_file(image_path)
        
        # Detect face locations
        face_locations = face_recognition.face_locations(image, model=self.model)
        
        if not face_locations:
            logger.warning(f"No faces detected in {image_path}")
            return []
        
        # Get face encodings
        face_encodings = face_recognition.face_encodings(
            image, 
            face_locations, 
            num_jitters=self.num_jitters
        )
        
        face_objects = []
        for i, (encoding, location) in enumerate(zip(face_encodings, face_locations)):
            # Extract face image
            top, right, bottom, left = location
            face_image = image[top:bottom, left:right]
            
            # Calculate confidence (based on face size relative to image)
            face_area = (bottom - top) * (right - left)
            image_area = image.shape[0] * image.shape[1]
            confidence = min(face_area / image_area * 10, 1.0)  # Normalize
            
            face_objects.append(FaceEncoding(
                encoding=encoding,
                face_location=location,
                face_image=face_image,
                confidence=confidence
            ))
        
        logger.info(f"Detected {len(face_objects)} face(s) in {image_path}")
        return face_objects
    
    def compare_faces(self, 
                     face_encoding1: np.ndarray, 
                     face_encoding2: np.ndarray) -> Tuple[float, CorrelationLevel]:
        """
        Compare two face encodings and return similarity.
        
        Args:
            face_encoding1: First face encoding
            face_encoding2: Second face encoding
            
        Returns:
            Tuple of (similarity_score, correlation_level)
        """
        # Calculate face distance (lower = more similar)
        distance = face_recognition.face_distance([face_encoding1], [face_encoding2])[0]
        
        # Convert to similarity score (0-1)
        similarity = 1 - distance
        
        # Determine correlation level
        if similarity >= 0.99:
            level = CorrelationLevel.EXACT
        elif similarity >= 0.90:
            level = CorrelationLevel.HIGH
        elif similarity >= 0.70:
            level = CorrelationLevel.MEDIUM
        elif similarity >= 0.50:
            level = CorrelationLevel.LOW
        else:
            level = CorrelationLevel.NO_MATCH
        
        return similarity, level
    
    def add_face_to_database(self, 
                            image_path: str, 
                            person_id: str,
                            person_name: Optional[str] = None,
                            source: Optional[str] = None,
                            tags: Optional[List[str]] = None) -> Dict:
        """
        Add a face to the known faces database.
        
        Args:
            image_path: Path to face image
            person_id: Unique identifier for person
            person_name: Optional person name
            source: Optional data source
            tags: Optional tags
            
        Returns:
            Dictionary with face registration info
        """
        # Detect faces
        faces = self.detect_faces(image_path)
        
        if not faces:
            return {
                'success': False,
                'error': 'No faces detected in image',
                'person_id': person_id
            }
        
        # Use the first/largest face
        primary_face = max(faces, key=lambda f: f.confidence)
        
        # Generate face ID
        face_id = hashlib.sha256(
            f"{person_id}_{primary_face.encoding.tobytes()}".encode()
        ).hexdigest()[:16]
        
        # Extract metadata
        metadata = self.extract_metadata(image_path)
        
        # Save face image to database
        face_dir = os.path.join(self.db_path, person_id)
        os.makedirs(face_dir, exist_ok=True)
        
        face_image_path = os.path.join(face_dir, f"{face_id}.jpg")
        Image.fromarray(primary_face.face_image).save(face_image_path)
        
        # Store in database
        self._known_faces_db[face_id] = {
            'face_id': face_id,
            'person_id': person_id,
            'person_name': person_name,
            'encoding': primary_face.encoding,
            'metadata': asdict(metadata),
            'source': source,
            'tags': tags or [],
            'registered_at': datetime.now().isoformat(),
            'image_path': face_image_path
        }
        
        # Save database
        self._save_database()
        
        logger.info(f"Added face {face_id} for person {person_id}")
        
        return {
            'success': True,
            'face_id': face_id,
            'person_id': person_id,
            'person_name': person_name,
            'confidence': primary_face.confidence,
            'metadata': asdict(metadata)
        }
    
    def search_database(self, 
                       image_path: str,
                       top_k: int = 5) -> List[Dict]:
        """
        Search for matching faces in the database.
        
        Args:
            image_path: Query image path
            top_k: Number of top matches to return
            
        Returns:
            List of match results
        """
        # Detect faces in query
        query_faces = self.detect_faces(image_path)
        
        if not query_faces:
            return []
        
        query_face = query_faces[0]  # Use primary face
        query_encoding = query_face.encoding
        
        # Compare with all known faces
        matches = []
        
        for face_id, face_data in self._known_faces_db.items():
            similarity, level = self.compare_faces(
                query_encoding, 
                face_data['encoding']
            )
            
            if level != CorrelationLevel.NO_MATCH:
                matches.append({
                    'face_id': face_id,
                    'person_id': face_data['person_id'],
                    'person_name': face_data.get('person_name'),
                    'similarity_score': round(similarity, 4),
                    'correlation_level': level.value,
                    'source': face_data.get('source'),
                    'tags': face_data.get('tags', []),
                    'registered_at': face_data.get('registered_at')
                })
        
        # Sort by similarity (descending)
        matches.sort(key=lambda x: x['similarity_score'], reverse=True)
        
        return matches[:top_k]
    
    async def reverse_image_search(self, 
                                    image_path: str,
                                    engines: Optional[List[str]] = None) -> Dict:
        """
        Perform reverse image search across multiple engines.
        
        Note: This is a simulation/template. Real implementations require
        API keys or web scraping with proper handling.
        
        Args:
            image_path: Path to query image
            engines: List of search engines to use
            
        Returns:
            Dictionary with search results from each engine
        """
        engines = engines or ['tineye', 'yandex']
        results = {}
        
        # Read image data
        with open(image_path, 'rb') as f:
            image_data = f.read()
        
        async with aiohttp.ClientSession() as session:
            tasks = []
            
            for engine in engines:
                if engine in self.REVERSE_SEARCH_APIS:
                    task = self._search_engine(session, engine, image_data)
                    tasks.append((engine, task))
            
            for engine, task in tasks:
                try:
                    result = await asyncio.wait_for(task, timeout=30)
                    results[engine] = result
                except Exception as e:
                    results[engine] = {
                        'status': 'error',
                        'error': str(e)
                    }
        
        return {
            'query_image': image_path,
            'engines_searched': engines,
            'results': results,
            'timestamp': datetime.now().isoformat()
        }
    
    async def _search_engine(self, 
                            session: aiohttp.ClientSession,
                            engine: str,
                            image_data: bytes) -> Dict:
        """
        Search specific engine (template method).
        
        Note: Actual implementation requires API keys and proper rate limiting.
        """
        # This is a template - real implementation needs API integration
        return {
            'status': 'not_implemented',
            'message': f'Reverse search for {engine} requires API integration',
            'note': 'Use official APIs: Google Vision, Azure Face, AWS Rekognition'
        }
    
    def correlate_faces(self, 
                       image_path: str,
                       search_database: bool = True,
                       extract_metadata: bool = True,
                       reverse_search: bool = False) -> CorrelationResult:
        """
        Perform complete face correlation analysis.
        
        Args:
            image_path: Path to query image
            search_database: Whether to search known faces database
            extract_metadata: Whether to extract image metadata
            reverse_search: Whether to perform reverse image search
            
        Returns:
            CorrelationResult with complete analysis
        """
        import time
        start_time = time.time()
        
        # Step 1: Detect faces
        faces = self.detect_faces(image_path)
        
        # Step 2: Extract metadata
        metadata = None
        if extract_metadata:
            try:
                metadata = self.extract_metadata(image_path)
            except Exception as e:
                logger.error(f"Metadata extraction failed: {e}")
        
        # Step 3: Search database
        matched_faces = []
        if search_database and faces:
            query_face = faces[0]
            
            for face_id, face_data in self._known_faces_db.items():
                similarity, level = self.compare_faces(
                    query_face.encoding,
                    face_data['encoding']
                )
                
                if level != CorrelationLevel.NO_MATCH:
                    matched_faces.append(FaceMatch(
                        source_face_id="query",
                        target_face_id=face_id,
                        similarity_score=similarity,
                        correlation_level=level,
                        matching_features=['facial_structure', 'encoding_similarity'],
                        match_details={
                            'person_id': face_data['person_id'],
                            'person_name': face_data.get('person_name'),
                            'source': face_data.get('source')
                        }
                    ))
        
        # Sort matches by similarity
        matched_faces.sort(key=lambda x: x.similarity_score, reverse=True)
        
        # Step 4: Reverse image search (async)
        search_sources = []
        if reverse_search:
            try:
                loop = asyncio.get_event_loop()
                reverse_results = loop.run_until_complete(
                    self.reverse_image_search(image_path)
                )
                search_sources = list(reverse_results['results'].keys())
            except Exception as e:
                logger.error(f"Reverse search failed: {e}")
        
        processing_time = time.time() - start_time
        
        return CorrelationResult(
            query_image_path=image_path,
            query_face_count=len(faces),
            matched_faces=matched_faces,
            metadata=metadata,
            search_sources=search_sources,
            processing_time=processing_time
        )
    
    def batch_correlate(self, 
                       image_paths: List[str],
                       max_workers: int = 4) -> List[CorrelationResult]:
        """
        Correlate multiple images in parallel.
        
        Args:
            image_paths: List of image paths
            max_workers: Maximum parallel workers
            
        Returns:
            List of CorrelationResult objects
        """
        results = []
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_path = {
                executor.submit(self.correlate_faces, path): path 
                for path in image_paths
            }
            
            for future in as_completed(future_to_path):
                path = future_to_path[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    logger.error(f"Error processing {path}: {e}")
                    # Create error result
                    results.append(CorrelationResult(
                        query_image_path=path,
                        query_face_count=0,
                        matched_faces=[],
                        metadata=None,
                        search_sources=[],
                        processing_time=0,
                        timestamp=datetime.now().isoformat()
                    ))
        
        return results
    
    def generate_correlation_report(self, 
                                    result: CorrelationResult,
                                    output_format: str = 'json') -> Union[str, Dict]:
        """
        Generate correlation analysis report.
        
        Args:
            result: CorrelationResult to report on
            output_format: 'json', 'html', or 'markdown'
            
        Returns:
            Report in specified format
        """
        if output_format == 'json':
            return result.to_dict()
        
        elif output_format == 'markdown':
            md = f"""# Face Correlation Report

## Query Image
- **Path:** {result.query_image_path}
- **Faces Detected:** {result.query_face_count}
- **Processing Time:** {result.processing_time:.2f}s
- **Timestamp:** {result.timestamp}

## Metadata
"""
            if result.metadata:
                md += f"""- **File:** {result.metadata.filename}
- **Dimensions:** {result.metadata.dimensions[0]}x{result.metadata.dimensions[1]}
- **Format:** {result.metadata.format}
- **File Size:** {result.metadata.file_size:,} bytes
- **Capture Date:** {result.metadata.capture_date or 'Unknown'}
- **Camera:** {result.metadata.camera_info or 'Unknown'}
- **GPS:** {result.metadata.gps_coordinates or 'Not available'}
"""
            else:
                md += "- No metadata extracted\n"
            
            md += "\n## Matches Found\n"
            
            if result.matched_faces:
                for i, match in enumerate(result.matched_faces, 1):
                    md += f"""
### Match #{i}
- **Target Face ID:** {match.target_face_id}
- **Similarity Score:** {match.similarity_score:.4f}
- **Correlation Level:** {match.correlation_level.value.upper()}
- **Person:** {match.match_details.get('person_name', 'Unknown')} ({match.match_details.get('person_id', 'N/A')})
- **Source:** {match.match_details.get('source', 'Unknown')}
"""
            else:
                md += "No matches found in database.\n"
            
            md += f"\n## Search Sources\n"
            if result.search_sources:
                md += "\n".join(f"- {src}" for src in result.search_sources)
            else:
                md += "- No external searches performed"
            
            return md
        
        elif output_format == 'html':
            # Simple HTML report
            md = self.generate_correlation_report(result, 'markdown')
            # Convert markdown to basic HTML
            html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Face Correlation Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; }}
        h1 {{ color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .match {{ background: #f8f9fa; padding: 15px; margin: 10px 0; border-radius: 5px; }}
        .high {{ border-left: 4px solid #28a745; }}
        .medium {{ border-left: 4px solid #ffc107; }}
        .low {{ border-left: 4px solid #fd7e14; }}
        .exact {{ border-left: 4px solid #007bff; }}
    </style>
</head>
<body>
    <pre>{md}</pre>
</body>
</html>"""
            return html
        
        else:
            raise ValueError(f"Unsupported format: {output_format}")
    
    def cluster_faces(self, 
                     image_paths: List[str],
                     tolerance: Optional[float] = None) -> Dict[str, List[str]]:
        """
        Cluster faces by identity across multiple images.
        
        Args:
            image_paths: List of image paths
            tolerance: Clustering tolerance (default: self.tolerance)
            
        Returns:
            Dictionary mapping person_id to list of image paths
        """
        tolerance = tolerance or self.tolerance
        
        # Extract all faces
        all_faces = []
        for path in image_paths:
            faces = self.detect_faces(path)
            for face in faces:
                all_faces.append({
                    'path': path,
                    'encoding': face.encoding,
                    'location': face.face_location
                })
        
        # Simple clustering using face distance
        clusters = []
        unclustered = all_faces.copy()
        
        while unclustered:
            # Start new cluster with first unclustered face
            seed = unclustered.pop(0)
            cluster = [seed]
            
            # Find all faces matching this cluster
            i = 0
            while i < len(unclustered):
                face = unclustered[i]
                distances = face_recognition.face_distance(
                    [f['encoding'] for f in cluster],
                    [face['encoding']]
                )
                min_distance = min(distances)
                
                if min_distance <= tolerance:
                    cluster.append(face)
                    unclustered.pop(i)
                else:
                    i += 1
            
            clusters.append(cluster)
        
        # Format results
        results = {}
        for i, cluster in enumerate(clusters):
            cluster_id = f"person_{i+1}"
            results[cluster_id] = [f['path'] for f in cluster]
        
        return results
    
    def verify_identity(self, 
                       image_path1: str,
                       image_path2: str) -> Dict:
        """
        Verify if two images contain the same person.
        
        Args:
            image_path1: First image path
            image_path2: Second image path
            
        Returns:
            Verification result
        """
        faces1 = self.detect_faces(image_path1)
        faces2 = self.detect_faces(image_path2)
        
        if not faces1 or not faces2:
            return {
                'verified': False,
                'confidence': 0,
                'reason': 'No faces detected in one or both images',
                'faces_image1': len(faces1),
                'faces_image2': len(faces2)
            }
        
        # Compare primary (largest) faces
        face1 = max(faces1, key=lambda f: f.confidence)
        face2 = max(faces2, key=lambda f: f.confidence)
        
        similarity, level = self.compare_faces(face1.encoding, face2.encoding)
        
        return {
            'verified': level in [CorrelationLevel.EXACT, CorrelationLevel.HIGH],
            'confidence': similarity,
            'correlation_level': level.value,
            'same_person': level in [CorrelationLevel.EXACT, CorrelationLevel.HIGH],
            'faces_image1': len(faces1),
            'faces_image2': len(faces2),
            'recommendation': 'Same person' if level in [CorrelationLevel.EXACT, CorrelationLevel.HIGH] else 'Different person or insufficient data'
        }
    
    def export_database(self, output_path: Optional[str] = None) -> str:
        """
        Export face database to JSON file.
        
        Args:
            output_path: Output file path
            
        Returns:
            Path to exported file
        """
        output_path = output_path or os.path.join(
            self.db_path, 
            f"faces_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        
        export_data = {}
        for face_id, face_data in self._known_faces_db.items():
            export_data[face_id] = {
                **{k: v for k, v in face_data.items() if k != 'encoding'},
                'encoding': face_data['encoding'].tolist()
            }
        
        with open(output_path, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        logger.info(f"Database exported to {output_path}")
        return output_path
    
    def get_database_stats(self) -> Dict:
        """Get statistics about the face database."""
        persons = set()
        sources = set()
        tags = set()
        
        for face_data in self._known_faces_db.values():
            persons.add(face_data.get('person_id'))
            if face_data.get('source'):
                sources.add(face_data['source'])
            tags.update(face_data.get('tags', []))
        
        return {
            'total_faces': len(self._known_faces_db),
            'unique_persons': len(persons),
            'sources': list(sources),
            'tags': list(tags),
            'database_path': self.db_path
        }


# ============== CONVENIENCE FUNCTIONS ==============

def quick_verify(image1: str, image2: str) -> Dict:
    """Quick identity verification between two images."""
    engine = FaceCorrelationEngine()
    return engine.verify_identity(image1, image2)


def quick_search(image_path: str, db_path: Optional[str] = None) -> List[Dict]:
    """Quick search for face in database."""
    engine = FaceCorrelationEngine(db_path=db_path)
    return engine.search_database(image_path)


def extract_image_metadata(image_path: str) -> Dict:
    """Extract metadata from image file."""
    engine = FaceCorrelationEngine()
    metadata = engine.extract_metadata(image_path)
    return asdict(metadata)


# ============== MAIN ==============

if __name__ == "__main__":
    # Example usage
    engine = FaceCorrelationEngine()
    
    print("=" * 60)
    print("OSINT Face Correlation Engine")
    print("=" * 60)
    print(f"\nDatabase Stats: {json.dumps(engine.get_database_stats(), indent=2)}")
    
    print("\nExample commands:")
    print("  engine.add_face_to_database('photo.jpg', 'person_001', 'John Doe')")
    print("  engine.search_database('query.jpg')")
    print("  engine.verify_identity('img1.jpg', 'img2.jpg')")
    print("  engine.correlate_faces('target.jpg', search_database=True)")