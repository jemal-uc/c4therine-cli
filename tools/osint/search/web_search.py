"""
Web Search Engine v1.0
Multi-engine fallback: DuckDuckGo → Google CSE → Bing → Manual Scrape
Dengan relevance scoring dan deduplication.
"""

import re
import json
import time
import logging
import urllib.request
import urllib.error
import urllib.parse
from typing import List, Dict, Optional, Set, Tuple, Any
from dataclasses import dataclass, field, asdict
from urllib.parse import quote, urlencode, urlparse
from datetime import datetime

from .base_engine import BaseEngine

logger = logging.getLogger("osint.web_search")


@dataclass
class SearchResult:
    """Single search result."""
    title: str
    href: str
    body: str
    source: str
    relevance_score: float = 0.0
    match_type: str = ""
    discovered_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict:
        return asdict(self)


class DuckDuckGoEngine(BaseEngine):
    """Engine 1: DuckDuckGo via ddgs package atau HTML fallback."""

    def search(self, query: str, max_results: int = 5) -> List[Dict]:
        """Search menggunakan DuckDuckGo."""
        # Try ddgs package first
        try:
            from ddgs import DDGS
            with DDGS() as ddgs:
                results = list(ddgs.text(query, max_results=max_results))
                return [{"title": r.get("title", ""), 
                        "href": r.get("href", ""), 
                        "body": r.get("body", "")} for r in results]
        except ImportError:
            try:
                from duckduckgo_search import DDGS
                with DDGS() as ddgs:
                    results = list(ddgs.text(query, max_results=max_results))
                    return [{"title": r.get("title", ""), 
                            "href": r.get("href", ""), 
                            "body": r.get("body", "")} for r in results]
            except Exception as e:
                logger.warning(f"DuckDuckGo package error: {e}")
                return []
        except Exception as e:
            logger.warning(f"DuckDuckGo search error: {e}")
            return []


class GoogleCSEEngine(BaseEngine):
    """Engine 2: Google Custom Search API."""

    def __init__(self, api_key: Optional[str] = None, 
                 cx: Optional[str] = None, **kwargs):
        super().__init__(**kwargs)
        self.api_key = api_key
        self.cx = cx

    def search(self, query: str, max_results: int = 5) -> List[Dict]:
        if not self.api_key or not self.cx:
            logger.debug("Google CSE: No API key or CX configured")
            return []

        try:
            params = {
                "key": self.api_key,
                "cx": self.cx,
                "q": query,
                "num": min(max_results, 10)
            }
            url = f"https://www.googleapis.com/customsearch/v1?{urlencode(params)}"

            html, info = self._make_request(url, timeout=10)
            if not html:
                return []

            data = json.loads(html)
            results = []
            for item in data.get("items", []):
                results.append({
                    "title": item.get("title", ""),
                    "href": item.get("link", ""),
                    "body": item.get("snippet", "")
                })
            logger.info(f"Google CSE returned {len(results)} results")
            return results
        except Exception as e:
            logger.warning(f"Google CSE error: {e}")
            return []


class BingEngine(BaseEngine):
    """Engine 3: Bing Web Search API."""

    def __init__(self, api_key: Optional[str] = None, **kwargs):
        super().__init__(**kwargs)
        self.api_key = api_key

    def search(self, query: str, max_results: int = 5) -> List[Dict]:
        if not self.api_key:
            logger.debug("Bing: No API key configured")
            return []

        try:
            url = "https://api.bing.microsoft.com/v7.0/search"
            headers = {
                "Ocp-Apim-Subscription-Key": self.api_key,
                "User-Agent": self._get_random_ua()
            }
            params = {"q": query, "count": min(max_results, 50)}

            full_url = f"{url}?{urlencode(params)}"
            html, info = self._make_request(full_url, headers=headers, timeout=10)
            if not html:
                return []

            data = json.loads(html)
            results = []
            for item in data.get("webPages", {}).get("value", []):
                results.append({
                    "title": item.get("name", ""),
                    "href": item.get("url", ""),
                    "body": item.get("snippet", "")
                })
            logger.info(f"Bing returned {len(results)} results")
            return results
        except Exception as e:
            logger.warning(f"Bing error: {e}")
            return []


class ManualScrapeEngine(BaseEngine):
    """Engine 4: Manual scraping dari DuckDuckGo HTML (last resort)."""

    def search(self, query: str, max_results: int = 5) -> List[Dict]:
        try:
            encoded = quote(query)
            url = f"https://html.duckduckgo.com/html/?q={encoded}"

            html, info = self._make_request(url, timeout=15)
            if not html:
                return []

            results = []
            # Parse hasil DDG HTML
            title_pattern = r'<a[^>]*class="result__a"[^>]*href="([^"]*)"[^>]*>(.*?)</a>'
            snippet_pattern = r'<a[^>]*class="result__snippet"[^>]*>(.*?)</a>'

            titles = re.findall(title_pattern, html, re.DOTALL)
            snippets = re.findall(snippet_pattern, html, re.DOTALL)

            for i, (href, title) in enumerate(titles[:max_results]):
                clean_title = re.sub(r'<[^>]+>', '', title)
                clean_href = href.replace("&amp;", "&")

                snippet = ""
                if i < len(snippets):
                    snippet = re.sub(r'<[^>]+>', '', snippets[i])

                results.append({
                    "title": clean_title.strip(),
                    "href": clean_href.strip(),
                    "body": snippet.strip()
                })

            logger.info(f"Manual scrape returned {len(results)} results")
            return results
        except Exception as e:
            logger.warning(f"Manual scrape error: {e}")
            return []


class WebSearchEngine:
    """
    Unified web search dengan multi-engine fallback.
    Primary: DuckDuckGo → Google CSE → Bing → Manual Scrape
    """

    def __init__(
        self,
        google_api_key: Optional[str] = None,
        google_cx: Optional[str] = None,
        bing_api_key: Optional[str] = None,
        max_results_per_query: int = 5,
        deduplicate: bool = True
    ):
        """
        Initialize web search engine.

        Args:
            google_api_key: Google Custom Search API key
            google_cx: Google Custom Search Engine ID
            bing_api_key: Bing Web Search API key
            max_results_per_query: Max results per query
            deduplicate: Remove duplicate results across engines
        """
        self.max_results = max_results_per_query
        self.deduplicate = deduplicate

        self.engines: List[BaseEngine] = [
            DuckDuckGoEngine(),
            GoogleCSEEngine(api_key=google_api_key, cx=google_cx),
            BingEngine(api_key=bing_api_key),
            ManualScrapeEngine()
        ]

        self.seen_urls: Set[str] = set()
        self.seen_content_hashes: Set[str] = set()

        # Stats
        self.queries_made = 0
        self.total_results = 0

    def _is_duplicate(self, result: Dict) -> bool:
        """Check if result is duplicate."""
        if not self.deduplicate:
            return False

        url = result.get("href", "")
        content = f"{result.get('title', '')}{result.get('body', '')}".lower()
        content_hash = hash(content) % (10 ** 10)

        if url in self.seen_urls:
            return True
        if content_hash in self.seen_content_hashes:
            return True

        self.seen_urls.add(url)
        self.seen_content_hashes.add(content_hash)
        return False

    def search(self, query: str, max_results: Optional[int] = None) -> List[SearchResult]:
        """
        Search across all engines dengan fallback.

        Args:
            query: Search query
            max_results: Override default max results

        Returns:
            List of SearchResult objects
        """
        max_res = max_results or self.max_results
        all_results: List[SearchResult] = []

        logger.info(f"[WebSearch] Query: '{query}'")

        for engine in self.engines:
            engine_name = engine.__class__.__name__
            logger.info(f"[WebSearch] Trying {engine_name}...")

            try:
                raw_results = engine.search(query, max_res)
                if raw_results:
                    logger.info(f"[WebSearch] {engine_name} returned {len(raw_results)} results")

                    for res in raw_results:
                        if self._is_duplicate(res):
                            continue

                        search_result = SearchResult(
                            title=res.get("title", ""),
                            href=res.get("href", ""),
                            body=res.get("body", ""),
                            source=engine_name.replace("Engine", "").lower()
                        )
                        all_results.append(search_result)

                    # Stop jika sudah cukup hasil
                    if len(all_results) >= max_res:
                        break
                else:
                    logger.info(f"[WebSearch] {engine_name} failed or no results")
            except Exception as e:
                logger.error(f"[WebSearch] {engine_name} error: {e}")

        self.queries_made += 1
        self.total_results += len(all_results)

        logger.info(f"[WebSearch] Total unique results: {len(all_results)}")
        return all_results[:max_res]

    def search_multiple(self, queries: List[str], max_results: Optional[int] = None) -> Dict[str, List[SearchResult]]:
        """Search multiple queries."""
        results = {}
        for query in queries:
            results[query] = self.search(query, max_results)
            time.sleep(1.0)  # Rate limiting antara queries
        return results

    def search_with_variants(self, base_query: str, variants: List[str], 
                             max_results: Optional[int] = None) -> List[SearchResult]:
        """Search dengan multiple query variants dan merge results."""
        all_results: List[SearchResult] = []
        self.seen_urls.clear()
        self.seen_content_hashes.clear()

        for variant in variants:
            query = base_query.format(variant=variant)
            results = self.search(query, max_results)
            all_results.extend(results)

        # Sort by relevance (placeholder - would use proper scoring)
        return all_results

    def search_platform_specific(self, username: str, platform: str,
                                  max_results: Optional[int] = None) -> List[SearchResult]:
        """Search for username on specific platform."""
        query = f'"{username}" site:{platform}'
        return self.search(query, max_results)

    def search_social_profiles(self, name: str, 
                                platforms: Optional[List[str]] = None,
                                max_results: Optional[int] = None) -> Dict[str, List[SearchResult]]:
        """Search for social media profiles."""
        if platforms is None:
            platforms = ["instagram.com", "twitter.com", "x.com", "github.com", 
                        "linkedin.com", "facebook.com", "tiktok.com", "youtube.com"]

        results = {}
        for platform in platforms:
            query = f'"{name}" site:{platform}'
            results[platform] = self.search(query, max_results)

        return results

    def get_stats(self) -> Dict[str, Any]:
        """Get search statistics."""
        return {
            "queries_made": self.queries_made,
            "total_results": self.total_results,
            "avg_results_per_query": self.total_results / self.queries_made if self.queries_made > 0 else 0,
        }

    def reset_cache(self) -> None:
        """Clear deduplication cache."""
        self.seen_urls.clear()
        self.seen_content_hashes.clear()