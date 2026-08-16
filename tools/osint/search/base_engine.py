import time
import random
import logging
import urllib.request
import urllib.error
import urllib.parse
from typing import Optional, Dict, List, Tuple, Any
from dataclasses import dataclass
from datetime import datetime, timedelta
from collections import deque
import threading

logger = logging.getLogger("osint.base_engine")


@dataclass
class ProxyConfig:
    """Proxy configuration."""
    host: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None
    protocol: str = "http"
    
    def to_url(self) -> str:
        if self.username and self.password:
            auth = f"{urllib.parse.quote(self.username)}:{urllib.parse.quote(self.password)}@"
            return f"{self.protocol}://{auth}{self.host}:{self.port}"
        return f"{self.protocol}://{self.host}:{self.port}"


class RateLimiter:
    """
    Token bucket rate limiter.
    Ensures requests don't exceed specified rate.
    """
    
    def __init__(self, max_requests: int = 10, time_window: float = 60.0):
        """
        Args:
            max_requests: Maximum requests allowed in time_window
            time_window: Time window in seconds
        """
        self.max_requests = max_requests
        self.time_window = time_window
        self.tokens = max_requests
        self.last_update = time.time()
        self.lock = threading.Lock()
        self.request_times: deque = deque()
    
    def acquire(self, blocking: bool = True, timeout: Optional[float] = None) -> bool:
        """
        Acquire a token. Returns True if allowed, False if rate limited.
        
        Args:
            blocking: If True, wait until token available
            timeout: Max seconds to wait if blocking
        """
        with self.lock:
            now = time.time()
            
            # Remove old request times outside window
            while self.request_times and self.request_times[0] < now - self.time_window:
                self.request_times.popleft()
            
            # Check if under limit
            if len(self.request_times) < self.max_requests:
                self.request_times.append(now)
                return True
            
            if not blocking:
                return False
            
            # Calculate wait time
            wait_time = self.request_times[0] + self.time_window - now
            if timeout and wait_time > timeout:
                return False
        
        if blocking:
            time.sleep(wait_time)
            return self.acquire(blocking=True, timeout=timeout)
        
        return False
    
    def get_current_rate(self) -> float:
        """Get current request rate (requests per minute)."""
        with self.lock:
            now = time.time()
            while self.request_times and self.request_times[0] < now - self.time_window:
                self.request_times.popleft()
            return len(self.request_times) / (self.time_window / 60.0)


class ProxyRotator:
    """
    Rotates through proxy list untuk load balancing dan avoid IP bans.
    """
    
    def __init__(self, proxies: Optional[List[ProxyConfig]] = None):
        self.proxies = proxies or []
        self.current_index = 0
        self.failed_proxies: Dict[str, int] = {}
        self.max_failures = 3
        self.lock = threading.Lock()
    
    def add_proxy(self, proxy: ProxyConfig) -> None:
        """Add a proxy to the rotation."""
        self.proxies.append(proxy)
    
    def add_proxies_from_file(self, filepath: str) -> None:
        """Load proxies from file (format: host:port or protocol://host:port)."""
        try:
            with open(filepath, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    
                    # Parse proxy string
                    if "://" in line:
                        protocol, rest = line.split("://", 1)
                    else:
                        protocol, rest = "http", line
                    
                    if "@" in rest:
                        auth, host_port = rest.split("@", 1)
                        username, password = auth.split(":", 1)
                    else:
                        username = password = None
                        host_port = rest
                    
                    host, port = host_port.rsplit(":", 1)
                    self.add_proxy(ProxyConfig(
                        host=host,
                        port=int(port),
                        username=username,
                        password=password,
                        protocol=protocol
                    ))
            logger.info(f"Loaded {len(self.proxies)} proxies from {filepath}")
        except Exception as e:
            logger.error(f"Failed to load proxies: {e}")
    
    def get_next_proxy(self) -> Optional[ProxyConfig]:
        """Get next available proxy in rotation."""
        with self.lock:
            if not self.proxies:
                return None
            
            attempts = 0
            while attempts < len(self.proxies):
                proxy = self.proxies[self.current_index]
                self.current_index = (self.current_index + 1) % len(self.proxies)
                
                proxy_key = f"{proxy.host}:{proxy.port}"
                if self.failed_proxies.get(proxy_key, 0) < self.max_failures:
                    return proxy
                
                attempts += 1
            
            # All proxies failed, reset counters
            self.failed_proxies.clear()
            return self.proxies[0] if self.proxies else None
    
    def mark_failed(self, proxy: ProxyConfig) -> None:
        """Mark proxy as failed."""
        with self.lock:
            proxy_key = f"{proxy.host}:{proxy.port}"
            self.failed_proxies[proxy_key] = self.failed_proxies.get(proxy_key, 0) + 1
            logger.warning(f"Proxy {proxy_key} failed ({self.failed_proxies[proxy_key]}/{self.max_failures})")


class BaseEngine:
    """
    Base HTTP engine dengan semua fitur infrastructure.
    Foundation untuk semua OSINT modules.
    """
    
    DEFAULT_USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:126.0) Gecko/20100101 Firefox/126.0",
        "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/124.0.2478.80",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    ]
    
    def __init__(
        self,
        max_retries: int = 3,
        retry_delay: float = 2.0,
        timeout: int = 15,
        rate_limit_requests: int = 10,
        rate_limit_window: float = 60.0,
        use_proxy: bool = False,
        proxy_file: Optional[str] = None,
        verify_ssl: bool = True,
        follow_redirects: bool = True,
        max_redirects: int = 5
    ):
        """
        Initialize base engine.
        
        Args:
            max_retries: Maximum retry attempts
            retry_delay: Base delay between retries (doubles each attempt)
            timeout: Request timeout in seconds
            rate_limit_requests: Max requests per time window
            rate_limit_window: Rate limit window in seconds
            use_proxy: Enable proxy rotation
            proxy_file: Path to proxy list file
            verify_ssl: Verify SSL certificates
            follow_redirects: Follow HTTP redirects
            max_redirects: Maximum redirects to follow
        """
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.follow_redirects = follow_redirects
        self.max_redirects = max_redirects
        
        # Rate limiter
        self.rate_limiter = RateLimiter(rate_limit_requests, rate_limit_window)
        
        # Proxy rotator
        self.proxy_rotator = ProxyRotator()
        if use_proxy and proxy_file:
            self.proxy_rotator.add_proxies_from_file(proxy_file)
        
        # Session state
        self.cookie_jar = urllib.request.HTTPCookieProcessor()
        self.last_response_info: Optional[Dict[str, Any]] = None
        self.request_count = 0
        self.success_count = 0
        self.error_count = 0
    
    def _get_random_ua(self) -> str:
        """Get random User-Agent string."""
        return random.choice(self.DEFAULT_USER_AGENTS)
    
    def _build_opener(self, proxy: Optional[ProxyConfig] = None) -> urllib.request.OpenerDirector:
        """Build urllib opener dengan cookie jar dan optional proxy."""
        handlers = [self.cookie_jar]
        
        if proxy:
            proxy_handler = urllib.request.ProxyHandler({
                "http": proxy.to_url(),
                "https": proxy.to_url()
            })
            handlers.append(proxy_handler)
        
        if not self.verify_ssl:
            import ssl
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            handlers.append(urllib.request.HTTPSHandler(context=ssl_context))
        
        return urllib.request.build_opener(*handlers)
    
    def _make_request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        data: Optional[bytes] = None,
        timeout: Optional[int] = None,
        allow_redirects: Optional[bool] = None
    ) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
        """
        Make HTTP request dengan full infrastructure support.
        
        Returns:
            Tuple of (response_body, response_info)
            response_info contains: status, headers, url, redirect_history, timing
        """
        # Rate limiting
        if not self.rate_limiter.acquire(blocking=True, timeout=30):
            logger.warning("Rate limit exceeded, request blocked")
            return None, None
        
        # Default headers
        default_headers = {
            "User-Agent": self._get_random_ua(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Cache-Control": "max-age=0",
        }
        
        if headers:
            default_headers.update(headers)
        
        # Allow redirects setting
        follow = allow_redirects if allow_redirects is not None else self.follow_redirects
        
        req_timeout = timeout or self.timeout
        proxy = self.proxy_rotator.get_next_proxy() if self.proxy_rotator.proxies else None
        
        last_error = None
        redirect_history = []
        
        for attempt in range(self.max_retries):
            start_time = time.time()
            try:
                opener = self._build_opener(proxy)
                
                req = urllib.request.Request(
                    url,
                    data=data,
                    headers=default_headers,
                    method=method
                )
                
                with opener.open(req, timeout=req_timeout) as response:
                    # Handle gzip/deflate
                    content = response.read()
                    encoding = response.headers.get("Content-Encoding", "").lower()
                    
                    if encoding == "gzip":
                        import gzip
                        content = gzip.decompress(content)
                    elif encoding == "deflate":
                        import zlib
                        content = zlib.decompress(content)
                    elif encoding == "br":
                        try:
                            import brotli
                            content = brotli.decompress(content)
                        except ImportError:
                            pass
                    
                    body = content.decode("utf-8", errors="replace")
                    
                    response_info = {
                        "status": response.status,
                        "headers": dict(response.headers),
                        "url": response.geturl(),
                        "redirect_history": redirect_history,
                        "timing": time.time() - start_time,
                        "attempt": attempt + 1,
                        "proxy_used": proxy.to_url() if proxy else None,
                        "content_length": len(body),
                    }
                    
                    self.last_response_info = response_info
                    self.success_count += 1
                    self.request_count += 1
                    
                    return body, response_info
                    
            except urllib.error.HTTPError as e:
                last_error = e
                response_info = {
                    "status": e.code,
                    "headers": dict(e.headers) if e.headers else {},
                    "url": url,
                    "error": f"HTTP {e.code}: {e.reason}",
                    "timing": time.time() - start_time,
                    "attempt": attempt + 1,
                }
                
                # Don't retry on 404 or 410
                if e.code in (404, 410):
                    self.error_count += 1
                    self.request_count += 1
                    return None, response_info
                
                # Retry on rate limit or server errors
                if e.code in (429, 500, 502, 503, 504):
                    wait = self.retry_delay * (2 ** attempt)
                    logger.warning(f"HTTP {e.code} (attempt {attempt+1}/{self.max_retries}), waiting {wait}s...")
                    time.sleep(wait)
                    
                    # Mark proxy as failed jika 429
                    if e.code == 429 and proxy:
                        self.proxy_rotator.mark_failed(proxy)
                        proxy = self.proxy_rotator.get_next_proxy()
                else:
                    logger.error(f"HTTP Error {e.code}: {e.reason}")
                    break
                    
            except urllib.error.URLError as e:
                last_error = e
                logger.warning(f"URL Error (attempt {attempt+1}): {e.reason}")
                if proxy:
                    self.proxy_rotator.mark_failed(proxy)
                    proxy = self.proxy_rotator.get_next_proxy()
                time.sleep(self.retry_delay * (2 ** attempt))
                
            except Exception as e:
                last_error = e
                logger.error(f"Request error (attempt {attempt+1}): {e}")
                time.sleep(self.retry_delay)
        
        self.error_count += 1
        self.request_count += 1
        
        error_info = {
            "status": None,
            "error": str(last_error) if last_error else "Unknown error",
            "url": url,
            "attempts": self.max_retries,
            "timing": time.time() - start_time if 'start_time' in dir() else 0,
        }
        
        return None, error_info
    
    def head_request(self, url: str, timeout: Optional[int] = None) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Lightweight HEAD request untuk check URL availability.
        
        Returns:
            Tuple of (is_available, response_info)
        """
        body, info = self._make_request(url, method="HEAD", timeout=timeout or 10)
        if info and info.get("status") == 200:
            return True, info
        return False, info
    
    def get_stats(self) -> Dict[str, Any]:
        """Get engine statistics."""
        return {
            "total_requests": self.request_count,
            "successful": self.success_count,
            "errors": self.error_count,
            "success_rate": (self.success_count / self.request_count * 100) if self.request_count > 0 else 0,
            "current_rate": self.rate_limiter.get_current_rate(),
            "proxies_available": len(self.proxy_rotator.proxies),
            "proxies_failed": len(self.proxy_rotator.failed_proxies),
        }
    
    def reset_stats(self) -> None:
        """Reset statistics counters."""
        self.request_count = 0
        self.success_count = 0
        self.error_count = 0