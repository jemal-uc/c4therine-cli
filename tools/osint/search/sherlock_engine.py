import re
import json
import time
import asyncio
import logging
import aiohttp
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field, asdict
from urllib.parse import quote
from pathlib import Path

from .base_engine import BaseEngine

logger = logging.getLogger("osint.sherlock")


@dataclass
class SiteResult:
    """Hasil pencarian di satu platform."""
    site_name: str
    url_main: str
    url_user: str
    status: str  # "found", "not_found", "error", "blocked"
    http_status: Optional[int] = None
    response_time: float = 0.0
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SherlockReport:
    """Laporan lengkap pencarian username."""
    username: str
    total_sites: int
    sites_checked: int
    sites_found: int
    sites_not_found: int
    sites_error: int
    sites_blocked: int
    results: List[SiteResult] = field(default_factory=list)
    scan_duration: float = 0.0
    timestamp: str = field(default_factory=lambda: time.strftime("%Y-%m-%d %H:%M:%S"))
    
    def to_dict(self) -> dict:
        return {
            "username": self.username,
            "total_sites": self.total_sites,
            "sites_checked": self.sites_checked,
            "sites_found": self.sites_found,
            "sites_not_found": self.sites_not_found,
            "sites_error": self.sites_error,
            "sites_blocked": self.sites_blocked,
            "scan_duration": self.scan_duration,
            "timestamp": self.timestamp,
            "results": [r.to_dict() for r in self.results]
        }


class SiteDatabase:
    """
    Database 600+ platform untuk username lookup.
    Di-load dari JSON atau built-in defaults.
    """
    
    # Core platforms - most reliable and commonly used
    CORE_SITES = {
        # Social Media
        "Instagram": {
            "url_main": "https://www.instagram.com/",
            "url_user": "https://www.instagram.com/{username}",
            "error_type": "status_code",
            "error_code": 404,
            "headers": {"User-Agent": "Mozilla/5.0"},
        },
        "Twitter/X": {
            "url_main": "https://x.com/",
            "url_user": "https://x.com/{username}",
            "error_type": "status_code",
            "error_code": 404,
            "headers": {"User-Agent": "Mozilla/5.0"},
        },
        "Facebook": {
            "url_main": "https://www.facebook.com/",
            "url_user": "https://www.facebook.com/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "TikTok": {
            "url_main": "https://www.tiktok.com/",
            "url_user": "https://www.tiktok.com/@{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "LinkedIn": {
            "url_main": "https://www.linkedin.com/",
            "url_user": "https://www.linkedin.com/in/{username}/",
            "error_type": "status_code",
            "error_code": 404,
        },
        "Pinterest": {
            "url_main": "https://www.pinterest.com/",
            "url_user": "https://www.pinterest.com/{username}/",
            "error_type": "status_code",
            "error_code": 404,
        },
        "Reddit": {
            "url_main": "https://www.reddit.com/",
            "url_user": "https://www.reddit.com/user/{username}/",
            "error_type": "status_code",
            "error_code": 404,
        },
        "Snapchat": {
            "url_main": "https://www.snapchat.com/",
            "url_user": "https://www.snapchat.com/add/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "YouTube": {
            "url_main": "https://www.youtube.com/",
            "url_user": "https://www.youtube.com/@{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "Twitch": {
            "url_main": "https://www.twitch.tv/",
            "url_user": "https://www.twitch.tv/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "Discord": {
            "url_main": "https://discord.com/",
            "url_user": "https://discord.com/users/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "Telegram": {
            "url_main": "https://t.me/",
            "url_user": "https://t.me/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        
        # Development
        "GitHub": {
            "url_main": "https://github.com/",
            "url_user": "https://github.com/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "GitLab": {
            "url_main": "https://gitlab.com/",
            "url_user": "https://gitlab.com/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "Bitbucket": {
            "url_main": "https://bitbucket.org/",
            "url_user": "https://bitbucket.org/{username}/",
            "error_type": "status_code",
            "error_code": 404,
        },
        "StackOverflow": {
            "url_main": "https://stackoverflow.com/",
            "url_user": "https://stackoverflow.com/users/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "Dev.to": {
            "url_main": "https://dev.to/",
            "url_user": "https://dev.to/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "CodePen": {
            "url_main": "https://codepen.io/",
            "url_user": "https://codepen.io/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "Replit": {
            "url_main": "https://replit.com/",
            "url_user": "https://replit.com/@{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "HackerRank": {
            "url_main": "https://www.hackerrank.com/",
            "url_user": "https://www.hackerrank.com/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "LeetCode": {
            "url_main": "https://leetcode.com/",
            "url_user": "https://leetcode.com/{username}/",
            "error_type": "status_code",
            "error_code": 404,
        },
        "Kaggle": {
            "url_main": "https://www.kaggle.com/",
            "url_user": "https://www.kaggle.com/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        
        # Content & Creative
        "Medium": {
            "url_main": "https://medium.com/",
            "url_user": "https://medium.com/@{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "WordPress": {
            "url_main": "https://wordpress.com/",
            "url_user": "https://{username}.wordpress.com",
            "error_type": "status_code",
            "error_code": 404,
        },
        "Blogger": {
            "url_main": "https://www.blogger.com/",
            "url_user": "https://{username}.blogspot.com",
            "error_type": "status_code",
            "error_code": 404,
        },
        "Tumblr": {
            "url_main": "https://www.tumblr.com/",
            "url_user": "https://{username}.tumblr.com",
            "error_type": "status_code",
            "error_code": 404,
        },
        "Flickr": {
            "url_main": "https://www.flickr.com/",
            "url_user": "https://www.flickr.com/people/{username}/",
            "error_type": "status_code",
            "error_code": 404,
        },
        "DeviantArt": {
            "url_main": "https://www.deviantart.com/",
            "url_user": "https://www.deviantart.com/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "Behance": {
            "url_main": "https://www.behance.net/",
            "url_user": "https://www.behance.net/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "Dribbble": {
            "url_main": "https://dribbble.com/",
            "url_user": "https://dribbble.com/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        
        # Gaming
        "Steam": {
            "url_main": "https://steamcommunity.com/",
            "url_user": "https://steamcommunity.com/id/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "Roblox": {
            "url_main": "https://www.roblox.com/",
            "url_user": "https://www.roblox.com/user.aspx?username={username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "Minecraft": {
            "url_main": "https://namemc.com/",
            "url_user": "https://namemc.com/profile/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        
        # Forums & Communities
        "Quora": {
            "url_main": "https://www.quora.com/",
            "url_user": "https://www.quora.com/profile/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "Goodreads": {
            "url_main": "https://www.goodreads.com/",
            "url_user": "https://www.goodreads.com/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "Wattpad": {
            "url_main": "https://www.wattpad.com/",
            "url_user": "https://www.wattpad.com/user/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "Keybase": {
            "url_main": "https://keybase.io/",
            "url_user": "https://keybase.io/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        
        # Professional
        "About.me": {
            "url_main": "https://about.me/",
            "url_user": "https://about.me/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "Gravatar": {
            "url_main": "https://en.gravatar.com/",
            "url_user": "https://en.gravatar.com/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "SlideShare": {
            "url_main": "https://www.slideshare.net/",
            "url_user": "https://www.slideshare.net/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "AngelList": {
            "url_main": "https://angel.co/",
            "url_user": "https://angel.co/u/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        
        # Indonesian Platforms
        "Kaskus": {
            "url_main": "https://www.kaskus.co.id/",
            "url_user": "https://www.kaskus.co.id/@{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "Tokopedia": {
            "url_main": "https://www.tokopedia.com/",
            "url_user": "https://www.tokopedia.com/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "Bukalapak": {
            "url_main": "https://www.bukalapak.com/",
            "url_user": "https://www.bukalapak.com/u/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "Shopee": {
            "url_main": "https://shopee.co.id/",
            "url_user": "https://shopee.co.id/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
    }
    
    # Extended sites - content-based detection
    EXTENDED_SITES = {
        "Spotify": {
            "url_main": "https://open.spotify.com/",
            "url_user": "https://open.spotify.com/user/{username}",
            "error_type": "message",
            "error_msg": "page not found",
        },
        "SoundCloud": {
            "url_main": "https://soundcloud.com/",
            "url_user": "https://soundcloud.com/{username}",
            "error_type": "message",
            "error_msg": "not found",
        },
        "Bandcamp": {
            "url_main": "https://bandcamp.com/",
            "url_user": "https://bandcamp.com/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "Vimeo": {
            "url_main": "https://vimeo.com/",
            "url_user": "https://vimeo.com/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "DailyMotion": {
            "url_main": "https://www.dailymotion.com/",
            "url_user": "https://www.dailymotion.com/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "Mixcloud": {
            "url_main": "https://www.mixcloud.com/",
            "url_user": "https://www.mixcloud.com/{username}/",
            "error_type": "status_code",
            "error_code": 404,
        },
        "Last.fm": {
            "url_main": "https://www.last.fm/",
            "url_user": "https://www.last.fm/user/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "ProductHunt": {
            "url_main": "https://www.producthunt.com/",
            "url_user": "https://www.producthunt.com/@{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "Kickstarter": {
            "url_main": "https://www.kickstarter.com/",
            "url_user": "https://www.kickstarter.com/profile/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "Patreon": {
            "url_main": "https://www.patreon.com/",
            "url_user": "https://www.patreon.com/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "BuyMeACoffee": {
            "url_main": "https://www.buymeacoffee.com/",
            "url_user": "https://www.buymeacoffee.com/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "Ko-fi": {
            "url_main": "https://ko-fi.com/",
            "url_user": "https://ko-fi.com/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "Substack": {
            "url_main": "https://substack.com/",
            "url_user": "https://{username}.substack.com",
            "error_type": "status_code",
            "error_code": 404,
        },
        "Ghost": {
            "url_main": "https://ghost.org/",
            "url_user": "https://{username}.ghost.io",
            "error_type": "status_code",
            "error_code": 404,
        },
        "Notion": {
            "url_main": "https://www.notion.so/",
            "url_user": "https://{username}.notion.site",
            "error_type": "status_code",
            "error_code": 404,
        },
        "Figma": {
            "url_main": "https://www.figma.com/",
            "url_user": "https://www.figma.com/@{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "Canva": {
            "url_main": "https://www.canva.com/",
            "url_user": "https://www.canva.com/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "Unsplash": {
            "url_main": "https://unsplash.com/",
            "url_user": "https://unsplash.com/@{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "500px": {
            "url_main": "https://500px.com/",
            "url_user": "https://500px.com/p/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "Imgur": {
            "url_main": "https://imgur.com/",
            "url_user": "https://imgur.com/user/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "Giphy": {
            "url_main": "https://giphy.com/",
            "url_user": "https://giphy.com/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "Tinder": {
            "url_main": "https://tinder.com/",
            "url_user": "https://tinder.com/@{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "Bumble": {
            "url_main": "https://bumble.com/",
            "url_user": "https://bumble.com/user/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "Strava": {
            "url_main": "https://www.strava.com/",
            "url_user": "https://www.strava.com/athletes/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "MyFitnessPal": {
            "url_main": "https://www.myfitnesspal.com/",
            "url_user": "https://www.myfitnesspal.com/profile/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "MapMyRun": {
            "url_main": "https://www.mapmyrun.com/",
            "url_user": "https://www.mapmyrun.com/profile/{username}/",
            "error_type": "status_code",
            "error_code": 404,
        },
        "Duolingo": {
            "url_main": "https://www.duolingo.com/",
            "url_user": "https://www.duolingo.com/profile/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "Coursera": {
            "url_main": "https://www.coursera.org/",
            "url_user": "https://www.coursera.org/user/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "Udemy": {
            "url_main": "https://www.udemy.com/",
            "url_user": "https://www.udemy.com/user/{username}/",
            "error_type": "status_code",
            "error_code": 404,
        },
        "Skillshare": {
            "url_main": "https://www.skillshare.com/",
            "url_user": "https://www.skillshare.com/profile/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "Pluralsight": {
            "url_main": "https://www.pluralsight.com/",
            "url_user": "https://www.pluralsight.com/profile/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "Codecademy": {
            "url_main": "https://www.codecademy.com/",
            "url_user": "https://www.codecademy.com/profiles/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "FreeCodeCamp": {
            "url_main": "https://www.freecodecamp.org/",
            "url_user": "https://www.freecodecamp.org/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "Exercism": {
            "url_main": "https://exercism.org/",
            "url_user": "https://exercism.org/profiles/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "Codewars": {
            "url_main": "https://www.codewars.com/",
            "url_user": "https://www.codewars.com/users/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "TryHackMe": {
            "url_main": "https://tryhackme.com/",
            "url_user": "https://tryhackme.com/p/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "HackTheBox": {
            "url_main": "https://www.hackthebox.com/",
            "url_user": "https://app.hackthebox.com/profile/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "RootMe": {
            "url_main": "https://www.root-me.org/",
            "url_user": "https://www.root-me.org/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "CTFtime": {
            "url_main": "https://ctftime.org/",
            "url_user": "https://ctftime.org/user/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "Bugcrowd": {
            "url_main": "https://bugcrowd.com/",
            "url_user": "https://bugcrowd.com/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "HackerOne": {
            "url_main": "https://hackerone.com/",
            "url_user": "https://hackerone.com/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
        "Intigriti": {
            "url_main": "https://app.intigriti.com/",
            "url_user": "https://app.intigriti.com/researcher/{username}",
            "error_type": "status_code",
            "error_code": 404,
        },
    }
    
    def __init__(self, use_extended: bool = True):
        self.sites = dict(self.CORE_SITES)
        if use_extended:
            self.sites.update(self.EXTENDED_SITES)
        logger.info(f"Loaded {len(self.sites)} platforms")
    
    def load_from_json(self, filepath: str) -> None:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.sites.update(data)
            logger.info(f"Loaded {len(data)} additional platforms from {filepath}")
        except Exception as e:
            logger.error(f"Failed to load site database: {e}")
    
    def save_to_json(self, filepath: str) -> None:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(self.sites, f, indent=2, ensure_ascii=False)
    
    def get_sites(self, categories: Optional[List[str]] = None) -> Dict[str, Dict]:
        if not categories:
            return self.sites
        return self.sites
    
    def add_site(self, name: str, config: Dict[str, Any]) -> None:
        self.sites[name] = config
        logger.info(f"Added custom site: {name}")


class SherlockEngine:
    """Sherlock-style username search engine."""
    
    def __init__(
        self,
        site_database: Optional[SiteDatabase] = None,
        max_workers: int = 20,
        timeout: int = 10,
        use_extended: bool = True
    ):
        self.site_db = site_database or SiteDatabase(use_extended=use_extended)
        self.max_workers = max_workers
        self.timeout = timeout
        self.base_engine = BaseEngine(
            max_retries=2,
            retry_delay=1.0,
            timeout=timeout,
            rate_limit_requests=30,
            rate_limit_window=60.0
        )
        self._compile_patterns()
    
    def _compile_patterns(self) -> None:
        self.error_patterns: Dict[str, re.Pattern] = {}
        for site_name, config in self.site_db.sites.items():
            if config.get("error_type") == "message":
                error_msg = config.get("error_msg", "")
                if error_msg:
                    self.error_patterns[site_name] = re.compile(
                        re.escape(error_msg), 
                        re.IGNORECASE
                    )
    
    def _check_site(self, username: str, site_name: str, site_config: Dict) -> SiteResult:
        url_user = site_config["url_user"].format(username=quote(username, safe=""))
        url_main = site_config["url_main"]
        start_time = time.time()
        
        try:
            headers = site_config.get("headers", {})
            body, info = self.base_engine._make_request(
                url_user,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=True
            )
            
            response_time = time.time() - start_time
            
            if info is None:
                return SiteResult(
                    site_name=site_name, url_main=url_main, url_user=url_user,
                    status="error", response_time=response_time,
                    error_message="No response info"
                )
            
            status_code = info.get("status")
            error_type = site_config.get("error_type", "status_code")
            
            if error_type == "status_code":
                error_code = site_config.get("error_code", 404)
                if status_code == error_code:
                    return SiteResult(site_name, url_main, url_user, "not_found", status_code, response_time)
                elif status_code == 200:
                    return SiteResult(site_name, url_main, url_user, "found", status_code, response_time, metadata={"content_length": info.get("content_length", 0)})
                elif status_code in (301, 302):
                    return SiteResult(site_name, url_main, url_user, "found", status_code, response_time, metadata={"redirect": True})
                elif status_code == 429:
                    return SiteResult(site_name, url_main, url_user, "blocked", status_code, response_time, "Rate limited")
                else:
                    return SiteResult(site_name, url_main, url_user, "error", status_code, response_time, f"Unexpected status: {status_code}")
            
            elif error_type == "message":
                if body is None:
                    return SiteResult(site_name, url_main, url_user, "error", status_code, response_time, "Empty response body")
                
                pattern = self.error_patterns.get(site_name)
                if pattern and pattern.search(body):
                    return SiteResult(site_name, url_main, url_user, "not_found", status_code, response_time)
                else:
                    return SiteResult(site_name, url_main, url_user, "found", status_code, response_time, metadata={"content_length": len(body)})
            
            else:
                return SiteResult(site_name, url_main, url_user, "error", status_code, response_time, f"Unknown error type: {error_type}")
                
        except Exception as e:
            return SiteResult(site_name, url_main, url_user, "error", None, time.time() - start_time, str(e))
    
    def search(
        self,
        username: str,
        sites: Optional[List[str]] = None,
        include_extended: bool = True,
        progress_callback: Optional[callable] = None
    ) -> SherlockReport:
        start_time = time.time()
        
        if sites:
            site_list = {k: v for k, v in self.site_db.sites.items() if k in sites}
        else:
            site_list = self.site_db.sites
            if not include_extended:
                site_list = {k: v for k, v in site_list.items() 
                           if k in SiteDatabase.CORE_SITES}
        
        total_sites = len(site_list)
        logger.info(f"[Sherlock] Checking \"{username}\" on {total_sites} platforms...")
        
        results: List[SiteResult] = []
        checked = 0
        
        for site_name, site_config in site_list.items():
            result = self._check_site(username, site_name, site_config)
            results.append(result)
            checked += 1
            
            if progress_callback:
                progress_callback(checked, total_sites)
            
            if checked % 10 == 0:
                time.sleep(0.5)
        
        found = sum(1 for r in results if r.status == "found")
        not_found = sum(1 for r in results if r.status == "not_found")
        errors = sum(1 for r in results if r.status == "error")
        blocked_count = sum(1 for r in results if r.status == "blocked")
        
        scan_duration = time.time() - start_time
        
        results.sort(key=lambda x: (
            0 if x.status == "found" else 1,
            0 if x.status == "blocked" else 1,
            x.response_time
        ))
        
        report = SherlockReport(
            username=username,
            total_sites=total_sites,
            sites_checked=checked,
            sites_found=found,
            sites_not_found=not_found,
            sites_error=errors,
            sites_blocked=blocked_count,
            results=results,
            scan_duration=scan_duration
        )
        
        logger.info(f"[Sherlock] Done! Found: {found}, Not Found: {not_found}, "
                   f"Errors: {errors}, Blocked: {blocked_count} ({scan_duration:.1f}s)")
        
        return report
    
    async def search_async(
        self,
        username: str,
        sites: Optional[List[str]] = None,
        max_concurrent: int = 20
    ) -> SherlockReport:
        import aiohttp
        
        start_time = time.time()
        
        if sites:
            site_list = {k: v for k, v in self.site_db.sites.items() if k in sites}
        else:
            site_list = self.site_db.sites
        
        total_sites = len(site_list)
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def check_one(site_name: str, site_config: Dict) -> SiteResult:
            async with semaphore:
                url_user = site_config["url_user"].format(username=quote(username, safe=""))
                url_main = site_config["url_main"]
                start = time.time()
                try:
                    timeout = aiohttp.ClientTimeout(total=self.timeout)
                    headers = {"User-Agent": self.base_engine._get_random_ua()}
                    headers.update(site_config.get("headers", {}))
                    
                    async with aiohttp.ClientSession(timeout=timeout) as session:
                        async with session.get(url_user, headers=headers, allow_redirects=True) as resp:
                            response_time = time.time() - start
                            status_code = resp.status
                            
                            error_type = site_config.get("error_type", "status_code")
                            
                            if error_type == "status_code":
                                error_code = site_config.get("error_code", 404)
                                if status_code == error_code:
                                    return SiteResult(site_name, url_main, url_user, "not_found", status_code, response_time)
                                elif status_code == 200:
                                    content_length = resp.content_length if getattr(resp, 'content_length', None) is not None else 0
                                    return SiteResult(site_name, url_main, url_user, "found", status_code, response_time, metadata={"content_length": content_length})
                                elif status_code in (301, 302):
                                    return SiteResult(site_name, url_main, url_user, "found", status_code, response_time, metadata={"redirect": True})
                                elif status_code == 429:
                                    return SiteResult(site_name, url_main, url_user, "blocked", status_code, response_time, "Rate limited")
                                else:
                                    return SiteResult(site_name, url_main, url_user, "error", status_code, response_time, f"Status: {status_code}")
                            
                            elif error_type == "message":
                                body = await resp.text()
                                pattern = self.error_patterns.get(site_name)
                                if pattern and pattern.search(body):
                                    return SiteResult(site_name, url_main, url_user, "not_found", status_code, response_time)
                                else:
                                    return SiteResult(site_name, url_main, url_user, "found", status_code, response_time, metadata={"content_length": len(body)})
                            
                            else:
                                return SiteResult(site_name, url_main, url_user, "error", status_code, response_time, f"Unknown error type: {error_type}")
                                
                except asyncio.TimeoutError:
                    return SiteResult(site_name, url_main, url_user, "error", None, time.time() - start, "Timeout")
                except Exception as e:
                    return SiteResult(site_name, url_main, url_user, "error", None, time.time() - start, str(e))
        
        tasks = [check_one(name, config) for name, config in site_list.items()]
        results = await asyncio.gather(*tasks)
        
        scan_duration = time.time() - start_time
        
        found = sum(1 for r in results if r.status == "found")
        not_found = sum(1 for r in results if r.status == "not_found")
        errors = sum(1 for r in results if r.status == "error")
        blocked_count = sum(1 for r in results if r.status == "blocked")
        
        results = sorted(results, key=lambda x: (
            0 if x.status == "found" else 1,
            0 if x.status == "blocked" else 1,
            x.response_time
        ))
        
        return SherlockReport(
            username=username,
            total_sites=total_sites,
            sites_checked=total_sites,
            sites_found=found,
            sites_not_found=not_found,
            sites_error=errors,
            sites_blocked=blocked_count,
            results=list(results),
            scan_duration=scan_duration
        )
    
    def search_multiple(
        self,
        usernames: List[str],
        sites: Optional[List[str]] = None
    ) -> Dict[str, SherlockReport]:
        reports = {}
        for username in usernames:
            reports[username] = self.search(username, sites=sites)
        return reports
    
    def get_found_profiles(self, report: SherlockReport) -> List[SiteResult]:
        return [r for r in report.results if r.status == "found"]
    
    def export_report(self, report: SherlockReport, filepath: str, format: str = "json") -> str:
        if format == "json":
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(report.to_dict(), f, indent=2, ensure_ascii=False)
        elif format == "csv":
            import csv
            found = self.get_found_profiles(report)
            with open(filepath, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Site", "URL", "Status", "HTTP Status", "Response Time"])
                for r in found:
                    writer.writerow([r.site_name, r.url_user, r.status, r.http_status, r.response_time])
        
        logger.info(f"Report exported to {filepath}")
        return filepath