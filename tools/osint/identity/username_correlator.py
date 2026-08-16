import re
import time
import logging
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime
from urllib.parse import quote

import urllib.request
import urllib.error

logger = logging.getLogger("osint.username_correlator")


@dataclass
class UsernameProfile:
    """Profile username di satu platform."""
    username: str
    platform: str
    url: str
    profile_data: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0
    checked_at: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> dict:
        return asdict(self)


class UsernameCorrelator:
    """
    Cross-platform username correlation engine.
    Cek username existence di 40+ platform.
    """
    
    # Platform URL templates
    PLATFORM_URLS = {
        # Social Media
        "github": "https://github.com/{username}",
        "gitlab": "https://gitlab.com/{username}",
        "twitter_x": "https://x.com/{username}",
        "twitter_legacy": "https://twitter.com/{username}",
        "instagram": "https://www.instagram.com/{username}/",
        "reddit": "https://www.reddit.com/user/{username}/",
        "tiktok": "https://www.tiktok.com/@{username}",
        "pinterest": "https://www.pinterest.com/{username}/",
        "stackoverflow": "https://stackoverflow.com/users/{username}",
        "steam": "https://steamcommunity.com/id/{username}",
        "youtube": "https://www.youtube.com/@{username}",
        "linkedin": "https://www.linkedin.com/in/{username}/",
        "medium": "https://medium.com/@{username}",
        "deviantart": "https://www.deviantart.com/{username}",
        "twitch": "https://www.twitch.tv/{username}",
        "keybase": "https://keybase.io/{username}",
        "facebook": "https://www.facebook.com/{username}",
        "snapchat": "https://www.snapchat.com/add/{username}",
        "telegram": "https://t.me/{username}",
        "discord": "https://discord.com/users/{username}",
        
        # Development
        "bitbucket": "https://bitbucket.org/{username}/",
        "codepen": "https://codepen.io/{username}",
        "devto": "https://dev.to/{username}",
        "replit": "https://replit.com/@{username}",
        "hackerrank": "https://www.hackerrank.com/{username}",
        "leetcode": "https://leetcode.com/{username}/",
        "kaggle": "https://www.kaggle.com/{username}",
        "freecodecamp": "https://www.freecodecamp.org/{username}",
        "codecademy": "https://www.codecademy.com/profiles/{username}",
        "codewars": "https://www.codewars.com/users/{username}",
        "exercism": "https://exercism.org/profiles/{username}",
        "tryhackme": "https://tryhackme.com/p/{username}",
        "hackthebox": "https://app.hackthebox.com/profile/{username}",
        
        # Content
        "wordpress": "https://{username}.wordpress.com",
        "blogger": "https://{username}.blogspot.com",
        "tumblr": "https://{username}.tumblr.com",
        "substack": "https://{username}.substack.com",
        "ghost": "https://{username}.ghost.io",
        
        # Creative
        "behance": "https://www.behance.net/{username}",
        "dribbble": "https://dribbble.com/{username}",
        "flickr": "https://www.flickr.com/people/{username}/",
        "unsplash": "https://unsplash.com/@{username}",
        "500px": "https://500px.com/p/{username}",
        "imgur": "https://imgur.com/user/{username}",
        
        # Gaming
        "roblox": "https://www.roblox.com/user.aspx?username={username}",
        "namemc": "https://namemc.com/profile/{username}",
        
        # Forums
        "quora": "https://www.quora.com/profile/{username}",
        "goodreads": "https://www.goodreads.com/{username}",
        "wattpad": "https://www.wattpad.com/user/{username}",
        
        # Professional
        "aboutme": "https://about.me/{username}",
        "gravatar": "https://en.gravatar.com/{username}",
        "slideshare": "https://www.slideshare.net/{username}",
        "angellist": "https://angel.co/u/{username}",
        
        # Indonesian
        "kaskus": "https://www.kaskus.co.id/@{username}",
        "tokopedia": "https://www.tokopedia.com/{username}",
        "bukalapak": "https://www.bukalapak.com/u/{username}",
        "shopee": "https://shopee.co.id/{username}",
    }
    
    # User agents untuk rotation
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    ]
    
    def __init__(self, timeout: int = 10, delay: float = 0.5):
        """
        Initialize username correlator.
        
        Args:
            timeout: Request timeout
            delay: Delay antara requests (rate limiting)
        """
        self.timeout = timeout
        self.delay = delay
        self.ua_index = 0
    
    def _get_ua(self) -> str:
        """Get next User-Agent."""
        ua = self.USER_AGENTS[self.ua_index % len(self.USER_AGENTS)]
        self.ua_index += 1
        return ua
    
    def _check_url(self, url: str) -> Tuple[bool, Optional[str], Optional[Dict]]:
        """
        Check URL dengan HEAD request.
        
        Returns:
            Tuple of (exists, redirect_url, response_info)
        """
        try:
            req = urllib.request.Request(
                url,
                method="HEAD",
                headers={"User-Agent": self._get_ua()},
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                return True, None, {"status": response.status, "headers": dict(response.headers)}
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return False, None, {"status": 404}
            elif e.code in (301, 302, 307, 308):
                return True, e.headers.get("Location"), {"status": e.code, "redirect": e.headers.get("Location")}
            return False, None, {"status": e.code, "error": str(e)}
        except Exception as e:
            return False, None, {"error": str(e)}
    
    def _extract_profile_data(self, url: str) -> Dict[str, Any]:
        """Extract profile data dari halaman jika bisa di-fetch."""
        data = {}
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": self._get_ua()},
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                html = response.read().decode("utf-8", errors="replace")
                
                # Extract title
                title_match = re.search(r"<title>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
                if title_match:
                    data["page_title"] = title_match.group(1).strip()
                
                # Extract meta description
                desc_match = re.search(
                    r'<meta[^>]*name=["\']description["\'][^>]*content=["\']([^"\']+)',
                    html, re.IGNORECASE
                )
                if desc_match:
                    data["description"] = desc_match.group(1).strip()
                
                # Extract OG image
                img_match = re.search(
                    r'<meta[^>]*property=["\']og:image["\'][^>]*content=["\']([^"\']+)',
                    html, re.IGNORECASE
                )
                if img_match:
                    data["profile_image"] = img_match.group(1).strip()
        except Exception:
            pass
        
        return data
    
    def correlate(
        self,
        username: str,
        platforms: Optional[List[str]] = None,
        source_platform: Optional[str] = None,
        extract_data: bool = False
    ) -> List[UsernameProfile]:
        """
        Cek username di semua platform.
        
        Args:
            username: Username to check
            platforms: Specific platforms (None = all)
            source_platform: Platform where username was originally found
            extract_data: Extract profile page data
            
        Returns:
            List of UsernameProfile untuk platforms yang ditemukan
        """
        logger.info(f"[UsernameCorrelator] Checking \"{username}\" across platforms...")
        
        if platforms is None:
            platforms = list(self.PLATFORM_URLS.keys())
        
        profiles = []
        
        for platform in platforms:
            if platform == source_platform:
                continue
            
            url_template = self.PLATFORM_URLS.get(platform)
            if not url_template:
                continue
            
            url = url_template.format(username=quote(username, safe=""))
            
            # Check URL
            exists, redirect, info = self._check_url(url)
            
            if exists or redirect:
                final_url = redirect or url
                
                # Calculate confidence
                confidence = 50.0  # Base
                
                # Extract profile data jika diminta
                profile_data = {}
                if extract_data:
                    profile_data = self._extract_profile_data(final_url)
                    if profile_data:
                        confidence += 20.0
                
                # Bonus jika username exact match di URL
                if username.lower() in final_url.lower():
                    confidence += 15.0
                
                # Bonus jika status 200 (bukan redirect)
                if info and info.get("status") == 200:
                    confidence += 10.0
                
                profiles.append(UsernameProfile(
                    username=username,
                    platform=platform,
                    url=final_url,
                    profile_data=profile_data,
                    confidence=min(confidence, 100.0)
                ))
                
                logger.info(f"  [FOUND] {platform}: {final_url}")
            
            time.sleep(self.delay)  # Rate limiting
        
        # Sort by confidence
        profiles.sort(key=lambda x: x.confidence, reverse=True)
        logger.info(f"[UsernameCorrelator] Found {len(profiles)} platform matches")
        
        return profiles
    
    def generate_variants(self, username: str) -> List[str]:
        """
        Generate variasi username yang mirip.
        Useful untuk find aliases atau related accounts.
        
        Returns:
            List of username variants
        """
        variants = set()
        variants.add(username)
        variants.add(username.lower())
        variants.add(username.upper())
        
        # Common leet substitutions
        leet_map = {
            'a': ['4', '@'],
            'e': ['3'],
            'i': ['1', '!'],
            'o': ['0'],
            's': ['5', '$'],
            't': ['7'],
            'l': ['1'],
            'g': ['9'],
            'b': ['8'],
        }
        
        # Generate leet variants
        for char, replacements in leet_map.items():
            for rep in replacements:
                if char in username.lower():
                    variants.add(username.lower().replace(char, rep))
                    variants.add(username.lower().replace(char, rep).capitalize())
        
        # Add common separators
        for sep in ['', '_', '.', '-']:
            variants.add(f"{username}{sep}")
            variants.add(f"{sep}{username}")
        
        # Add year suffixes
        current_year = datetime.now().year
        for year in range(current_year - 15, current_year + 1):
            variants.add(f"{username}{year}")
            variants.add(f"{username}_{year}")
            variants.add(f"{username}-{year}")
        
        # Add common suffixes
        for suffix in ['official', 'real', 'hq', 'team', 'dev', 'bot', 'news']:
            variants.add(f"{username}{suffix}")
            variants.add(f"{username}_{suffix}")
        
        # Add common prefixes
        for prefix in ['the', 'real', 'official', 'its', 'iam', 'mr', 'ms']:
            variants.add(f"{prefix}{username}")
            variants.add(f"{prefix}_{username}")
        
        return sorted(list(variants))
    
    def find_similar_accounts(
        self,
        username: str,
        platforms: Optional[List[str]] = None
    ) -> Dict[str, List[UsernameProfile]]:
        """
        Find similar usernames across platforms.
        
        Returns:
            Dict mapping variant -> list of profiles
        """
        variants = self.generate_variants(username)
        results = {}
        
        for variant in variants[:20]:  # Limit untuk avoid too many requests
            profiles = self.correlate(variant, platforms=platforms)
            if profiles:
                results[variant] = profiles
        
        return results
    
    def get_platform_url(self, username: str, platform: str) -> Optional[str]:
        """Get URL untuk username di specific platform."""
        template = self.PLATFORM_URLS.get(platform)
        if template:
            return template.format(username=quote(username, safe=""))
        return None
    
    def add_platform(self, platform: str, url_template: str) -> None:
        """Add custom platform."""
        self.PLATFORM_URLS[platform] = url_template
        logger.info(f"Added platform: {platform}")
    
    def export_results(self, profiles: List[UsernameProfile], filepath: str) -> str:
        """Export correlation results ke JSON."""
        data = {
            "username": profiles[0].username if profiles else None,
            "total_platforms": len(profiles),
            "platforms": [p.to_dict() for p in profiles]
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return filepath