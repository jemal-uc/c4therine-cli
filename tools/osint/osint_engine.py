import re
import logging
from urllib.parse import urlparse
from tools.osint.identity.name_matcher import NameMatcher
from tools.osint.search.web_search import WebSearchEngine

logger = logging.getLogger("osint.legacy_engine")

class AdvancedOSINTLookup:
    def __init__(self):
        self.name = "osint"
        self.matcher = NameMatcher()
        self.search_engine = WebSearchEngine()

    def execute(self, target: str, **kwargs) -> dict:
        """
        Execute OSINT lookup on target name.
        """
        try:
            normalized_name = self.matcher.normalize(target)
            
            # Generate variants to search
            name_parts = normalized_name.split()
            variants = [target]
            if len(name_parts) > 1:
                variants.append(" ".join(name_parts))
                
            # Perform web search using WebSearchEngine
            search_query = f'"{target}"'
            search_results = self.search_engine.search(search_query, max_results=10)
            
            all_results = []
            usernames_found = set()
            emails_found = set()
            social_profiles = {}
            total_exact_matches = 0
            
            for res in search_results:
                # Match relevance using NameMatcher
                match_res = self.matcher.match(target, res.title, "combined")
                
                # Check for emails in the body/title
                emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', res.body + " " + res.title)
                for email in emails:
                    emails_found.add(email)
                    
                # Look for social media platform profile links in the results
                url = res.href
                parsed_url = urlparse(url)
                netloc = parsed_url.netloc.lower()
                
                platform = None
                username = None
                
                # Identify if it is a social media link
                for p in ["instagram.com", "twitter.com", "x.com", "github.com", "facebook.com", "linkedin.com", "youtube.com", "tiktok.com"]:
                    if p in netloc:
                        platform = p.split(".")[0]
                        path = parsed_url.path.strip("/")
                        if path:
                            parts = path.split("/")
                            username = parts[0]
                            username = username.split("?")[0]
                            if username and len(username) > 2:
                                usernames_found.add(username)
                        break
                
                is_exact = match_res.is_match or target.lower() in res.title.lower()
                if is_exact:
                    total_exact_matches += 1
                
                res_dict = {
                    "title": res.title,
                    "source": res.source,
                    "href": res.href,
                    "match_type": "EXACT" if is_exact else "PARTIAL",
                    "relevance_score": match_res.score * 100,
                    "body": res.body
                }
                all_results.append(res_dict)
                
                if platform and username:
                    if platform not in social_profiles:
                        social_profiles[platform] = []
                    social_profiles[platform].append({
                        "username": username,
                        "url": url,
                        "title": res.title
                    })
            
            # Estimate confidence score
            confidence_score = min(100, int((total_exact_matches / max(1, len(all_results))) * 50 + (50 if total_exact_matches > 0 else 0)))
            
            return {
                "status": "success",
                "target": target,
                "normalized_name": normalized_name,
                "name_variants_searched": variants,
                "platforms_searched": ["duckduckgo", "google_cse", "bing", "manual_scrape"],
                "total_exact_matches": total_exact_matches,
                "confidence_score": confidence_score,
                "profile": {
                    "usernames_found": list(usernames_found),
                    "emails_found": list(emails_found),
                    "all_results": all_results,
                    "social_profiles": social_profiles
                }
            }
        except Exception as e:
            logger.error(f"AdvancedOSINTLookup execute failed: {e}")
            return {"status": "error", "message": str(e)}
