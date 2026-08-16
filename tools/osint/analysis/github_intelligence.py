import re
import json
import base64
import logging
import urllib.request
import urllib.error
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime
from urllib.parse import quote

logger = logging.getLogger("osint.github_intel")


@dataclass
class GitHubProfile:
    """GitHub user profile."""
    username: str
    url: str = ""
    name: Optional[str] = None
    email: Optional[str] = None
    bio: Optional[str] = None
    company: Optional[str] = None
    location: Optional[str] = None
    blog: Optional[str] = None
    twitter_username: Optional[str] = None
    followers: int = 0
    following: int = 0
    public_repos: int = 0
    public_gists: int = 0
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    avatar_url: Optional[str] = None
    hireable: Optional[bool] = None
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class GitHubRepo:
    """GitHub repository."""
    name: str
    full_name: str
    url: str = ""
    description: Optional[str] = None
    language: Optional[str] = None
    stars: int = 0
    forks: int = 0
    is_fork: bool = False
    is_private: bool = False
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    topics: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class GitHubCommit:
    """GitHub commit."""
    sha: str
    repo: str
    message: str = ""
    author_name: Optional[str] = None
    author_email: Optional[str] = None
    author_date: Optional[str] = None
    committer_name: Optional[str] = None
    committer_email: Optional[str] = None
    committer_date: Optional[str] = None
    
    def to_dict(self) -> dict:
        return asdict(self)


class GitHubIntelligence:
    """
    GitHub OSINT intelligence engine.
    """
    
    API_BASE = "https://api.github.com"
    RAW_BASE = "https://raw.githubusercontent.com"
    
    # Secret patterns untuk basic detection
    SECRET_PATTERNS = {
        "aws_access_key": r"AKIA[0-9A-Z]{16}",
        "aws_secret_key": r"[0-9a-zA-Z/+]{40}",
        "github_token": r"gh[pousr]_[A-Za-z0-9_]{36,}",
        "slack_token": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
        "private_key": r"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
        "api_key_generic": r"[aA][pP][iI][_-]?[kK][eE][yY][\\s]*[=:][\\s]*[\\'\"]?[a-zA-Z0-9]{16,}[\\'\"]?",
        "password_in_code": r"[pP][aA][sS][sS][wW][oO][rR][dD][\\s]*[=:][\\s]*[\\'\"][^\\'\"]{4,}[\\'\"]",
    }
    
    def __init__(self, api_token: Optional[str] = None, timeout: int = 15):
        """
        Initialize GitHub intelligence.
        
        Args:
            api_token: GitHub personal access token (increases rate limit)
            timeout: Request timeout
        """
        self.api_token = api_token
        self.timeout = timeout
    
    def _api_request(self, endpoint: str) -> Optional[Any]:
        """Make authenticated GitHub API request."""
        url = f"{self.API_BASE}/{endpoint}"
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "OSINT-Engine-v3.0",
        }
        
        if self.api_token:
            headers["Authorization"] = f"token {self.api_token}"
        
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                return json.loads(response.read().decode())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            elif e.code == 403:
                logger.warning("GitHub rate limited. Use API token untuk increase limit.")
                return None
            logger.error(f"GitHub API HTTP {e.code}: {e.reason}")
            return None
        except Exception as e:
            logger.error(f"GitHub API error: {e}")
            return None
    
    def get_user(self, username: str) -> Optional[GitHubProfile]:
        """
        Get GitHub user profile.
        
        Args:
            username: GitHub username
            
        Returns:
            GitHubProfile atau None
        """
        logger.info(f"[GitHub] Fetching user: {username}")
        
        data = self._api_request(f"users/{quote(username)}")
        if not data:
            return None
        
        profile = GitHubProfile(
            username=data.get("login", username),
            url=data.get("html_url", ""),
            name=data.get("name"),
            email=data.get("email"),
            bio=data.get("bio"),
            company=data.get("company"),
            location=data.get("location"),
            blog=data.get("blog"),
            twitter_username=data.get("twitter_username"),
            followers=data.get("followers", 0),
            following=data.get("following", 0),
            public_repos=data.get("public_repos", 0),
            public_gists=data.get("public_gists", 0),
            created_at=data.get("created_at"),
            updated_at=data.get("updated_at"),
            avatar_url=data.get("avatar_url"),
            hireable=data.get("hireable")
        )
        
        logger.info(f"[GitHub] Found user: {profile.name or profile.username}")
        return profile
    
    def get_repos(self, username: str, max_repos: int = 100) -> List[GitHubRepo]:
        """
        Get user repositories.
        
        Args:
            username: GitHub username
            max_repos: Maximum repositories to fetch
            
        Returns:
            List of GitHubRepo objects
        """
        logger.info(f"[GitHub] Fetching repos for: {username}")
        
        data = self._api_request(f"users/{quote(username)}/repos?per_page={min(max_repos, 100)}")
        if not data:
            return []
        
        repos = []
        for repo_data in data:
            repo = GitHubRepo(
                name=repo_data.get("name", ""),
                full_name=repo_data.get("full_name", ""),
                url=repo_data.get("html_url", ""),
                description=repo_data.get("description"),
                language=repo_data.get("language"),
                stars=repo_data.get("stargazers_count", 0),
                forks=repo_data.get("forks_count", 0),
                is_fork=repo_data.get("fork", False),
                is_private=repo_data.get("private", False),
                created_at=repo_data.get("created_at"),
                updated_at=repo_data.get("updated_at"),
                topics=repo_data.get("topics", [])
            )
            repos.append(repo)
        
        logger.info(f"[GitHub] Found {len(repos)} repos for {username}")
        return repos
    
    def get_commits(self, username: str, repo: str, max_commits: int = 100) -> List[GitHubCommit]:
        """
        Get commits dari repository.
        
        Args:
            username: Repository owner
            repo: Repository name
            max_commits: Maximum commits to fetch
            
        Returns:
            List of GitHubCommit objects
        """
        logger.info(f"[GitHub] Fetching commits: {username}/{repo}")
        
        data = self._api_request(
            f"repos/{quote(username)}/{quote(repo)}/commits?per_page={min(max_commits, 100)}"
        )
        if not data:
            return []
        
        commits = []
        for commit_data in data:
            commit_info = commit_data.get("commit", {})
            author = commit_info.get("author", {})
            committer = commit_info.get("committer", {})
            
            commit = GitHubCommit(
                sha=commit_data.get("sha", "")[:7],
                repo=f"{username}/{repo}",
                message=commit_info.get("message", ""),
                author_name=author.get("name"),
                author_email=author.get("email"),
                author_date=author.get("date"),
                committer_name=committer.get("name"),
                committer_email=committer.get("email"),
                committer_date=committer.get("date")
            )
            commits.append(commit)
        
        logger.info(f"[GitHub] Found {len(commits)} commits in {repo}")
        return commits
    
    def extract_emails_from_commits(self, username: str, max_repos: int = 10) -> Set[str]:
        """
        Extract unique email addresses dari commit history.
        
        Args:
            username: GitHub username
            max_repos: Maximum repos to check
            
        Returns:
            Set of email addresses
        """
        logger.info(f"[GitHub] Extracting emails from commits: {username}")
        
        repos = self.get_repos(username, max_repos)
        emails = set()
        
        for repo in repos:
            if repo.is_fork:
                continue
            
            commits = self.get_commits(username, repo.name, max_commits=50)
            for commit in commits:
                if commit.author_email:
                    emails.add(commit.author_email)
                if commit.committer_email and commit.committer_email != commit.author_email:
                    emails.add(commit.committer_email)
        
        logger.info(f"[GitHub] Extracted {len(emails)} unique emails")
        return emails
    
    def get_organizations(self, username: str) -> List[Dict[str, Any]]:
        """
        Get organizations yang diikuti user.
        
        Returns:
            List of organization dicts
        """
        logger.info(f"[GitHub] Fetching organizations for: {username}")
        
        data = self._api_request(f"users/{quote(username)}/orgs")
        if not data:
            return []
        
        orgs = []
        for org in data:
            orgs.append({
                "login": org.get("login"),
                "url": org.get("html_url"),
                "description": org.get("description"),
                "avatar_url": org.get("avatar_url")
            })
        
        logger.info(f"[GitHub] Found {len(orgs)} organizations")
        return orgs
    
    def get_gists(self, username: str) -> List[Dict[str, Any]]:
        """
        Get user gists.
        
        Returns:
            List of gist dicts
        """
        logger.info(f"[GitHub] Fetching gists for: {username}")
        
        data = self._api_request(f"users/{quote(username)}/gists")
        if not data:
            return []
        
        gists = []
        for gist in data:
            gists.append({
                "id": gist.get("id"),
                "url": gist.get("html_url"),
                "description": gist.get("description"),
                "created_at": gist.get("created_at"),
                "updated_at": gist.get("updated_at"),
                "files": list(gist.get("files", {}).keys())
            })
        
        return gists
    
    def scan_for_secrets(self, username: str, repo: str, 
                         file_paths: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Basic secrets scanning dalam repository files.
        
        Args:
            username: Repository owner
            repo: Repository name
            file_paths: Specific files to scan (None = common config files)
            
        Returns:
            List of potential secret findings
        """
        if file_paths is None:
            file_paths = [
                ".env", ".env.example", "config.json", "secrets.json",
                "docker-compose.yml", "kubernetes.yml", ".travis.yml",
                "Makefile", "package.json", "requirements.txt"
            ]
        
        findings = []
        
        for file_path in file_paths:
            try:
                url = f"{self.RAW_BASE}/{quote(username)}/{quote(repo)}/HEAD/{quote(file_path)}"
                req = urllib.request.Request(url, headers={"User-Agent": "OSINT-Engine-v3.0"})
                with urllib.request.urlopen(req, timeout=10) as response:
                    content = response.read().decode("utf-8", errors="replace")
                
                for secret_type, pattern in self.SECRET_PATTERNS.items():
                    matches = re.finditer(pattern, content, re.MULTILINE)
                    for match in matches:
                        # Get context (5 lines around match)
                        lines = content[:match.start()].count("\\n")
                        
                        findings.append({
                            "file": file_path,
                            "type": secret_type,
                            "line": lines + 1,
                            "match": match.group()[:50] + "..." if len(match.group()) > 50 else match.group(),
                            "severity": "critical" if secret_type in ("private_key", "github_token") else "high"
                        })
                        
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    continue
            except Exception as e:
                logger.debug(f"Error scanning {file_path}: {e}")
        
        logger.info(f"[GitHub] Found {len(findings)} potential secrets in {repo}")
        return findings
    
    def get_contributors(self, username: str, repo: str) -> List[Dict[str, Any]]:
        """
        Get repository contributors.
        
        Returns:
            List of contributor dicts
        """
        data = self._api_request(f"repos/{quote(username)}/{quote(repo)}/contributors")
        if not data:
            return []
        
        return [
            {
                "username": c.get("login"),
                "contributions": c.get("contributions", 0),
                "url": c.get("html_url")
            }
            for c in data
        ]
    
    def get_repo_languages(self, username: str, repo: str) -> Dict[str, int]:
        """
        Get repository language breakdown.
        
        Returns:
            Dict of language -> bytes
        """
        data = self._api_request(f"repos/{quote(username)}/{quote(repo)}/languages")
        return data or {}
    
    def analyze_user(self, username: str) -> Dict[str, Any]:
        """
        Comprehensive user analysis.
        
        Returns:
            Complete analysis dict
        """
        logger.info(f"[GitHub] Analyzing user: {username}")
        
        profile = self.get_user(username)
        if not profile:
            return {"error": "User not found"}
        
        repos = self.get_repos(username, max_repos=50)
        orgs = self.get_organizations(username)
        gists = self.get_gists(username)
        
        # Extract emails dari commits
        emails = self.extract_emails_from_commits(username, max_repos=10)
        
        # Calculate stats
        total_stars = sum(r.stars for r in repos)
        total_forks = sum(r.forks for r in repos)
        languages = {}
        for repo in repos:
            if repo.language:
                languages[repo.language] = languages.get(repo.language, 0) + 1
        
        # Timeline
        if profile.created_at:
            try:
                account_age_days = (datetime.now() - datetime.fromisoformat(
                    profile.created_at.replace("Z", "+00:00")
                )).days
            except ValueError:
                account_age_days = 0
        else:
            account_age_days = 0
        
        analysis = {
            "username": username,
            "profile": profile.to_dict(),
            "repositories": {
                "total": len(repos),
                "original": sum(1 for r in repos if not r.is_fork),
                "forked": sum(1 for r in repos if r.is_fork),
                "total_stars": total_stars,
                "total_forks": total_forks,
                "languages": dict(sorted(languages.items(), key=lambda x: x[1], reverse=True))
            },
            "organizations": orgs,
            "gists": len(gists),
            "emails_extracted": sorted(emails),
            "account_age_days": account_age_days,
            "activity_score": self._calculate_activity_score(profile, repos)
        }
        
        logger.info(f"[GitHub] Analysis complete for {username}")
        return analysis
    
    def _calculate_activity_score(self, profile: GitHubProfile, repos: List[GitHubRepo]) -> int:
        """Calculate activity score (0-100)."""
        score = 0
        
        # Followers
        if profile.followers > 1000:
            score += 20
        elif profile.followers > 100:
            score += 10
        elif profile.followers > 10:
            score += 5
        
        # Repos
        if len(repos) > 50:
            score += 20
        elif len(repos) > 20:
            score += 15
        elif len(repos) > 5:
            score += 10
        
        # Stars
        total_stars = sum(r.stars for r in repos)
        if total_stars > 1000:
            score += 20
        elif total_stars > 100:
            score += 10
        elif total_stars > 10:
            score += 5
        
        # Account age
        if profile.created_at:
            try:
                age_days = (datetime.now() - datetime.fromisoformat(
                    profile.created_at.replace("Z", "+00:00")
                )).days
                if age_days > 365 * 5:
                    score += 20
                elif age_days > 365 * 2:
                    score += 10
                elif age_days > 365:
                    score += 5
            except ValueError:
                pass
        
        # Profile completeness
        if profile.bio:
            score += 5
        if profile.company:
            score += 5
        if profile.blog:
            score += 5
        
        return min(score, 100)
    
    def export_analysis(self, analysis: Dict[str, Any], filepath: str) -> str:
        """Export analysis ke JSON."""
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(analysis, f, indent=2, ensure_ascii=False)
        return filepath