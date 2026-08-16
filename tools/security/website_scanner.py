from tools.security.headers.header_analyzer import HeaderAnalyzer
from tools.security.ssl.ssl_checker import SSLChecker
from tools.security.recon.tech_detector import TechDetector
from tools.security.vuln.redirect_checker import RedirectChecker
from tools.security.vuln.csrf_checker import CSRFChecker
import time
from datetime import datetime

class WebsiteScanner:
    def __init__(self):
        self.name = "security"
        self.header_analyzer = HeaderAnalyzer()
        self.ssl_checker = SSLChecker()
        self.tech_detector = TechDetector()
        self.redirect_checker = RedirectChecker()
        self.csrf_checker = CSRFChecker()

    def execute(self, url: str, **kwargs) -> dict:
        start_time = time.time()
        
        if not url.startswith('http'):
            url = 'https://' + url

        results = {
            "metadata": {
                "scan_date": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
                "scanner": "C4therine Security Framework v1.0",
                "target": url
            },
            "tech_stack": self.tech_detector.detect(url),
            "headers": self.header_analyzer.analyze(url),
            "ssl": self.ssl_checker.check(url),
            "vulnerabilities": {
                "open_redirect": self.redirect_checker.check(url),
                "csrf_protection": self.csrf_checker.check(url)
            }
            # Catatan: Modul Cookie & Config akan diinjeksikan di sini pada iterasi berikutnya
        }

        # 1. SSL Score
        ssl_score = 100 if results["ssl"].get("valid") else 0
        
        # 2. Header Score
        header_score = 100
        missing_hdrs = results["headers"].get("missing", [])
        if missing_hdrs:
            header_score = max(0, 100 - (len(missing_hdrs) * 20))
            
        # 3. Vulnerability Score
        vuln_score = 100
        if results["vulnerabilities"]["csrf_protection"].get("risk_level") == "HIGH":
            vuln_score -= 40
        if results["vulnerabilities"]["open_redirect"].get("risk_level") == "MEDIUM":
            vuln_score -= 20

        # Overall Score Calculation (Disiapkan untuk metrik masa depan)
        # Asumsi Cookie, Config, dan Exposure saat ini default 100 jika belum di-scan
        cookie_score = 100 
        config_score = 100
        exposure_score = 100

        overall_score = (ssl_score * 0.2) + (header_score * 0.2) + (vuln_score * 0.3) + (cookie_score * 0.1) + (config_score * 0.1) + (exposure_score * 0.1)
        
        results["scores"] = {
            "overall": int(overall_score),
            "ssl_tls": ssl_score,
            "headers": header_score,
            "vulnerability": vuln_score,
            "cookie_security": cookie_score,
            "configuration": config_score,
            "information_exposure": exposure_score
        }
        
        scan_duration = round(time.time() - start_time, 2)
        results["metadata"]["duration_seconds"] = scan_duration
        
        return {"status": "success", "data": results}