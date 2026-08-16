from urllib.parse import urlparse, parse_qs

class RedirectChecker:
    def check(self, url: str) -> dict:
        suspicious_params = ['next', 'url', 'redirect', 'return', 'go', 'out']
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        vulnerable_params = []
        for param in suspicious_params:
            if param in params:
                vulnerable_params.append(param)
                
        return {
            "status": "success",
            "risk_level": "MEDIUM" if vulnerable_params else "INFO",
            "suspicious_parameters": vulnerable_params,
            "message": "Ditemukan parameter berpotensi Open Redirect." if vulnerable_params else "Tidak ditemukan indikasi pola parameter Open Redirect umum. (Bukan jaminan aman mutlak)."
        }