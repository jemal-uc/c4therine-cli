import requests

class HeaderAnalyzer:
    def analyze(self, url: str) -> dict:
        target_headers = [
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy"
        ]
        
        try:
            # Pastikan URL menggunakan skema http/https
            if not url.startswith('http'):
                url = 'https://' + url
                
            response = requests.get(url, timeout=10, verify=False)
            headers = response.headers
            
            found = {}
            missing = []
            
            for h in target_headers:
                if h in headers:
                    found[h] = headers[h]
                else:
                    missing.append(h)
                    
            # Kalkulasi skor kasar (tiap missing header -20 poin)
            score = max(0, 100 - (len(missing) * 20))
            
            return {
                "status": "success",
                "score": score,
                "found": found,
                "missing": missing
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}