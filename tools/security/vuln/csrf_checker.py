import requests
from bs4 import BeautifulSoup

class CSRFChecker:
    def check(self, url: str) -> dict:
        try:
            response = requests.get(url, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            if len(forms) == 0:
                return {
                    "status": "success",
                    "risk_level": "INFO",
                    "forms_detected": 0,
                    "unprotected_forms": 0,
                    "message": "N/A (Not Applicable) - Tidak ada elemen form HTML yang terdeteksi untuk dianalisis."
                }
            
            unprotected_forms = 0
            for form in forms:
                tokens = form.find_all('input', {'type': 'hidden'})
                token_names = [t.get('name', '').lower() for t in tokens]
                if not any('csrf' in name or 'token' in name for name in token_names):
                    unprotected_forms += 1
                    
            risk = "HIGH" if unprotected_forms > 0 else "LOW"
            return {
                "status": "success",
                "risk_level": risk,
                "forms_detected": len(forms),
                "unprotected_forms": unprotected_forms,
                "message": f"Ditemukan {unprotected_forms} form tanpa perlindungan token CSRF." if unprotected_forms > 0 else "Seluruh form memiliki indikasi token pelindung."
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}