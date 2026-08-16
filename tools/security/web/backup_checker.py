import requests

class BackupChecker:
    def check(self, url: str) -> dict:
        base_url = url.rstrip('/')
        # Daftar arsip umum yang berisiko terekspos
        payloads = ['/backup.zip', '/database.sql', '/.env', '/config.php.bak']
        exposed = []
        
        try:
            for payload in payloads:
                target = base_url + payload
                # Gunakan metode HEAD untuk efisiensi bandwidth
                response = requests.head(target, timeout=5, verify=False)
                if response.status_code == 200:
                    exposed.append(payload)
                    
            return {
                "status": "success",
                "exposed_files": exposed,
                "risk_level": "HIGH" if exposed else "LOW"
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}