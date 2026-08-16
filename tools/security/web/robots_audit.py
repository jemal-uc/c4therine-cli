import requests

class RobotsAudit:
    def audit(self, url: str) -> dict:
        target_url = url.rstrip('/') + '/robots.txt'
        disallowed_paths = []
        try:
            response = requests.get(target_url, timeout=10, verify=False)
            if response.status_code == 200:
                lines = response.text.split('\n')
                for line in lines:
                    if line.lower().startswith('disallow:'):
                        path = line.split(':', 1)[1].strip()
                        if path:
                            disallowed_paths.append(path)
                            
                return {
                    "status": "success",
                    "found": True,
                    "disallowed_count": len(disallowed_paths),
                    "disallowed_preview": disallowed_paths[:5]
                }
            return {"status": "success", "found": False, "message": "robots.txt tidak ditemukan."}
        except Exception as e:
            return {"status": "error", "message": str(e)}