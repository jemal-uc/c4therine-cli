import requests
import re

class TechDetector:
    def detect(self, url: str) -> dict:
        technologies = []
        try:
            response = requests.get(url, timeout=10, verify=False)
            headers = response.headers
            html = response.text.lower()

            # Deteksi Server
            server = headers.get('Server', '')
            if server:
                technologies.append(f"Server: {server}")

            # Deteksi Backend
            powered_by = headers.get('X-Powered-By', '')
            if powered_by:
                technologies.append(f"Backend: {powered_by}")

            # Analisis Signature HTML Kasar
            if 'wp-content' in html or 'wordpress' in html:
                technologies.append("CMS: WordPress")
            if 'laravel_session' in response.cookies.keys():
                technologies.append("Framework: Laravel")
            if '<div id="root">' in html or 'react' in html:
                technologies.append("Frontend: React")
            if 'vue' in html:
                technologies.append("Frontend: Vue.js")

            return {
                "status": "success",
                "detected": technologies if technologies else ["Unknown/Obfuscated"]
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}