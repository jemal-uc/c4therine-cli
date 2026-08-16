import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse

class SSLChecker:
    def check(self, url: str) -> dict:
        try:
            # Parsing untuk mendapatkan hostname murni (tanpa https:// atau path)
            parsed = urlparse(url)
            hostname = parsed.netloc if parsed.netloc else parsed.path
            hostname = hostname.split('/')[0] # Bersihkan sisa path jika ada
            
            context = ssl.create_default_context()
            
            # Membuka koneksi socket ke port 443 (HTTPS)
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Ekstrak informasi Issuer
                    issuer = dict(x[0] for x in cert['issuer'])
                    issuer_name = issuer.get('organizationName', issuer.get('commonName', 'Unknown'))
                    
                    # Kalkulasi waktu kedaluwarsa
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_left = (not_after - datetime.utcnow()).days
                    
                    return {
                        "status": "success",
                        "valid": True,
                        "issuer": issuer_name,
                        "expires": not_after.strftime('%Y-%m-%d'),
                        "days_left": days_left
                    }
        except Exception as e:
            return {"status": "error", "message": f"Koneksi SSL gagal: {str(e)}"}