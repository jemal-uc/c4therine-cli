import requests
from bs4 import BeautifulSoup
import csv
import os
import time
import random
import urllib.parse
# Import DDGS dihapus karena sudah dipindah ke tools/search.py

class ScraperTool:
    def __init__(self):
        self.name = "scrape"
        self.session = requests.Session()
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }
        self.session.headers.update(self.headers)

    def execute(self, url: str, target_element: str, max_export: int, **kwargs) -> dict:
        try:
            export_limit = min(max_export, 20000)
            time.sleep(random.uniform(1.5, 3.5))
            response = self.session.get(url, timeout=15)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.text, 'html.parser')
            elements = soup.select(target_element)
            
            if not elements:
                return {"status": "error", "message": f"Elemen '{target_element}' tidak ditemukan."}

            extracted_data = [el.get_text(strip=True) for el in elements if el.get_text(strip=True)]
            extracted_data = extracted_data[:export_limit]
            
            # Hanya mengembalikan data mentah, tidak melakukan save CSV di sini
            return {
                "status": "success",
                "preview": extracted_data[:10],
                "total_found": len(elements),
                "exported": len(extracted_data),
                "data": extracted_data # Data dikirim ke Router
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}
# Tidak ada lagi search_web atau osint_lookup di bawah sini!