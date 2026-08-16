import json
import os

class MemoryManager:
    def __init__(self, max_history=10):
        self.max_history = max_history
        self.history = []
        self.profile_path = "storage/memory/user_profile.json"
        self.profile = self._load_profile()

    def _load_profile(self):
        if os.path.exists(self.profile_path):
            with open(self.profile_path, "r") as f:
                return json.load(f)
        
        # Default Profile jika belum pernah disetting
        return {
            "name": "User",
            "profession": "Developer",
            "preference": "Beri jawaban yang singkat, teknis, dan to the point dengan gaya hacker."
        }

    def update_profile(self, key, value):
        """Memperbarui dan menyimpan profil ke file JSON"""
        self.profile[key] = value
        os.makedirs(os.path.dirname(self.profile_path), exist_ok=True)
        with open(self.profile_path, "w") as f:
            json.dump(self.profile, f, indent=4)

    def add_message(self, role: str, content: str):
        self.history.append({"role": role, "content": content})
        if len(self.history) > self.max_history:
            self.history.pop(0)

    def get_context(self) -> list:
        """Menggabungkan Profil (System) dan Riwayat Chat (Short-term)"""
        
        # 1. Pesan rahasia yang tidak terlihat di terminal, tapi dibaca oleh AI
        system_instruction = (
            f"Kamu adalah C4therine, AI Assistant CLI. "
            f"Kamu sedang berbicara dengan {self.profile.get('name')}, "
            f"seorang {self.profile.get('profession')}. "
            f"Instruksi wajib untuk respons kamu: {self.profile.get('preference')}"
        )
        
        # 2. Inject ke urutan pertama dengan role "system"
        context = [{"role": "system", "content": system_instruction}]
        
        # 3. Tambahkan riwayat percakapan yang sedang berlangsung
        context.extend(self.history)
        
        return context