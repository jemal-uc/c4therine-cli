import requests
import json
from config.settings import GROQ_API_KEY, GROQ_API_URL, DEFAULT_MODEL
from core.cache import CacheSystem
from core.memory import MemoryManager
from core.usage_tracker import UsageTracker

class AIEngine:
    def __init__(self, memory: MemoryManager, cache: CacheSystem, tracker: UsageTracker):
        self.memory = memory
        self.cache = cache
        self.tracker = tracker
        self.model = DEFAULT_MODEL

    def generate_response(self, prompt: str) -> str:
        budget_status = self.tracker.check_budget()
        if budget_status == "exceeded":
            return "[SYSTEM BLOCK] Budget exceeded limit. AI request denied."

        cached_response = self.cache.get(prompt)
        if cached_response:
            self.memory.add_message("user", prompt)
            self.memory.add_message("assistant", cached_response)
            return f"[CACHED] {cached_response}"

        headers = {
            "Authorization": f"Bearer {GROQ_API_KEY}",
            "Content-Type": "application/json"
        }

        messages = [{"role": "system", "content": "You are C4therine, a futuristic hacker AI terminal assistant."}]
        messages.extend(self.memory.get_context())
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.7
        }

        try:
            response = requests.post(GROQ_API_URL, headers=headers, json=payload)
            response.raise_for_status()
            data = response.json()
            
            ai_text = data["choices"][0]["message"]["content"]
            usage = data.get("usage", {})
            
            self.tracker.add_usage(usage.get("prompt_tokens", 0), usage.get("completion_tokens", 0))
            self.cache.set(prompt, ai_text)
            
            self.memory.add_message("user", prompt)
            self.memory.add_message("assistant", ai_text)
            
            return ai_text
            
        except Exception as e:
            return f"[ERROR] API Connection Failed. Fallback mode activated. Detail: {str(e)}"