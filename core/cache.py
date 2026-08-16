class CacheSystem:
    def __init__(self):
        self._cache = {}

    def get(self, prompt: str):
        return self._cache.get(prompt.strip().lower())

    def set(self, prompt: str, response: str):
        self._cache[prompt.strip().lower()] = response
        
    def clear(self):
        self._cache.clear()