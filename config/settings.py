class Settings:
    APP_NAME = 'C4therine'
    VERSION = '0.0.1'
import os
from dotenv import load_dotenv

load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
DEFAULT_MODEL = "llama-3.1-8b-instant" # Bisa diganti ke Qwen atau Llama 3.3 sesuai ketersediaan
MAX_MEMORY_HISTORY = 10