# src/config.py
import os
from dotenv import load_dotenv

load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY")

# Groq-provided models
# You can change these to ANY model listed in https://console.groq.com/docs/models

MODEL_A_NAME = os.getenv("MODEL_A_NAME", "llama-3.1-8b-instant")
MODEL_B_NAME = os.getenv("MODEL_B_NAME", "openai/gpt-oss-20b")
MODEL_C_NAME = os.getenv("MODEL_C_NAME", "qwen/qwen3-32b")

def validate_config():
    missing = []
    if not GROQ_API_KEY:
        missing.append("GROQ_API_KEY")
    if missing:
        raise RuntimeError("Missing required config: " + ", ".join(missing))
