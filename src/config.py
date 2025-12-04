# src/config.py

import os
from typing import Optional

from dotenv import load_dotenv

# Load variables from .env at project root.
load_dotenv()

# Core configuration values exported at module level
GROQ_API_KEY: Optional[str] = os.getenv("GROQ_API_KEY")

# You can override these via env vars if you want.
MODEL_A_NAME: str = os.getenv("MODEL_A_NAME", "llama-3.1-8b-instant")
MODEL_B_NAME: str = os.getenv("MODEL_B_NAME", "llama-3.1-8b-instant")
MODEL_C_NAME: str = os.getenv("MODEL_C_NAME", "llama-3.1-8b-instant")


def validate_config() -> None:
    """
    Validate that all required configuration values are present.

    This is called by ModelClient.__init__ before any API calls.
    """
    missing = []

    if not GROQ_API_KEY:
        missing.append("GROQ_API_KEY")

    if not MODEL_A_NAME:
        missing.append("MODEL_A_NAME")

    if not MODEL_B_NAME:
        missing.append("MODEL_B_NAME")

    if not MODEL_C_NAME:
        missing.append("MODEL_C_NAME")

    if missing:
        # Fail fast with a clear message so users can fix their .env.
        raise RuntimeError(
            "Missing required configuration values: "
            + ", ".join(missing)
            + ". Make sure they are set in your environment or .env file."
        )
