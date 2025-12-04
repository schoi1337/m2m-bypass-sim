# src/models_client.py

from typing import Literal
from groq import Groq

from .config import (
    GROQ_API_KEY,
    MODEL_A_NAME,
    MODEL_B_NAME,
    MODEL_C_NAME,
    validate_config,
)

RoleType = Literal["user"]


class ModelClient:
    """
    Single Groq client for all Stage A/B/C calls.
    Each stage uses a different Groq model name defined in config.py.
    """

    def __init__(self) -> None:
        validate_config()
        self.client = Groq(api_key=GROQ_API_KEY)

    def _call(self, model_name: str, content: str) -> str:
        """Internal helper to call a Groq chat model."""
        print(f"Calling model: {model_name}")
        resp = self.client.chat.completions.create(
            model=model_name,
            messages=[{"role": "user", "content": content}],
            temperature=0.2,
        )
        return resp.choices[0].message.content or ""

    # Stage A: summary
    def call_model_a(self, content: str) -> str:
        return self._call(MODEL_A_NAME, content)

    # Stage B: classification
    def call_model_b(self, content: str) -> str:
        return self._call(MODEL_B_NAME, content)

    # Stage C: decision/action
    def call_model_c(self, content: str) -> str:
        return self._call(MODEL_C_NAME, content)
