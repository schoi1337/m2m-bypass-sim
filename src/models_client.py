# path: src/models_client.py
from typing import Literal

from groq import Groq

from .config import (
    GROQ_API_KEY,
    MODEL_A_NAME,
    MODEL_B_NAME,
    MODEL_C_NAME,
    validate_config,
)

RoleType = Literal["system", "user"]


class ModelClient:
    """
    Simple wrapper around the Groq client for M2M experiments.

    This class provides three explicit entry points:
    - Model A: summary / interpretation
    - Model B: classification / risk scoring
    - Model C: decision / action suggestion
    """

    def __init__(self) -> None:
        """Initialize the client and validate configuration."""
        validate_config()
        if not GROQ_API_KEY:
            # Extra safety check, should already be caught by validate_config.
            raise RuntimeError("GROQ_API_KEY is not set.")

        self.client = Groq(api_key=GROQ_API_KEY)

    def _call_model(self, model_name: str, role: RoleType, content: str) -> str:
        """
        Call a single model and return the response content.

        Args:
            model_name: The model identifier to call.
            role: The role for the message ("system" or "user").
            content: The content to send to the model.

        Returns:
            The text content of the first completion choice.
        """
        # Debug print to confirm which model is being called.
        # You can comment this out later if it is too noisy.
        print(f"[DEBUG] Calling model: {model_name}")

        response = self.client.chat.completions.create(
            model=model_name,
            messages=[
                {
                    "role": role,
                    "content": content,
                }
            ],
            temperature=0.2,
        )

        message = response.choices[0].message
        # Sometimes content can be None, so we guard against that.
        text = message.content or ""
        if not text.strip():
            print("[WARN] Empty content returned from model.")
        return text

    def call_model_a(self, content: str) -> str:
        """
        Call Model A (summary / interpretation).

        Args:
            content: Raw input text describing the user action or event.

        Returns:
            A summarized / interpreted version of the input.
        """
        return self._call_model(MODEL_A_NAME, "user", content)

    def call_model_b(self, content: str) -> str:
        """
        Call Model B (classification / risk scoring).

        Args:
            content: Typically the output of Model A (summary).

        Returns:
            A classification or risk assessment for the summarized content.
        """
        return self._call_model(MODEL_B_NAME, "user", content)

    def call_model_c(self, content: str) -> str:
        """
        Call Model C (decision / action suggestion).

        Args:
            content: Typically the output of Model B (classification).

        Returns:
            A final decision or action recommendation (e.g., alert / monitor / ignore).
        """
        return self._call_model(MODEL_C_NAME, "user", content)
