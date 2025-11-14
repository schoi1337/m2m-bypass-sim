"""Groq-backed client used."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Optional, Sequence

from . import config

try:  # Groq is an optional runtime dependency during testing.
    from groq import Groq
except ImportError:  # pragma: no cover - exercised only without Groq installed.
    Groq = None  # type: ignore[assignment]


def _first_non_empty_attr(module: object, candidates: Sequence[str]) -> str:
    """Return the first truthy attribute found on the module."""
    for name in candidates:
        value = getattr(module, name, "")
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


@dataclass
class ModelNames:
    """Container for the three Groq model identifiers."""

    model_a: str
    model_b: str
    model_c: str


class ModelClient:
    """High level helper that talks to Groq chat completions."""

    _TEMPERATURE: float = 0.2

    def __init__(
        self,
        *,
        api_key: Optional[str] = None,
        model_a_name: Optional[str] = None,
        model_b_name: Optional[str] = None,
        model_c_name: Optional[str] = None,
        client: Optional[Groq] = None,
    ) -> None:
        self._api_key = api_key or _first_non_empty_attr(
            config,
            ("GROQ_API_KEY", "API_KEY", "GROQ_KEY"),
        )
        self._models = ModelNames(
            model_a=model_a_name
            or _first_non_empty_attr(
                config,
                ("MODEL_A_NAME", "MODEL_A", "MODEL_SUMMARY"),
            ),
            model_b=model_b_name
            or _first_non_empty_attr(
                config,
                ("MODEL_B_NAME", "MODEL_B", "MODEL_CLASSIFICATION"),
            ),
            model_c=model_c_name
            or _first_non_empty_attr(
                config,
                ("MODEL_C_NAME", "MODEL_C", "MODEL_DECISION"),
            ),
        )
        if client is not None:
            self._client = client
        elif self._api_key and Groq is not None:
            self._client = Groq(api_key=self._api_key)
        else:
            self._client = None
        if self._api_key and self._client is None and Groq is None:
            raise ImportError(
                "The 'groq' package is required to instantiate ModelClient without a custom client.",
            )

    def call_model_a(self, content: str) -> str:
        """Call Model A to obtain a summary or interpretation."""
        return self._call_model(self._models.model_a, "user", content)

    def call_model_b(self, content: str) -> str:
        """Call Model B to obtain a classification or risk score."""
        return self._call_model(self._models.model_b, "user", content)

    def call_model_c(self, content: str) -> str:
        """Call Model C to obtain an action or decision recommendation."""
        return self._call_model(self._models.model_c, "user", content)

    def _call_model(
        self,
        model_name: str,
        role: Literal["system", "user"],
        content: str,
    ) -> str:
        """Thin wrapper around `chat.completions.create` with safe guards."""
        if not content or not isinstance(content, str):
            return ""
        if not model_name or not self._client:
            return ""

        try:
            completion = self._client.chat.completions.create(
                model=model_name,
                temperature=self._TEMPERATURE,
                messages=[{"role": role, "content": content}],
            )
        except Exception:
            return ""

        choices = getattr(completion, "choices", None)
        if not choices:
            return ""
        choice = choices[0]
        message = getattr(choice, "message", None)
        response_content = getattr(message, "content", "") if message else ""
        return response_content.strip() if response_content else ""
