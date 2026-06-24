"""Core SLM engine — wraps Phi-3-mini GGUF via llama-cpp-python."""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Iterator

_LOCK = threading.Lock()
_instance: "SLMEngine | None" = None

DEFAULT_MODEL_PATH = Path(__file__).parents[2] / "models" / "Phi-3-mini-4k-instruct-q4.gguf"

SYSTEM_PROMPT = (
    "You are Guardian, an expert cybersecurity AI assistant. "
    "You analyze security data and return concise, structured threat assessments. "
    "Always respond in the exact JSON format requested. Be precise and accurate."
)


class SLMEngine:
    """Singleton wrapper around a llama-cpp-python Llama instance."""

    def __init__(self, model_path: Path | str | None = None, n_ctx: int = 4096, n_threads: int = 4):
        try:
            from llama_cpp import Llama
        except ImportError as e:
            raise ImportError(
                "llama-cpp-python is not installed. Run: pip install llama-cpp-python"
            ) from e

        path = Path(model_path) if model_path else DEFAULT_MODEL_PATH
        if not path.exists():
            raise FileNotFoundError(
                f"Model not found at {path}.\n"
                "Run: guardian download-model"
            )

        self._llm = Llama(
            model_path=str(path),
            n_ctx=n_ctx,
            n_threads=n_threads,
            n_gpu_layers=-1,  # auto-offload to GPU if available
            verbose=False,
        )
        self._lock = threading.Lock()

    def analyze(
        self,
        user_prompt: str,
        max_tokens: int = 512,
        temperature: float = 0.1,
    ) -> str:
        """Run inference and return the full response string."""
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ]
        with self._lock:
            result = self._llm.create_chat_completion(
                messages=messages,
                max_tokens=max_tokens,
                temperature=temperature,
                stream=False,
            )
        return result["choices"][0]["message"]["content"].strip()

    def stream_analyze(
        self,
        user_prompt: str,
        max_tokens: int = 512,
        temperature: float = 0.1,
    ) -> Iterator[str]:
        """Stream inference tokens."""
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ]
        with self._lock:
            for chunk in self._llm.create_chat_completion(
                messages=messages,
                max_tokens=max_tokens,
                temperature=temperature,
                stream=True,
            ):
                delta = chunk["choices"][0]["delta"]
                if "content" in delta:
                    yield delta["content"]


def get_engine(model_path: Path | str | None = None) -> SLMEngine:
    """Return the global singleton SLMEngine, initializing it on first call."""
    global _instance
    with _LOCK:
        if _instance is None:
            _instance = SLMEngine(model_path=model_path)
    return _instance
