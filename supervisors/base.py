"""
Base Supervisor — LLM-powered finding validator.

Uses HF Inference API (Qwen3-8B) when HF_TOKEN is set.
Degrades to heuristic-only if token unavailable or API down.
Results are marked "⚠️ Unvalidated" in offline mode.
"""

import os
import re
import json
from typing import Optional

HF_TOKEN = os.environ.get("HF_TOKEN") or os.environ.get("HUGGINGFACE_TOKEN")

_PRIMARY_MODEL = "Qwen/Qwen3-8B"
_FALLBACK_MODELS = [
    "Qwen/Qwen2.5-7B-Instruct",
    "mistralai/Mistral-7B-Instruct-v0.3",
    "meta-llama/Llama-3.1-8B-Instruct",
]

# Track whether LLM is reachable (avoid repeated failed calls in a scan)
_llm_available: Optional[bool] = None


def _try_hf_call(model: str, messages: list, max_tokens: int = 200) -> Optional[str]:
    try:
        from huggingface_hub import InferenceClient
        client = InferenceClient(model, token=HF_TOKEN)
        resp = client.chat_completion(
            messages=messages,
            max_tokens=max_tokens,
            temperature=0.1,
        )
        return resp.choices[0].message.content
    except Exception:
        return None


def llm_call(messages: list, max_tokens: int = 200) -> Optional[str]:
    """Try primary model then fallbacks. Returns None if all fail or no token."""
    global _llm_available
    if not HF_TOKEN:
        return None
    if _llm_available is False:
        return None  # already know it's down this session

    for model in [_PRIMARY_MODEL] + _FALLBACK_MODELS:
        result = _try_hf_call(model, messages, max_tokens)
        if result:
            _llm_available = True
            return result

    _llm_available = False
    return None


def reset_llm_state():
    """Call between scans to re-try LLM after a failure."""
    global _llm_available
    _llm_available = None


def parse_verdict(raw: Optional[str]) -> dict:
    """Parse {"verdict":"confirm|reject|downgrade","reason":"...","confidence":0-100}."""
    if not raw:
        return {"verdict": "unvalidated", "reason": "LLM supervisor unavailable", "confidence": 0}

    # Try JSON extraction
    try:
        m = re.search(r'\{[^{}]*"verdict"[^{}]*\}', raw, re.DOTALL)
        if m:
            data = json.loads(m.group(0))
            verdict = str(data.get("verdict", "unvalidated")).lower()
            if verdict not in ("confirm", "reject", "downgrade"):
                verdict = "unvalidated"
            return {
                "verdict": verdict,
                "reason": str(data.get("reason", ""))[:300],
                "confidence": max(0, min(100, int(data.get("confidence", 50)))),
            }
    except Exception:
        pass

    # Keyword fallback
    raw_lower = raw.lower()
    if "confirm" in raw_lower:
        return {"verdict": "confirm", "reason": raw[:200], "confidence": 65}
    if "reject" in raw_lower:
        return {"verdict": "reject", "reason": raw[:200], "confidence": 65}
    if "downgrade" in raw_lower:
        return {"verdict": "downgrade", "reason": raw[:200], "confidence": 60}
    return {"verdict": "unvalidated", "reason": raw[:200], "confidence": 0}


def is_llm_online() -> bool:
    return bool(HF_TOKEN) and _llm_available is not False
