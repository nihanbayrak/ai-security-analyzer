"""Injection Supervisor — validates prompt injection findings."""

from .base import llm_call, parse_verdict
from .prompts import INJECTION_PROMPT


def evaluate(finding: dict, context: dict) -> dict:
    """
    Context-evaluate an injection finding.
    Returns {"verdict": "confirm|reject|downgrade|unvalidated", "reason": str, "confidence": int}
    """
    role = (context.get("sender") or "").lower()
    in_code = context.get("in_code_block", False)
    surrounding = (context.get("surrounding_messages") or "").lower()

    # Fast heuristic rejections (no LLM call needed)
    if role == "assistant":
        return {"verdict": "reject", "reason": "AI doesn't inject itself", "confidence": 95}

    if in_code:
        # Allow CRITICAL encoded injections even in code — they may be real attacks
        if finding.get("id") == "INJ_ENC_INJECTION":
            pass  # fall through to LLM
        else:
            return {"verdict": "reject", "reason": "Content is inside a code block (tutorial/demo context)", "confidence": 85}

    if any(w in surrounding for w in ("ctf", "pentest", "tutorial", "exercise", "homework", "example")):
        return {"verdict": "downgrade", "reason": "Educational/research context detected", "confidence": 80}

    # LLM validation for ambiguous cases
    messages = [
        {"role": "system", "content": INJECTION_PROMPT},
        {"role": "user", "content": (
            f"Finding: {finding.get('id')} — {finding.get('evidence', '')[:300]}\n"
            f"Sender: {context.get('sender', 'unknown')}\n"
            f"In code block: {in_code}\n"
            f"Context: {context.get('surrounding_messages', '')[:400]}\n\n"
            "Is this a true security concern or false positive?\n"
            'Reply JSON: {"verdict":"confirm|reject|downgrade","reason":"...","confidence":0-100}'
        )},
    ]
    raw = llm_call(messages)
    return parse_verdict(raw)
