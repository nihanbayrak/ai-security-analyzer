"""
Hallucination Supervisor — Factual accuracy analyst.

Only evaluates ASSISTANT messages. Rejects user content immediately
(users can claim anything they want — that's not a security finding).
"""

from supervisors.base import llm_call, parse_verdict
from supervisors.prompts import HALLUCINATION_PROMPT

# HAL finding IDs that warrant LLM evaluation
_REVIEW_IDS = {
    "HAL_AUTHORITY", "HAL_CITE", "HAL_STAT",
    "HAL_CONFIDENT", "HAL_MEDICAL", "HAL_LEGAL",
}


def evaluate(finding: dict, context: dict) -> dict:
    """
    Returns a verdict dict: {"verdict": "confirm|reject|downgrade", "reason": ..., "confidence": ...}
    """
    sender = (context.get("sender") or "").lower()
    fid = finding.get("id", "")
    evidence = finding.get("evidence", "")

    # Fast reject: hallucinations only apply to assistant messages
    if sender in ("user", "human"):
        return {"verdict": "reject", "reason": "Hallucinations only apply to AI responses, not user messages.", "confidence": 99}

    # Fast reject: hedged language (may, might, could, approximately)
    evidence_lower = evidence.lower()
    if any(hedge in evidence_lower for hedge in ("may ", "might ", "could ", "approximately", "possibly", "perhaps")):
        return {"verdict": "downgrade", "reason": "Finding contains hedged language — lower confidence of hallucination.", "confidence": 70}

    # Fast reject: very short evidence unlikely to be a real hallucination claim
    if len(evidence.strip()) < 20:
        return {"verdict": "reject", "reason": "Evidence too short to evaluate for hallucination.", "confidence": 80}

    # Only send high-value HAL IDs to LLM
    if fid not in _REVIEW_IDS:
        return {"verdict": "unvalidated", "reason": "Heuristic-only mode for this finding type.", "confidence": 0}

    messages = [
        {"role": "system", "content": HALLUCINATION_PROMPT},
        {"role": "user", "content": (
            f"Finding: {fid}\n"
            f"Evidence: {evidence[:300]}\n"
            f"Sender: {sender}\n"
            f"In code block: {context.get('in_code_block', False)}\n"
            f"Surrounding context: {context.get('surrounding_messages', '')[:200]}\n\n"
            "Is this a genuine hallucination/misinformation finding or a false positive?\n"
            'Reply JSON: {"verdict":"confirm|reject|downgrade","reason":"...","confidence":0-100}'
        )},
    ]
    raw = llm_call(messages, max_tokens=200)
    return parse_verdict(raw)
