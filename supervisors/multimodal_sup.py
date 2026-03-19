"""
Multimodal Supervisor — Image & vision security analyst.

Key insight: user-sent images vs AI-generated images have OPPOSITE risks.
- User image → check for EXIF PII, text-in-image injection, behavior shift in next response
- AI image (DALL-E) → check the prompt for injection keywords
"""

import re
from supervisors.base import llm_call, parse_verdict
from supervisors.prompts import MULTIMODAL_PROMPT

# Phrases that indicate post-image behavior change
_BEHAVIOR_SHIFT_PATTERNS = re.compile(
    r"(?:I\s+(?:will|can|shall|must)\s+(?:now|help|assist)|"
    r"as\s+(?:you\s+)?(?:requested|instructed|shown|asked)|"
    r"following\s+(?:your\s+)?(?:instructions?|commands?|image)|"
    r"I\s+see\s+(?:the\s+)?(?:instruction|command|note|message)\s+in\s+the\s+image|"
    r"the\s+image\s+(?:says?|shows?|contains?|instructs?))",
    re.IGNORECASE,
)

# Injection text embedded in image descriptions
_IMAGE_INJECTION = re.compile(
    r"(?:ignore\s+(?:previous|above|all)|disregard|override|bypass|"
    r"jailbreak|system\s+prompt|DAN|do\s+anything\s+now|"
    r"print\s+(?:your|the)\s+(?:system|secret)|reveal\s+(?:your|the))",
    re.IGNORECASE,
)


def evaluate(finding: dict, context: dict) -> dict:
    """
    Returns a verdict dict: {"verdict": "confirm|reject|downgrade", ...}
    """
    fid = finding.get("id", "")
    evidence = finding.get("evidence", "")
    sender = (context.get("sender") or "").lower()

    # Fast check: image injection via embedded text
    if _IMAGE_INJECTION.search(evidence):
        return {"verdict": "confirm", "reason": "Image contains embedded injection-like text.", "confidence": 88}

    # Post-image behavior shift: check the next assistant message
    next_assistant = context.get("next_assistant_message", "")
    if next_assistant and _BEHAVIOR_SHIFT_PATTERNS.search(next_assistant):
        return {"verdict": "confirm", "reason": "Assistant behavior changed after image upload — possible image injection.", "confidence": 82}

    # No behavior shift signals → downgrade
    if fid == "MM_POST_IMAGE_BEHAVIOR" and not next_assistant:
        return {"verdict": "downgrade", "reason": "No post-image assistant message available to evaluate behavior shift.", "confidence": 55}

    # Route to LLM for nuanced cases
    messages = [
        {"role": "system", "content": MULTIMODAL_PROMPT},
        {"role": "user", "content": (
            f"Finding: {fid}\n"
            f"Evidence: {evidence[:300]}\n"
            f"Sender: {sender}\n"
            f"Next assistant message: {next_assistant[:300] if next_assistant else '(not available)'}\n\n"
            "Does this multimodal content represent a genuine security risk?\n"
            'Reply JSON: {"verdict":"confirm|reject|downgrade","reason":"...","confidence":0-100}'
        )},
    ]
    raw = llm_call(messages, max_tokens=200)
    return parse_verdict(raw)
