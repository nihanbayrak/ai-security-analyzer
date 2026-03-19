"""
German Steuer-ID (Steueridentifikationsnummer) validator.

Rules:
- Exactly 11 digits
- First digit: 1-9 (never 0)
- Digits 1-10: one digit appears exactly 2 or 3 times, no digit appears 4+ times
- Check digit (digit 11): ISO 7064 MOD 11,10 variant
"""

import re

_STEUER_RE = re.compile(r"\b[1-9]\d{10}\b")

# Context keywords that increase likelihood of a Steuer-ID match
CONTEXT_KEYWORDS = re.compile(
    r"(?i)steuer(?:nummer|id|identifikation|identifikationsnummer|n\.?r\.?)|"
    r"idnr|tin\b|tax\s*id|steuern"
)


def validate(candidate: str) -> dict:
    """
    Validate a German Steuer-ID candidate.

    Returns:
        {"valid": bool, "reason": str}
    """
    candidate = re.sub(r"\s", "", candidate)

    if not re.fullmatch(r"[1-9]\d{10}", candidate):
        return {"valid": False, "reason": "Not 11 digits or starts with 0."}

    digits = [int(d) for d in candidate]

    # Frequency check: one digit must appear 2-3 times, none 4+
    from collections import Counter
    freq = Counter(digits[:10])  # check first 10 digits only
    counts = list(freq.values())
    if max(counts) >= 4:
        return {"valid": False, "reason": "A digit appears 4+ times — invalid Steuer-ID."}
    if max(counts) < 2:
        return {"valid": False, "reason": "No digit repeats — invalid Steuer-ID structure."}

    # ISO 7064 MOD 11,10 check digit
    product = 10
    for i in range(10):
        total = (digits[i] + product) % 10
        if total == 0:
            total = 10
        product = (2 * total) % 11
    expected_check = (11 - product) % 10
    if digits[10] != expected_check:
        return {"valid": False, "reason": f"Check digit failed (expected {expected_check}, got {digits[10]})."}

    return {"valid": True, "reason": "Steuer-ID checksum passed."}


def has_context(text: str, match_start: int, window: int = 60) -> bool:
    """Return True if text near the match contains Steuer-ID context keywords."""
    snippet = text[max(0, match_start - window): match_start + window]
    return bool(CONTEXT_KEYWORDS.search(snippet))


def find_candidates(text: str):
    """Yield (candidate_str, match_start) for each Steuer-ID candidate in text."""
    for m in _STEUER_RE.finditer(text):
        yield m.group(0), m.start()
