"""
TC Kimlik No (Turkish National ID) validator.

Algorithm from Turkish Ministry of Interior:
- 11 digits, never starts with 0
- 10th digit: (sum(d[0,2,4,6,8])*7 - sum(d[1,3,5,7])) % 10
- 11th digit: sum(d[0..9]) % 10
"""

import re

_TC_RE = re.compile(r"\b[1-9]\d{10}\b")

# Known placeholder / sequential test IDs that should be rejected
_PLACEHOLDER_PATTERN = re.compile(r"^(\d)\1{10}$|^1234567890\d$|^9876543210\d$")


def validate(tc: str) -> dict:
    """
    Validate a TC Kimlik candidate string.

    Returns:
        {"valid": bool, "reason": str, "is_placeholder": bool}
    """
    tc = tc.strip()
    if not re.fullmatch(r"[1-9]\d{10}", tc):
        return {"valid": False, "reason": "Not 11 digits or starts with 0.", "is_placeholder": False}

    if _PLACEHOLDER_PATTERN.match(tc):
        return {"valid": False, "reason": "Known placeholder/sequential ID.", "is_placeholder": True}

    digits = [int(d) for d in tc]

    # 10th digit check
    d10 = (
        (digits[0] + digits[2] + digits[4] + digits[6] + digits[8]) * 7
        - (digits[1] + digits[3] + digits[5] + digits[7])
    ) % 10
    if d10 != digits[9]:
        return {"valid": False, "reason": "10th digit checksum failed.", "is_placeholder": False}

    # 11th digit check
    d11 = sum(digits[:10]) % 10
    if d11 != digits[10]:
        return {"valid": False, "reason": "11th digit checksum failed.", "is_placeholder": False}

    return {"valid": True, "reason": "TC Kimlik checksum passed.", "is_placeholder": False}


def find_candidates(text: str) -> list:
    """Return all TC Kimlik candidate strings found in text."""
    return [m.group(0) for m in _TC_RE.finditer(text)]
