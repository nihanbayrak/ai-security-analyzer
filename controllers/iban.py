"""
IBAN validator — MOD-97 algorithm + country prefix + length check.

Centralises IBAN validation used by both pii.py detector and the PII supervisor.
"""

import re

# Expected IBAN lengths by country code
_IBAN_LENGTHS = {
    "AL": 28, "AD": 24, "AT": 20, "AZ": 28, "BH": 22, "BE": 16,
    "BA": 20, "BR": 29, "BG": 22, "CR": 22, "HR": 21, "CY": 28,
    "CZ": 24, "DK": 18, "DO": 28, "EE": 20, "EG": 29, "FO": 18,
    "FI": 18, "FR": 27, "GE": 22, "DE": 22, "GI": 23, "GR": 27,
    "GL": 18, "GT": 28, "HU": 28, "IS": 26, "IQ": 23, "IE": 22,
    "IL": 23, "IT": 27, "JO": 30, "KZ": 20, "XK": 20, "KW": 30,
    "LV": 21, "LB": 28, "LI": 21, "LT": 20, "LU": 20, "MK": 19,
    "MT": 31, "MR": 27, "MU": 30, "MD": 24, "MC": 27, "ME": 22,
    "NL": 18, "NO": 15, "PK": 24, "PS": 29, "PL": 28, "PT": 25,
    "QA": 29, "RO": 24, "LC": 32, "SM": 27, "ST": 25, "SA": 24,
    "RS": 22, "SC": 31, "SK": 24, "SI": 19, "ES": 24, "SE": 24,
    "CH": 21, "TL": 23, "TN": 24, "TR": 26, "UA": 29, "AE": 23,
    "GB": 22, "VA": 22, "VG": 24,
}


def validate(iban: str) -> dict:
    """
    Validate an IBAN string (spaces and dashes stripped automatically).

    Returns:
        {"valid": bool, "country": str, "reason": str}
    """
    iban = re.sub(r"[\s\-]", "", iban.upper())

    if len(iban) < 4:
        return {"valid": False, "country": "", "reason": "Too short to be an IBAN."}

    country = iban[:2]
    expected_len = _IBAN_LENGTHS.get(country)
    if expected_len and len(iban) != expected_len:
        return {
            "valid": False, "country": country,
            "reason": f"Wrong length for {country} IBAN: expected {expected_len}, got {len(iban)}."
        }

    # MOD-97: move first 4 chars to end, convert letters A=10..Z=35, compute mod 97
    rearranged = iban[4:] + iban[:4]
    numeric = ""
    for ch in rearranged:
        if ch.isdigit():
            numeric += ch
        elif ch.isalpha():
            numeric += str(ord(ch) - 55)
        else:
            return {"valid": False, "country": country, "reason": f"Invalid character '{ch}' in IBAN."}

    try:
        remainder = int(numeric) % 97
    except ValueError:
        return {"valid": False, "country": country, "reason": "IBAN contains non-numeric characters after letter expansion."}

    if remainder != 1:
        return {"valid": False, "country": country, "reason": f"MOD-97 check failed (remainder={remainder}, expected 1)."}

    return {"valid": True, "country": country, "reason": "IBAN MOD-97 passed."}


def find_candidates(text: str) -> list:
    """Return all IBAN-format strings found in text."""
    pattern = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9 ]{11,30}\b")
    return [m.group(0) for m in pattern.finditer(text)]
