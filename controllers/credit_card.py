"""
Credit Card Controller — Luhn validation + test card blocklist.
Only CONFIRM if Luhn passes AND not a known test/demo card.
"""

# Known test cards to REJECT (Stripe, Visa, MC, Amex, Discover test numbers)
_TEST_CARDS = {
    # Stripe test cards
    "4242424242424242", "4000056655665556", "5555555555554444",
    "5200828282828210", "5105105105105100", "378282246310005",
    "371449635398431",  "6011111111111117", "6011000990139424",
    "3056930009020004", "36227206271667",   "3566002020360505",
    "4929000000006",
    # Visa test
    "4111111111111111", "4012888888881881", "4222222222222",
    # Mastercard test
    "5500005555555559", "5425233430109903",
    # Amex test
    "378734493671000",
    # Discover test
    "6011601160116611",
    # PayPal test
    "4032030101010104",
}


def validate_luhn(number: str) -> bool:
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13:
        return False
    checksum = 0
    is_second = False
    for d in reversed(digits):
        if is_second:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
        is_second = not is_second
    return checksum % 10 == 0


def is_test_card(number: str) -> bool:
    digits = "".join(c for c in number if c.isdigit())
    return digits in _TEST_CARDS


def validate(evidence: str) -> dict:
    """
    Returns {"valid": bool, "reason": str, "is_test": bool}
    """
    digits = "".join(c for c in evidence if c.isdigit())

    if not (13 <= len(digits) <= 19):
        return {"valid": False, "reason": "Digit count out of range for credit card", "is_test": False}

    if not validate_luhn(digits):
        return {"valid": False, "reason": "Failed Luhn algorithm — not a valid card number", "is_test": False}

    if is_test_card(digits):
        return {"valid": False, "reason": "Known test/demo credit card number", "is_test": True}

    return {"valid": True, "reason": "Passed Luhn check and not a known test card", "is_test": False}
