"""
Context Validator — Reduces false positives for LLM-generated numbers.

Problem: AI assistants generate numbers that look like PII but aren't:
  - Math results: "2^50 = 1125899906842624"
  - Format examples: "SSN format: 123-45-6789"
  - Code snippets: "const id = 4532015112830366;"
  - Order IDs: "Your order ID: 4532-0151-1283-0366"
  - Test data: "Use test card 4111111111111111"

Solution: Context-aware validation that checks:
  1. Sender role (user sharing data vs AI generating examples)
  2. Surrounding context keywords
  3. Code block detection
  4. Example/placeholder indicators
"""

import re
from typing import Optional


# Keywords that indicate the number is an example/format demonstration
# Supports: English, German, Turkish
_EXAMPLE_CONTEXT = re.compile(
    r"(?i)(?:"
    # English
    r"for\s+example|"
    r"e\.?g\.?\s*[:,]?|"
    r"such\s+as|"
    r"like\s+this|"
    r"sample|"
    r"example|"
    r"format[ıi]?\s*(is|:)|"  # Turkish "formatı" support
    r"looks?\s+like|"
    r"placeholder|"
    r"dummy|"
    r"fake|"
    r"test\s*(card|number|data|value|key|token|mode)?|"
    r"demo|"
    r"mock|"
    r"template|"
    r"pattern\s*(is|:)|"
    r"syntax\s*(is|:)|"
    r"structured\s+as|"
    r"typically\s+(looks?|is)|"
    r"should\s+(be|look)|"
    r"would\s+(be|look)|"
    r"here.s\s+(an?|the)\s+example|"
    r"sandbox|"
    r"staging|"
    r"development\s+(key|token|mode)|"
    r"_test_|"
    r"sk_test|pk_test|"
    # German example/format indicators
    r"zum\s+beispiel|"          # for example
    r"z\.?\s*b\.?\s*[:,]?|"     # z.B. (abbreviation)
    r"beispiel(sweise)?|"       # example / for instance
    r"muster|"                  # pattern/sample
    r"vorlage|"                 # template
    r"platzhalter|"             # placeholder
    r"testdaten|"               # test data
    r"testkarte|"               # test card
    r"testnummer|"              # test number
    r"sieht\s+(so\s+)?aus\s+wie|"  # looks like
    r"das\s+format\s+(ist|:)|"  # the format is
    r"im\s+format|"             # in format
    r"formatierung|"            # formatting
    r"beispieldaten|"           # example data
    r"fiktiv|"                  # fictional
    r"testumgebung|"            # test environment
    r"entwicklungs(modus|umgebung)"  # development mode/environment
    r")"
)

# Keywords that indicate non-PII reference numbers
# Supports: English, German
_REFERENCE_CONTEXT = re.compile(
    r"(?i)(?:"
    # English
    r"order\s*(id|number|#|no\.?)|"
    r"transaction\s*(id|number|#|no\.?|ref)|"
    r"reference\s*(id|number|#|no\.?)|"
    r"confirmation\s*(id|number|#|no\.?)|"
    r"tracking\s*(id|number|#|no\.?)|"
    r"invoice\s*(id|number|#|no\.?)|"
    r"account\s*(id|number|#|no\.?)|"
    r"ticket\s*(id|number|#|no\.?)|"
    r"case\s*(id|number|#|no\.?)|"
    r"serial\s*(number|#|no\.?)|"
    r"product\s*(id|code)|"
    r"sku|"
    r"item\s*(id|number|#|no\.?)|"
    r"batch\s*(id|number|#|no\.?)|"
    r"version\s*(id|number)|"
    r"build\s*(id|number)|"
    r"id\s*[:=]|"
    r"uuid|"
    r"guid|"
    # German reference numbers
    r"bestellnummer|"           # order number
    r"bestell[_-]?nr\.?|"       # order no.
    r"transaktionsnummer|"      # transaction number
    r"transaktions[_-]?nr\.?|"  # transaction no.
    r"referenznummer|"          # reference number
    r"referenz[_-]?nr\.?|"      # reference no.
    r"rechnungsnummer|"         # invoice number
    r"rechnungs[_-]?nr\.?|"     # invoice no.
    r"kundennummer|"            # customer number
    r"kunden[_-]?nr\.?|"        # customer no.
    r"artikelnummer|"           # item/article number
    r"artikel[_-]?nr\.?|"       # item no.
    r"seriennummer|"            # serial number
    r"serien[_-]?nr\.?|"        # serial no.
    r"vorgangsnummer|"          # case/ticket number
    r"vorgang[_-]?nr\.?|"       # case no.
    r"sendungsnummer|"          # tracking/shipment number
    r"sendungs[_-]?nr\.?|"      # tracking no.
    r"buchungsnummer|"          # booking number
    r"kontonummer|"             # account number (non-IBAN context)
    r"produktnummer|"           # product number
    r"auftragsnummer|"          # order/job number
    r"auftrags[_-]?nr\.?"       # order no.
    r")"
)

# Math/calculation context
# Supports: English, German
_MATH_CONTEXT = re.compile(
    r"(?i)(?:"
    # English
    r"equals?\s*[:=]?|"
    r"result\s*(is|:)|"
    r"answer\s*(is|:)|"
    r"calculation|"
    r"compute[ds]?|"
    r"sum\s*(is|:)|"
    r"total\s*(is|:)|"
    r"product\s*(is|of)|"
    r"factorial|"
    r"\d+\s*[\+\-\*\/\^]\s*\d+|"  # arithmetic expressions
    r"=\s*\d{10,}|"  # = followed by big number
    r"\d{10,}\s*=|"  # big number followed by =
    # German math terms
    r"ergibt\s*[:=]?|"          # equals/results in
    r"ergebnis\s*(ist|:)|"      # result is
    r"das\s+ergebnis|"          # the result
    r"antwort\s*(ist|:)|"       # answer is
    r"berechnung|"              # calculation
    r"berechnet|"               # calculated
    r"summe\s*(ist|:)|"         # sum is
    r"gesamt\s*(ist|:)|"        # total is
    r"insgesamt|"               # in total
    r"fakultät"                 # factorial
    r")"
)

# Code context indicators
_CODE_CONTEXT = re.compile(
    r"(?:"
    r"```|"
    r"const\s+\w+\s*=|"
    r"let\s+\w+\s*=|"
    r"var\s+\w+\s*=|"
    r"int\s+\w+\s*=|"
    r"long\s+\w+\s*=|"
    r"\w+\s*=\s*\d{10,}\s*;|"  # variable = number;
    r"return\s+\d{10,}|"
    r"print\s*\(\s*\d{10,}|"
    r"console\.log|"
    r"System\.out|"
    r"def\s+\w+|"
    r"function\s+\w+"
    r")"
)

# Possessive context (user actually sharing their own data)
# Supports: English, German, Turkish
_POSSESSIVE_CONTEXT = re.compile(
    r"(?i)(?:"
    # English possessive
    r"my\s+(credit\s+card|card|ssn|social\s+security|phone|number|email|key|token|iban|kimlik)|"
    r"i.?m\s+sharing|"
    r"here.?s?\s+my|"
    r"this\s+is\s+my|"
    r"my\s+personal|"
    r"my\s+actual|"
    r"my\s+real|"
    r"please\s+(use|save|store)\s+(this|my)|"
    r"charge\s+(this|my)\s+card|"
    r"send\s+to\s+my|"
    r"contact\s+me\s+at|"
    # Turkish possessive
    r"benim\s+|"
    r"numaram|"              # my number
    r"kartım|"               # my card
    # German possessive
    r"meine?\s+(kreditkarte|karte|telefonnummer|handynummer|nummer|e-?mail|iban|kontonummer)|"
    r"hier\s+ist\s+meine?|"  # here is my
    r"das\s+ist\s+meine?|"   # this is my
    r"ich\s+teile\s+meine?|" # I'm sharing my
    r"meine?\s+persönliche|" # my personal
    r"meine?\s+echte|"       # my real
    r"bitte\s+(verwende|speichere|nutze)\s+(diese?|meine?)|"  # please use/save this/my
    r"belasten?\s+sie\s+meine?\s+karte|"  # charge my card
    r"kontaktieren?\s+sie\s+mich|"        # contact me
    r"senden?\s+sie\s+an\s+meine?|"       # send to my
    r"schicken?\s+sie\s+an\s+meine?"      # send to my
    r")"
)


def is_likely_false_positive(
    text: str,
    finding_id: str,
    role: str,
    evidence: str,
) -> tuple[bool, Optional[str]]:
    """
    Determine if a finding is likely a false positive based on context.

    Returns:
        (is_false_positive, reason)
        - True, "reason" if this should be suppressed
        - False, None if this is a real finding
    """
    role_lower = (role or "").lower()
    text_lower = text.lower()

    # ========================================================================
    # RULE 1: User explicitly sharing their own data = ALWAYS REAL
    # ========================================================================
    if role_lower in ("user", "human"):
        if _POSSESSIVE_CONTEXT.search(text):
            return False, None  # Real PII - user is sharing their data

    # ========================================================================
    # RULE 2: AI-generated content needs context validation
    # ========================================================================
    if role_lower == "assistant":

        # Check for example/demonstration context
        if _EXAMPLE_CONTEXT.search(text):
            return True, "AI providing format example or demonstration"

        # Check for reference number context (order ID, transaction, etc.)
        if _REFERENCE_CONTEXT.search(text):
            if finding_id in ("PII_CC", "PII_SSN", "PII_PHONE"):
                return True, "Context indicates reference/ID number, not PII"

        # Check for math/calculation context
        if _MATH_CONTEXT.search(text):
            if finding_id == "PII_CC":  # Credit cards often look like big numbers
                return True, "Context indicates math calculation result"

        # Check for code context
        if _CODE_CONTEXT.search(text):
            if finding_id in ("PII_CC", "PII_SSN", "PII_PHONE", "PII_IP"):
                return True, "Number appears in code context"

    # ========================================================================
    # RULE 3: Specific finding type validations
    # ========================================================================

    # SSN: Check for "format" language (English + German)
    if finding_id == "PII_SSN":
        if re.search(r"(?i)(format|pattern|structure|looks?\s+like|syntax|muster|aufbau|struktur|sieht\s+aus\s+wie)", text):
            return True, "SSN appears in format/pattern description"

    # Credit Card: Check for test card indicators (English + German)
    if finding_id in ("PII_CC", "PII_CC_TEST"):
        if re.search(r"(?i)(test|demo|sandbox|staging|fake|dummy|sample|testkarte|beispielkarte|fiktiv)\s*(card|payment|number|karte|zahlung)?", text):
            return True, "Test/demo card context"

    # Phone: Check for fake/example indicators (English + German)
    if finding_id == "PII_PHONE":
        # 555 prefix is reserved for fictional use in US
        if re.search(r"555-\d{3}-\d{4}", evidence or text):
            if role_lower == "assistant":
                return True, "555 prefix indicates fictional phone number"
        # German fictional phone prefixes: 0800 (toll-free example), fictional area codes
        if re.search(r"(?i)(example|fake|placeholder|fictional|beispiel|fiktiv|platzhalter|muster)", text):
            return True, "Phone in example context"

    # Turkish TC Kimlik: Check for format/example language
    if finding_id == "PII_TC_KIMLIK":
        if re.search(r"(?i)(format[ıi]?|örnek|example|pattern|structure)", text):
            return True, "TC Kimlik in format/example context"

    # German IBAN: Check for format/example language
    if finding_id == "PII_IBAN":
        if re.search(r"(?i)(format|beispiel|muster|example|pattern|structure|aufbau|sieht\s+aus\s+wie|zum\s+beispiel|z\.?\s*b\.?)", text):
            return True, "IBAN in format/example context"

    # Stripe: Test keys (sk_test_, pk_test_) are always safe
    if finding_id == "SEC_STRIPE_01":
        if re.search(r"(?:sk|pk|rk)_test_", evidence or text):
            return True, "Stripe test key (not production)"
        if re.search(r"(?i)(test\s*key|sandbox|development|staging)", text):
            return True, "Stripe key in test context"

    # Generic secrets: Check for example/test context
    if finding_id.startswith("SEC_"):
        if re.search(r"(?i)(example|test|fake|dummy|placeholder|sample|xxx+)", evidence or ""):
            return True, "Secret appears to be placeholder/example"

    # ========================================================================
    # RULE 4: No suppression - this appears to be a real finding
    # ========================================================================
    return False, None


def validate_finding_context(
    finding_id: str,
    evidence: str,
    full_message: str,
    role: str,
) -> dict:
    """
    Validate a finding based on context.

    Returns:
        {
            "valid": bool,      # True if finding should be kept
            "reason": str,      # Reason for decision
            "confidence_adj": float,  # Confidence adjustment (-0.3 to +0.1)
        }
    """
    is_fp, reason = is_likely_false_positive(
        text=full_message,
        finding_id=finding_id,
        role=role,
        evidence=evidence,
    )

    if is_fp:
        return {
            "valid": False,
            "reason": reason,
            "confidence_adj": -0.5,
        }

    # Boost confidence if user is explicitly sharing data
    if (role or "").lower() in ("user", "human"):
        if _POSSESSIVE_CONTEXT.search(full_message):
            return {
                "valid": True,
                "reason": "User explicitly sharing personal data",
                "confidence_adj": +0.1,
            }

    return {
        "valid": True,
        "reason": "Context validation passed",
        "confidence_adj": 0.0,
    }
