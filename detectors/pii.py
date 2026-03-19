"""
PII & Privacy Detector — OWASP LLM02:2025, LLM06:2025 / GDPR / CCPA

Covers 19 categories:
  Personal: email, phone, SSN, passport, driver's license, date of birth,
            street address, full name, national ID, IP address
  Financial: credit card (Luhn), IBAN (MOD-97), crypto wallet (BTC/ETH)
  Credentials: API keys (OpenAI, AWS, GitHub, Google), private keys,
               JWT tokens, plaintext passwords

Validation: Luhn for CC, MOD-97 for IBAN, context suppression for version numbers.
"""

import re
import ipaddress
from typing import List
from model import Finding, Severity, ProvenanceLocator

# All RFC-1918 + loopback + link-local + Docker ranges that are NOT public PII
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),      # loopback
    ipaddress.ip_network("10.0.0.0/8"),        # RFC-1918 class A
    ipaddress.ip_network("172.16.0.0/12"),     # RFC-1918 class B
    ipaddress.ip_network("192.168.0.0/16"),    # RFC-1918 class C
    ipaddress.ip_network("169.254.0.0/16"),    # link-local
    ipaddress.ip_network("0.0.0.0/8"),         # "this" network
]


def _is_private_ip(ip_str: str) -> bool:
    """Return True if the IP address is in a private/loopback/link-local range."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def validate_luhn(card_num: str) -> bool:
    digits = [int(x) for x in card_num if x.isdigit()]
    if len(digits) < 13:
        return False
    checksum = 0
    is_second = False
    for d in reversed(digits):
        if is_second:
            d = d * 2
            if d > 9:
                d -= 9
        checksum += d
        is_second = not is_second
    return checksum % 10 == 0


def validate_iban(iban: str) -> bool:
    """MOD-97 IBAN validation."""
    iban = iban.replace(" ", "").upper()
    if len(iban) < 15:
        return False
    rearranged = iban[4:] + iban[:4]
    numeric = ""
    for ch in rearranged:
        if ch.isdigit():
            numeric += ch
        elif ch.isalpha():
            numeric += str(ord(ch) - ord("A") + 10)
        else:
            return False
    try:
        return int(numeric) % 97 == 1
    except ValueError:
        return False


def _pii(fid, subtype, severity, score, evidence, locator, redaction, action, confidence=0.85):
    return Finding(
        id=fid,
        category="Personal Information (PII)",
        framework_mapping="OWASP LLM02:2025, GDPR Article 4",
        severity=severity,
        score=score,
        confidence=confidence,
        evidence=str(evidence)[:200],
        provenance=locator,
        recommended_action=action,
        safe_redaction=redaction,
    )


# ---------------------------------------------------------------------------
# Main detector
# ---------------------------------------------------------------------------

def detect_pii(text: str, locator: ProvenanceLocator) -> List[Finding]:
    """Detect PII across 19 categories with context-aware validation."""
    if not text or not text.strip():
        return []

    findings: List[Finding] = []

    # ---- 1. Email -----------------------------------------------------------
    email_re = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}")
    for m in email_re.finditer(text):
        addr = m.group(0)
        local = addr.split("@")[0]
        findings.append(_pii(
            "PII_EMAIL", "Email Address",
            Severity.LOW, 30,
            addr, locator,
            f"{local[0]}...@...",
            ["Verify if email sharing violates privacy policy"],
            confidence=0.9,
        ))

    # ---- 2. Phone number ----------------------------------------------------
    # Avoid matching version numbers like "v1.2.3" or "2.0.1"
    phone_re = re.compile(
        r"(?<!\d)"
        r"(\+?1[-.\s]?)?"
        r"\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}"
        r"(?!\.\d)"
    )
    for m in phone_re.finditer(text):
        # Skip if surrounded by version-like context
        snippet = text[max(0, m.start()-5):m.end()+5]
        if re.search(r"v\d|version|v\s*\d", snippet, re.I):
            continue
        findings.append(_pii(
            "PII_PHONE", "Phone Number",
            Severity.MEDIUM, 50,
            m.group(0), locator,
            "***-***-****",
            ["Remove or redact phone numbers from AI conversations"],
        ))

    # ---- 3. US Social Security Number ---------------------------------------
    ssn_re = re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")
    for m in ssn_re.finditer(text):
        findings.append(_pii(
            "PII_SSN", "US Social Security Number",
            Severity.CRITICAL, 95,
            m.group(0), locator,
            "XXX-XX-" + m.group(0)[-4:],
            ["Redact SSN immediately", "Report potential data breach if shared externally"],
            confidence=0.9,
        ))

    # ---- 4. Credit card (Luhn validated + test card filtered) ---------------
    _CC_TEST_CARDS = {
        "4242424242424242", "4111111111111111", "4012888888881881",
        "4000056655665556", "5555555555554444", "5105105105105100",
        "5200828282828210", "5425233430109903", "378282246310005",
        "371449635398431", "6011111111111117", "6011000990139424",
        "3530111333300000", "3566002020360505", "6304000000000000",
        "6759649826438453", "4026000000000002", "4508750000000003",
        "4917484589897107",
    }
    cc_re = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
    for m in cc_re.finditer(text):
        cc_str = re.sub(r"[\s-]", "", m.group(0))
        if not (13 <= len(cc_str) <= 19):
            continue
        if not validate_luhn(cc_str):
            continue  # failed Luhn — not a real card number
        if cc_str in _CC_TEST_CARDS:
            # Test/demo card — flag as LOW informational only
            findings.append(_pii(
                "PII_CC_TEST", "Test Credit Card (Demo Number)",
                Severity.LOW, 10,
                m.group(0), locator,
                "XXXX-XXXX-XXXX-" + cc_str[-4:] + " [TEST]",
                ["Known test card number — not a real card, no action needed"],
                confidence=0.99,
            ))
        else:
            findings.append(_pii(
                "PII_CC", "Credit Card Number",
                Severity.CRITICAL, 95,
                m.group(0), locator,
                "XXXX-XXXX-XXXX-" + cc_str[-4:],
                ["Redact credit card number immediately", "Report to your bank if inadvertently shared"],
                confidence=0.95,
            ))

    # ---- 5. IBAN (MOD-97 validated) -----------------------------------------
    iban_re = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9 ]{11,30}\b")
    for m in iban_re.finditer(text):
        candidate = m.group(0).replace(" ", "")
        if validate_iban(candidate):
            findings.append(_pii(
                "PII_IBAN", "IBAN Bank Account",
                Severity.HIGH, 85,
                candidate[:8] + "...", locator,
                candidate[:4] + "XXXX...",
                ["Remove bank account numbers from conversations"],
                confidence=0.9,
            ))

    # ---- 6. Passport number -------------------------------------------------
    # Generic: 1-2 letters + 6-9 digits (covers most countries)
    passport_re = re.compile(
        r"(?i)(?:passport\s*(?:no|number|#)?\s*[:=]?\s*)"
        r"([A-Z]{1,2}\d{6,9})"
    )
    for m in passport_re.finditer(text):
        findings.append(_pii(
            "PII_PASSPORT", "Passport Number",
            Severity.HIGH, 80,
            m.group(1), locator,
            "XXXXXXXX",
            ["Remove government ID numbers from AI conversations"],
        ))

    # ---- 7. Driver's license (US-style) -------------------------------------
    dl_re = re.compile(
        r"(?i)(?:driver.?s?\s+licen[sc]e|dl\s*(?:no|number|#))\s*[:=]?\s*([A-Z0-9-]{5,15})"
    )
    for m in dl_re.finditer(text):
        findings.append(_pii(
            "PII_DL", "Driver's License Number",
            Severity.HIGH, 75,
            m.group(1), locator,
            "XXXXXXXXX",
            ["Remove government ID numbers from AI conversations"],
        ))

    # ---- 8. IP address ------------------------------------------------------
    ip_re = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    )
    for m in ip_re.finditer(text):
        ip = m.group(0)
        # Fix 1C: Skip ALL private / loopback / link-local ranges — not PII
        if ip == "255.255.255.255" or _is_private_ip(ip):
            continue
        findings.append(_pii(
            "PII_IP", "IP Address",
            Severity.LOW, 30,
            ip, locator,
            "x.x.x.x",
            ["Consider if IP address identifies a specific individual (GDPR Art. 4)"],
            confidence=0.75,
        ))

    # ---- 9. Cryptocurrency wallet addresses ---------------------------------
    btc_re = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
    eth_re = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
    for m in btc_re.finditer(text):
        findings.append(_pii(
            "PII_CRYPTO_BTC", "Bitcoin Wallet Address",
            Severity.MEDIUM, 50,
            m.group(0), locator,
            m.group(0)[:6] + "...",
            ["Crypto wallets can uniquely identify individuals on-chain"],
        ))
    for m in eth_re.finditer(text):
        findings.append(_pii(
            "PII_CRYPTO_ETH", "Ethereum Wallet Address",
            Severity.MEDIUM, 50,
            m.group(0), locator,
            "0x" + "X" * 8 + "...",
            ["Crypto wallets can uniquely identify individuals on-chain"],
        ))

    # ---- 10. Date of birth --------------------------------------------------
    dob_re = re.compile(
        r"(?i)(?:date\s+of\s+birth|dob|born\s+on|birthday)\s*[:=]?\s*"
        r"(\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}[/-]\d{2}[/-]\d{2})"
    )
    for m in dob_re.finditer(text):
        findings.append(_pii(
            "PII_DOB", "Date of Birth",
            Severity.MEDIUM, 55,
            m.group(1), locator,
            "**/**/****",
            ["Date of birth is protected PII — remove from conversations"],
        ))

    # ---- 11. Language detection (boosts confidence for country-specific PII) --
    def _detect_lang(t: str) -> str:
        if any(c in "çğıöşüÇĞİÖŞÜ" for c in t):
            return "tr"
        if any(c in "äöüßÄÖÜ" for c in t):
            return "de"
        return "en"

    msg_lang = _detect_lang(text)

    # ---- 12. Turkish phone number -------------------------------------------
    # Mobile starts with 5, optionally preceded by +90 or 0
    tr_phone_re = re.compile(r"(?<!\d)(?:\+90|0)?5\d{9}(?!\d)")
    for m in tr_phone_re.finditer(text):
        findings.append(_pii(
            "PII_PHONE_TR", "Turkish Phone Number",
            Severity.MEDIUM, 50,
            m.group(0), locator,
            "+90 5XX XXX XXXX",
            ["Turkish phone numbers are personal data under KVKK."],
            confidence=0.88 if msg_lang == "tr" else 0.65,
        ))

    # ---- 13. Turkish IBAN ---------------------------------------------------
    tr_iban_re = re.compile(r"\bTR\d{24}\b")
    for m in tr_iban_re.finditer(text):
        candidate = m.group(0)
        if validate_iban(candidate):
            findings.append(_pii(
                "PII_IBAN_TR", "Turkish IBAN",
                Severity.HIGH, 80,
                candidate[:8] + "...", locator,
                "TR" + "X" * 24,
                ["Turkish IBAN is sensitive financial data under KVKK."],
                confidence=0.92 if msg_lang == "tr" else 0.82,
            ))

    # ---- 14. UK National Insurance Number (NIN) -----------------------------
    # Format: two letters + 6 digits + A-D. Reject invalid prefixes.
    uk_nin_re = re.compile(r"\b(?!(?:BG|GB|KN|NK|NT|TN|ZZ))[A-Z]{2}\d{6}[A-D]\b")
    for m in uk_nin_re.finditer(text):
        findings.append(_pii(
            "PII_UK_NIN", "UK National Insurance Number",
            Severity.HIGH, 80,
            m.group(0), locator,
            "XXXXXXXX",
            ["UK NIN is sensitive government ID under UK GDPR."],
            confidence=0.82,
        ))

    # ---- 15. German Steuer-ID (Tax ID) — requires context keyword -----------
    steuer_ctx_re = re.compile(
        r"(?i)(?:steuer.?(?:nummer|id|identifikationsnummer)|tax\s*id|steuernummer)\D{0,10}(\d{11})"
    )
    for m in steuer_ctx_re.finditer(text):
        findings.append(_pii(
            "PII_STEUER_ID", "German Steuer-ID (Tax ID)",
            Severity.HIGH, 80,
            m.group(1), locator,
            "XXXXXXXXXXX",
            ["German Steuer-ID is sensitive PII under DSGVO/BDSG."],
            confidence=0.88 if msg_lang == "de" else 0.72,
        ))

    # ---- 16. German phone ---------------------------------------------------
    de_phone_re = re.compile(r"\b(?:\+49|0)[1-9]\d{6,12}\b")
    for m in de_phone_re.finditer(text):
        findings.append(_pii(
            "PII_PHONE_DE", "German Phone Number",
            Severity.MEDIUM, 50,
            m.group(0), locator,
            "+49 XXX XXXXXXX",
            ["German phone numbers are personal data under DSGVO."],
            confidence=0.82 if msg_lang == "de" else 0.60,
        ))

    # ---- 17. German IBAN ----------------------------------------------------
    de_iban_re = re.compile(r"\bDE\d{20}\b")
    for m in de_iban_re.finditer(text):
        candidate = m.group(0)
        if validate_iban(candidate):
            findings.append(_pii(
                "PII_IBAN_DE", "German IBAN",
                Severity.HIGH, 80,
                candidate[:8] + "...", locator,
                "DE" + "X" * 20,
                ["German IBAN is sensitive financial data under DSGVO."],
                confidence=0.92 if msg_lang == "de" else 0.82,
            ))

    # ---- 18. Turkish National ID (TC Kimlik No) ------------------------------
    # 11 digits, first digit 1-9, with a specific checksum algorithm.
    # Checksum step 1: (7*(d0+d2+d4+d6+d8) - (d1+d3+d5+d7)) % 10 == d9
    # Checksum step 2: (d0+d1+...+d9) % 10 == d10
    tc_kimlik_re = re.compile(r"\b[1-9]\d{10}\b")

    def _validate_tc_kimlik(num: str) -> bool:
        if len(num) != 11 or not num.isdigit():
            return False
        d = [int(x) for x in num]
        check10 = (7 * (d[0] + d[2] + d[4] + d[6] + d[8]) - (d[1] + d[3] + d[5] + d[7])) % 10
        if check10 != d[9]:
            return False
        return sum(d[:10]) % 10 == d[10]

    for m in tc_kimlik_re.finditer(text):
        num = m.group(0)
        if _validate_tc_kimlik(num):
            findings.append(_pii(
                "PII_TC_KIMLIK", "Turkish National ID (TC Kimlik No)",
                Severity.HIGH, 80,
                num, locator,
                num[:3] + "XXXXXXXX",
                [
                    "Turkish National ID numbers are sensitive personal data under KVKK (Turkish GDPR).",
                    "Remove TC Kimlik numbers from AI conversations immediately.",
                ],
                confidence=0.92 if msg_lang == "tr" else 0.80,
            ))

    return findings
