"""PII Supervisor — validates privacy findings with country-aware context."""

from .base import llm_call, parse_verdict
from .prompts import PII_PROMPT
from controllers.credit_card import is_test_card, validate_luhn
from controllers.iban import validate as validate_iban
from controllers.tc_kimlik import validate as validate_tc_kimlik

_PLACEHOLDER_DOMAINS = {
    "example.com", "example.org", "example.net", "test.com", "foo.com",
    "bar.com", "email.com", "domain.com", "placeholder.com", "sample.com",
    "yourcompany.com", "company.com", "acme.com", "localhost",
}


def evaluate(finding: dict, context: dict) -> dict:
    """
    Context-evaluate a PII finding.
    """
    fid = finding.get("id", "")
    evidence = finding.get("evidence", "")
    in_code = context.get("in_code_block", False)
    role = (context.get("sender") or "").lower()

    # Fast reject: code block variable context
    if in_code and role != "user":
        # In code blocks, PII is usually just an example variable
        if fid in ("PII_EMAIL", "PII_IP", "PII_PHONE"):
            return {"verdict": "reject", "reason": "PII appears inside a code block as example/variable", "confidence": 80}

    # Placeholder email rejection
    if fid == "PII_EMAIL":
        domain = evidence.split("@")[-1].lower().strip() if "@" in evidence else ""
        if domain in _PLACEHOLDER_DOMAINS:
            return {"verdict": "reject", "reason": f"Placeholder email domain: {domain}", "confidence": 95}

    # Test credit card rejection (uses credit_card controller)
    if fid == "PII_CC":
        if is_test_card(evidence):
            return {"verdict": "reject", "reason": "Known test/demo credit card number", "confidence": 98}
        digits = "".join(c for c in evidence if c.isdigit())
        if not validate_luhn(digits):
            return {"verdict": "reject", "reason": "Failed Luhn algorithm — not a valid card", "confidence": 95}

    # IBAN validation via controller
    if fid in ("PII_IBAN", "PII_IBAN_TR", "PII_IBAN_DE"):
        result = validate_iban(evidence.replace(" ", ""))
        if not result["valid"]:
            return {"verdict": "reject", "reason": f"IBAN invalid: {result['reason']}", "confidence": 90}

    # TC Kimlik validation via controller
    if fid == "PII_TC_KIMLIK":
        digits_only = "".join(c for c in evidence if c.isdigit())
        if len(digits_only) == 11:
            result = validate_tc_kimlik(digits_only)
            if not result["valid"]:
                return {"verdict": "reject", "reason": f"TC Kimlik invalid: {result['reason']}", "confidence": 90}
            if result.get("is_placeholder"):
                return {"verdict": "reject", "reason": "Sequential/placeholder TC Kimlik", "confidence": 95}

    # Private/loopback IP rejection
    if fid == "PII_IP":
        ip = evidence.strip()
        if (ip.startswith("127.") or ip.startswith("0.") or
                ip.startswith("10.") or ip.startswith("192.168.") or
                ip.startswith("172.") or ip == "255.255.255.255"):
            return {"verdict": "reject", "reason": "Private/loopback IP address", "confidence": 95}

    # LLM for ambiguous country-specific PII
    if fid in ("PII_TC_KIMLIK", "PII_IBAN", "PII_SSN", "PII_CC", "PII_PASSPORT"):
        lang = context.get("language", "en")
        messages = [
            {"role": "system", "content": PII_PROMPT},
            {"role": "user", "content": (
                f"Finding: {fid} — evidence: {evidence[:200]}\n"
                f"Sender: {context.get('sender', 'unknown')}\n"
                f"Conversation language detected: {lang}\n"
                f"In code block: {in_code}\n"
                f"Context: {context.get('surrounding_messages', '')[:300]}\n\n"
                "Is this real PII or a false positive?\n"
                'Reply JSON: {"verdict":"confirm|reject|downgrade","reason":"...","confidence":0-100}'
            )},
        ]
        raw = llm_call(messages)
        verdict = parse_verdict(raw)
        if verdict["verdict"] != "unvalidated":
            return verdict

    # Default: confirm (heuristic detectors already filtered)
    return {"verdict": "confirm", "reason": "Passed all heuristic checks", "confidence": 75}
