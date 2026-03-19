"""
Benign Context Filter — False Positive Suppression

Skill spec target: < 5% FP rate for PII, < 10% for prompt injection.

Common false positive patterns:
  - Coding tutorials containing SQL/injection examples  → suppress injections
  - Base64 strings in developer conversations          → check context first
  - Multiple emails in business/code contexts          → suppress placeholders
  - High entropy in code snippets                      → suppress ANOM_ENTROPY
  - Security research discussions about jailbreaks     → suppress low-sev injections
  - AI-generated example numbers (math, order IDs)     → suppress PII
  - AI format demonstrations (SSN format: XXX-XX-XXXX) → suppress PII
"""

import re
from model import Finding, Severity
from controllers.context_validator import validate_finding_context

# ---------------------------------------------------------------------------
# Code block detection
# ---------------------------------------------------------------------------

_CODE_FENCE_RE = re.compile(r'```[\s\S]*?```', re.MULTILINE)
_CODE_INLINE_RE = re.compile(r'`[^`\n]{3,}`')


def is_in_code_block(evidence: str, message_text: str) -> bool:
    """Return True if the evidence snippet appears inside a fenced or inline code block."""
    if not message_text or not evidence:
        return False
    snippet = evidence[:150]
    for block in _CODE_FENCE_RE.findall(message_text):
        if snippet in block:
            return True
    for block in _CODE_INLINE_RE.findall(message_text):
        if snippet in block:
            return True
    return False


# ---------------------------------------------------------------------------
# Placeholder / test data detection
# ---------------------------------------------------------------------------

_PLACEHOLDER_EMAIL_DOMAINS = {
    "example.com", "example.org", "example.net",
    "test.com", "test.org", "testing.com",
    "foo.com", "bar.com", "baz.com",
    "placeholder.com", "domain.com", "yourdomain.com",
    "sample.com", "demo.com", "fake.com",
    "email.com", "yoursite.com", "website.com",
    "noreply.com", "no-reply.com",
    "mailinator.com", "tempmail.com",
}

_PLACEHOLDER_IP_PREFIXES = (
    "127.", "0.0.0.", "255.255.",   # loopback / broadcast
    "192.168.", "10.", "172.16.",   # private ranges
    "169.254.",                      # link-local
    "0.0.0",                         # unspecified
)

_EXAMPLE_CARD_NUMBERS = {
    # Luhn-valid test numbers published by payment providers
    "4111111111111111", "4242424242424242", "4012888888881881",
    "5500005555555559", "5105105105105100",
    "378282246310005",  "371449635398431",
    "6011111111111117", "3530111333300000",
}


def is_placeholder_email(email: str) -> bool:
    domain = email.lower().split("@", 1)[-1] if "@" in email else ""
    return domain in _PLACEHOLDER_EMAIL_DOMAINS


def is_safe_ip(ip: str) -> bool:
    return any(ip.startswith(p) for p in _PLACEHOLDER_IP_PREFIXES)


def is_test_card(number: str) -> bool:
    digits = re.sub(r"\D", "", number)
    return digits in _EXAMPLE_CARD_NUMBERS


# ---------------------------------------------------------------------------
# Benign context signals
# ---------------------------------------------------------------------------

_BENIGN_SIGNALS_RE = re.compile(
    r'\b(example|tutorial|how does|how do|for educational|academic|research|'
    r'demonstrat|sample|suppose|hypothetical|test case|unit test|proof of concept|'
    r'poc|for example|suppose we|let\'s say|imagine|walkthrough|step.by.step|'
    r'in this case|consider the following|here\'s how|for instance|'
    r'security research|ctf|capture the flag|penetration test|pentest)\b',
    re.IGNORECASE,
)


def is_benign_context(message_text: str) -> bool:
    """Return True if the message seems to be educational, research, or tutorial content."""
    return bool(_BENIGN_SIGNALS_RE.search(message_text))


# ---------------------------------------------------------------------------
# Main suppression logic
# ---------------------------------------------------------------------------

def should_suppress(finding: Finding, message_text: str, role: str = None) -> bool:
    """
    Return True if this finding is likely a false positive and should be removed.

    Rules applied in order:
    1. Role-based context validation (AI examples vs user real data)
    2. Evidence inside a code block → suppress PII, dark patterns, low-sev injection, entropy
    3. Placeholder email domains → suppress PII_EMAIL
    4. Safe/private IP addresses → suppress PII_IP
    5. Known test card numbers → suppress PII_CC
    6. Benign educational context → suppress low/medium injection findings
    """
    fid = finding.id
    sev = finding.severity
    ev = finding.evidence
    role = role or (finding.provenance.role if finding.provenance else None) or ""

    # --- RULE 0: Role-based context validation for PII ---
    # AI-generated numbers in examples/math/code should not be flagged
    if fid.startswith("PII_") or fid.startswith("SEC_"):
        validation = validate_finding_context(
            finding_id=fid,
            evidence=ev,
            full_message=message_text,
            role=role,
        )
        if not validation["valid"]:
            return True  # Suppress this finding

    in_code = is_in_code_block(ev, message_text)

    # --- Code block suppressions ---
    if in_code:
        # Always suppress PII inside code (they're placeholders / example data)
        if fid.startswith("PII_"):
            return True
        # Suppress dark patterns / hallucination / anomalies inside code
        if fid.startswith(("DARK_", "HAL_", "ANOM_")):
            return True
        # Suppress low/medium injection inside code (tutorial examples)
        if fid.startswith("INJ_") and sev in (Severity.LOW, Severity.MEDIUM, Severity.INFO):
            return True

    # --- Placeholder email ---
    if fid == "PII_EMAIL":
        emails = re.findall(r"[\w.+-]+@[\w.-]+\.\w+", ev)
        if emails and all(is_placeholder_email(e) for e in emails):
            return True

    # --- Safe IP ---
    if fid == "PII_IP":
        ips = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", ev)
        if ips and all(is_safe_ip(ip) for ip in ips):
            return True

    # --- Test card numbers ---
    if fid == "PII_CC":
        if is_test_card(ev):
            return True

    # --- Benign educational context: suppress low-severity injections ---
    if fid.startswith("INJ_") and sev in (Severity.LOW, Severity.MEDIUM):
        if is_benign_context(message_text):
            return True

    # --- Entropy anomalies in code-heavy messages ---
    if fid == "ANOM_ENTROPY":
        # If message has a code fence, entropy is expected
        if "```" in (message_text or "") and sev in (Severity.LOW, Severity.MEDIUM):
            return True

    return False


def apply_suppression(findings: list, msgs: list) -> tuple[list, int]:
    """
    Post-process findings list, removing benign false positives.

    Args:
        findings: List of Finding objects
        msgs:     List of Message objects (to look up original message text)

    Returns:
        (filtered_findings, suppressed_count)
    """
    # Build fast lookup: (conversation_id, message_index) → (message text, role)
    msg_lookup: dict[tuple, tuple] = {}
    for msg in msgs:
        msg_lookup[(msg.conversation_id, msg.index)] = (msg.content, msg.role)

    kept = []
    suppressed = 0
    for f in findings:
        loc = f.provenance
        msg_data = msg_lookup.get((loc.conversation_id, loc.message_index), ("", ""))
        msg_text, msg_role = msg_data
        # Use finding's role if available, otherwise message role
        role = loc.role or msg_role or ""
        if should_suppress(f, msg_text, role):
            suppressed += 1
        else:
            kept.append(f)

    return kept, suppressed
