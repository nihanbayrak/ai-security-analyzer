"""
Prompt Injection Detector — OWASP LLM01:2025, LLM07:2025 / MITRE ATLAS T0051, T0054

Covers:
  - Direct instruction overrides
  - Jailbreak templates (DAN, AIM, developer-mode, etc.)
  - System prompt leak attempts
  - Role-play / persona hijack attacks
  - Encoding / obfuscation attacks (Base64) — ONLY if decoded content is malicious
  - Delimiter confusion attacks
  - Indirect injection via tool / document context

Sender rules (Fix 9):
  - User/human sender attacking AI → CONFIRM
  - Assistant sender → skip (AI doesn't inject itself)
  - Tool/system → flag as indirect injection (higher severity)
  - Educational context (asking *about* injection, CTF, research) → skip
"""

import re
import base64
from typing import List
from model import Finding, Severity, ProvenanceLocator

# ---------------------------------------------------------------------------
# Pattern banks
# ---------------------------------------------------------------------------

_OVERRIDE_PATTERNS = [
    r"(?i)ignore\s+(all\s+)?previous\s+instructions",
    r"(?i)disregard\s+(all\s+)?previous\s+instructions",
    r"(?i)forget\s+(all\s+)?your\s+(previous\s+)?instructions",
    r"(?i)new\s+system\s+prompt\s*:",
    r"(?i)system\s*:\s*override",
    r"(?i)your\s+new\s+instructions\s+(are|follow)",
    r"(?i)override\s+(safety|content)\s+(filter|policy|guidelines?)",
    r"(?i)bypass\s+(your\s+)?(safety|content|ethical)\s+(filter|restrictions?|guidelines?)",
    r"(?i)disable\s+(your\s+)?(safety|content|ethical)\s+(filter|restrictions?|guidelines?)",
]

_JAILBREAK_PATTERNS = [
    r"(?i)\bDAN\b.*mode",
    r"(?i)you\s+are\s+now\s+(DAN|AIM|JAILBREAK|DEVMODE|BetterDAN)",
    r"(?i)pretend\s+(you\s+are|to\s+be)\s+(an?\s+)?(AI\s+with\s+no|uncensored|unfiltered|evil|unrestricted)",
    r"(?i)(act|behave)\s+as\s+(if\s+you\s+(have\s+no|are\s+without)\s+restrict|an?\s+unrestricted)",
    r"(?i)enable\s+(developer|god|admin|jailbreak|unrestricted)\s+mode",
    r"(?i)you\s+are\s+now\s+(operating|running|in)\s+(developer|god|admin|unrestricted)\s+mode",
    r"(?i)(jailbreak|jail\s*break)\s+(prompt|mode|this|the\s+AI)",
    r"(?i)imagine\s+you\s+(have\s+no\s+(rules|restrictions|guidelines|ethics)|are\s+free\s+to)",
    r"(?i)respond\s+(as\s+if|like)\s+you\s+(have\s+no|are\s+not\s+bound\s+by)",
]

_LEAK_PATTERNS = [
    r"(?i)what\s+(is\s+your\s+system\s+prompt|are\s+your\s+initial\s+instructions)",
    r"(?i)(reveal|show|print|output|display|repeat)\s+(your\s+)?(system\s+prompt|initial\s+instructions?|configuration|prompt)",
    r"(?i)tell\s+me\s+(what\s+you\s+were\s+told|your\s+instructions|your\s+system\s+prompt)",
    r"(?i)print\s+(the\s+text\s+above|everything\s+before\s+this|your\s+prompt)",
    r"(?i)(output|repeat|echo)\s+all\s+(previous|prior|above|your\s+system)\s+(text|messages?|instructions?|prompt)",
]

_ROLEPLAY_PATTERNS = [
    r"(?i)(act|pretend|play|role.?play)\s+as\s+(a\s+)?(hacker|criminal|evil|malicious|dark\s+web)",
    r"(?i)you\s+are\s+(now\s+)?(a\s+)?(hacker|criminal|without\s+(morals|ethics)|evil\s+AI|malicious\s+AI)",
    r"(?i)from\s+now\s+on\s+(you\s+are|act\s+as|pretend\s+to\s+be)",
    r"(?i)switch\s+(your|the)\s+(persona|personality|role|mode)\s+to",
    r"(?i)take\s+on\s+the\s+role\s+of\s+(a\s+)?(hacker|villain|malicious|unrestricted)",
]

_DELIMITER_PATTERNS = [
    r"(?i)---+\s*(system|prompt|instruction|new\s+context)",
    r"\[SYSTEM\]",
    r"<\|system\|>",
    r"<<SYS>>",
    r"(?i)\[INST\].*ignore",
    r"(?i)###\s*(system|new\s+prompt|override)",
]

# Malicious patterns to look for in decoded Base64 content (Fix 1A)
_DECODED_INJECTION_KW = re.compile(
    r"(?i)(?:ignore\s+(?:previous|all|above)\s+instructions?|"
    r"override\s+(?:safety|content|your)|"
    r"disregard\s+(?:previous|all)|"
    r"you\s+are\s+now\s+(?:DAN|AIM|JAILBREAK|unrestricted)|"
    r"forget\s+your\s+instructions|"
    r"new\s+system\s+prompt|"
    r"developer\s+mode|jailbreak|"
    r"rm\s+-rf|curl\s+\|\s*bash|eval\s*\(|exec\s*\(|os\.system|"
    r"subprocess\.(?:run|call|Popen))",
)

# Educational / research context signals — don't flag these as attacks (Fix 7)
_EDUCATIONAL_RE = re.compile(
    r"(?i)(?:what\s+is\s+(?:a\s+)?(?:prompt\s+injection|jailbreak|DAN)|"
    r"how\s+(?:does|do)\s+(?:prompt\s+injection|jailbreak)|"
    r"explain\s+(?:prompt\s+injection|jailbreak|this\s+attack)|"
    r"\b(?:CTF|capture\s+the\s+flag|pentesting?|red\s*team|security\s+research|"
    r"owasp|mitre\s+atlas|tutorial|example\s+of|for\s+educational|"
    r"how\s+(?:can\s+i|to)\s+(?:protect|defend|prevent)|"
    r"is\s+it\s+(?:safe|possible\s+to)|research\s+paper|"
    r"how\s+(?:can\s+i\s+protect|do\s+i\s+defend)))",
)


def _try_decode_b64(text: str):
    b64_re = re.compile(r"(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
    decoded_chunks = []
    for m in b64_re.finditer(text):
        try:
            raw = base64.b64decode(m.group(0) + "==")
            decoded = raw.decode("utf-8", errors="ignore")
            if len(decoded) > 20:
                decoded_chunks.append(decoded)
        except Exception:
            pass
    return decoded_chunks


def _make_finding(fid, category, framework, severity, score, evidence, locator, action, confidence=0.9):
    return Finding(
        id=fid,
        category=category,
        framework_mapping=framework,
        severity=severity,
        score=score,
        confidence=confidence,
        evidence=str(evidence)[:300],
        provenance=locator,
        recommended_action=action,
        safe_redaction=f"[{category} DETECTED]",
    )


def detect_prompt_injection(text: str, locator: ProvenanceLocator, is_tool_or_system: bool = False) -> List[Finding]:
    """Multi-tier prompt injection detector. Returns findings sorted by severity.

    Sender rules (Fix 9):
    - assistant sender → skip (AI doesn't inject itself)
    - user/human with educational context → skip (researching, not attacking)
    - tool/system → indirect injection (higher severity)
    """
    if not text or not text.strip():
        return []

    role = (locator.role or "").lower()

    # Fix 9: Assistant messages are never injections — the AI doesn't inject itself
    if role == "assistant":
        return []

    # Fix 7: User asking about injection topics educationally — not an attack
    if role in ("user", "human") and _EDUCATIONAL_RE.search(text):
        return []

    findings = []
    indirect = is_tool_or_system

    # Tier-1: Direct overrides
    for pattern in _OVERRIDE_PATTERNS:
        m = re.search(pattern, text)
        if m:
            sev = Severity.CRITICAL if indirect else Severity.HIGH
            findings.append(_make_finding(
                "INJ_OVERRIDE",
                "Indirect Prompt Injection" if indirect else "Direct Prompt Injection",
                "OWASP LLM01:2025, MITRE ATLAS T0051",
                sev, 95 if indirect else 85,
                f"Override attempt: '{m.group(0)}'",
                locator,
                ["Apply strict input delimiters", "Treat external content as untrusted data, not instructions"],
            ))
            break

    # Tier-2: Jailbreak templates
    for pattern in _JAILBREAK_PATTERNS:
        m = re.search(pattern, text)
        if m:
            findings.append(_make_finding(
                "INJ_JAILBREAK",
                "Jailbreak Attempt",
                "OWASP LLM01:2025, MITRE ATLAS T0054",
                Severity.HIGH, 85,
                f"Jailbreak template: '{m.group(0)}'",
                locator,
                ["Block known jailbreak templates at the API gateway", "Log and review the full conversation"],
                confidence=0.85,
            ))
            break

    # Tier-3: System prompt leak attempts
    for pattern in _LEAK_PATTERNS:
        m = re.search(pattern, text)
        if m:
            findings.append(_make_finding(
                "INJ_LEAK",
                "System Prompt Leak Attempt",
                "OWASP LLM07:2025, OWASP LLM01:2025",
                Severity.HIGH, 80,
                f"Prompt extraction attempt: '{m.group(0)}'",
                locator,
                ["Never echo system prompt content in responses", "Instruct model to refuse prompt reveal requests"],
                confidence=0.85,
            ))
            break

    # Tier-4: Role-play / persona hijack
    for pattern in _ROLEPLAY_PATTERNS:
        m = re.search(pattern, text)
        if m:
            findings.append(_make_finding(
                "INJ_ROLEPLAY",
                "Role-Play / Persona Hijack",
                "OWASP LLM01:2025",
                Severity.MEDIUM, 65,
                f"Persona hijack attempt: '{m.group(0)}'",
                locator,
                ["Monitor persona-switching requests", "Restrict role-play to safe predefined personas"],
                confidence=0.8,
            ))
            break

    # Tier-5: Delimiter / context confusion
    for pattern in _DELIMITER_PATTERNS:
        m = re.search(pattern, text)
        if m:
            findings.append(_make_finding(
                "INJ_DELIM",
                "Delimiter Confusion Attack",
                "OWASP LLM01:2025",
                Severity.MEDIUM, 60,
                f"Suspicious delimiter pattern: '{m.group(0)}'",
                locator,
                ["Sanitize special delimiter tokens from user input"],
                confidence=0.75,
            ))
            break

    # Fix 1A: Encoding attacks — ONLY flag if decoded content is actually malicious
    # If decoded content is benign → NO FINDING. Period.
    b64_re = re.compile(r"(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
    if b64_re.search(text):
        decoded_chunks = _try_decode_b64(text)
        if decoded_chunks:
            malicious_decoded = [
                chunk for chunk in decoded_chunks
                if _DECODED_INJECTION_KW.search(chunk)
            ]
            if malicious_decoded:
                # Has confirmed malicious payload
                first_bad = malicious_decoded[0]
                findings.append(_make_finding(
                    "INJ_ENC_INJECTION",
                    "Encoded Injection Attack",
                    "OWASP LLM01:2025",
                    Severity.CRITICAL, 95,
                    f"Decoded Base64 payload: {first_bad[:200]}",
                    locator,
                    ["Decode and re-scan all Base64 blocks before processing",
                     "Reject inputs with encoded injection patterns"],
                    confidence=0.92,
                ))
            # else: decoded content is benign → no finding (Fix 1A core)

    return findings
