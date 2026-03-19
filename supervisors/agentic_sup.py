"""
Agentic Supervisor — AI tool call safety analyst.

Evaluates risks from AI tool usage: browser visits, code execution,
DALL-E generation, and multi-step tool chains.
"""

import re
from supervisors.base import llm_call, parse_verdict
from supervisors.prompts import AGENTIC_PROMPT

# Safe domains that browser tool should not trigger findings for
_SAFE_DOMAINS = {
    "google.com", "github.com", "wikipedia.org", "stackoverflow.com",
    "docs.python.org", "developer.mozilla.org", "npmjs.com", "pypi.org",
    "anthropic.com", "openai.com", "huggingface.co", "arxiv.org",
    "microsoft.com", "apple.com", "amazon.com", "aws.amazon.com",
    "cloudflare.com", "youtube.com", "twitter.com", "x.com",
    "linkedin.com", "reddit.com", "medium.com", "substack.com",
}

# Dangerous code patterns in code interpreter calls
_DANGEROUS_CODE = re.compile(
    r"(?:subprocess|os\.system|eval|exec|__import__|urllib\.request|requests\.(get|post)|"
    r"socket\.|ftplib|smtplib|paramiko|/etc/passwd|/proc/|rm -rf|chmod\s+7|wget\s+|curl\s+)",
    re.IGNORECASE,
)

# Injection keywords in DALL-E prompts
_DALLE_INJECT = re.compile(
    r"(?:ignore\s+(?:previous|above|all)|disregard|jailbreak|override|bypass|system\s+prompt|"
    r"DAN|do\s+anything\s+now|pretend\s+you\s+are)",
    re.IGNORECASE,
)


def _domain_from_url(url: str) -> str:
    m = re.search(r"https?://(?:www\.)?([^/\s?#]+)", url)
    return m.group(1).lower() if m else ""


def evaluate(finding: dict, context: dict) -> dict:
    """
    Returns a verdict dict: {"verdict": "confirm|reject|downgrade", ...}
    """
    sender = (context.get("sender") or "").lower()
    fid = finding.get("id", "")
    evidence = finding.get("evidence", "")
    tool_name = context.get("tool_name", "")

    # Fast accept: credential forwarding is always critical
    if "ASI_CRED_FORWARD" in fid:
        return {"verdict": "confirm", "reason": "Credential forwarding to external service is critical.", "confidence": 96}

    # Fast check: browser tool visiting known-safe domain
    if tool_name == "browser" or "browser" in fid.lower():
        domain = _domain_from_url(evidence)
        if domain and any(domain == sd or domain.endswith("." + sd) for sd in _SAFE_DOMAINS):
            return {"verdict": "reject", "reason": f"Browser visited trusted domain: {domain}", "confidence": 90}

    # Fast check: code interpreter with dangerous patterns
    if tool_name in ("python", "code_interpreter") and _DANGEROUS_CODE.search(evidence):
        return {"verdict": "confirm", "reason": "Code interpreter executing potentially dangerous system command.", "confidence": 88}

    # Fast check: DALL-E prompt injection
    if tool_name in ("dalle.text2im", "dalle") and _DALLE_INJECT.search(evidence):
        return {"verdict": "confirm", "reason": "DALL-E prompt contains injection keywords.", "confidence": 85}

    # Route to LLM for ambiguous ASI_ findings
    if not fid.startswith("ASI_"):
        return {"verdict": "unvalidated", "reason": "Not an agentic finding.", "confidence": 0}

    messages = [
        {"role": "system", "content": AGENTIC_PROMPT},
        {"role": "user", "content": (
            f"Finding: {fid}\n"
            f"Tool: {tool_name or 'unknown'}\n"
            f"Evidence: {evidence[:300]}\n"
            f"Sender: {sender}\n"
            f"Surrounding context: {context.get('surrounding_messages', '')[:200]}\n\n"
            "Is this AI tool usage a genuine security risk or a false positive?\n"
            'Reply JSON: {"verdict":"confirm|reject|downgrade","reason":"...","confidence":0-100}'
        )},
    ]
    raw = llm_call(messages, max_tokens=200)
    return parse_verdict(raw)
