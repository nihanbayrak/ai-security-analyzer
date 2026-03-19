"""
Agentic Risk Detector — OWASP Agentic Top 10 2026

Fix 2: Safe DevOps allowlist applied here too.
  - ASI04 (Insecure Tool Integration) only fires for actually-dangerous shell commands.
  - `curl astral.sh/uv/install.sh | sh` in a bash tool call is NOT flagged.
  - Import safe-domain check from output detector to keep the allowlist in one place.
"""

import re
import json
from typing import List
from model import Finding, Severity, ProvenanceLocator, ToolTrace


# ---------------------------------------------------------------------------
# Dangerous shell patterns — only ones that are clearly malicious
# ---------------------------------------------------------------------------

# ASI04 trigger: pipe to shell from unknown domain
_CURL_PIPE_RE = re.compile(
    r"curl\s+[^\|]*?(https?://([^/\s\"']+)[^\s\"']*)[^\|]*\|\s*(ba?sh|sh|zsh|fish)",
    re.IGNORECASE,
)
_WGET_PIPE_RE = re.compile(
    r"wget\s+[^\|]*?(https?://([^/\s\"']+)[^\s\"']*)\s*\|\s*(ba?sh|sh|zsh|fish)",
    re.IGNORECASE,
)

# Destruction of system paths (same logic as output.py)
_DANGEROUS_RM_RE = re.compile(
    r"rm\s+-[rf]{1,3}\s+(?:/\s*$|/\s+|/etc\b|/usr\b|/bin\b|/sbin\b|/boot\b|"
    r"/lib\b|/var\b|/home\b|/root\b|/proc\b|\$HOME\s*$|\$\{HOME\}|~\s*$)",
    re.IGNORECASE,
)


def _is_safe_domain(domain: str) -> bool:
    """Re-use safe domain check (import lazily to avoid circular deps)."""
    try:
        from detectors.output import SAFE_DOMAINS
    except ImportError:
        return False
    domain = domain.lower().rstrip(".")
    if domain in SAFE_DOMAINS:
        return True
    parts = domain.split(".")
    for i in range(1, len(parts)):
        if ".".join(parts[i:]) in SAFE_DOMAINS:
            return True
    return False


def detect_agentic_risks(trace: ToolTrace, locator: ProvenanceLocator) -> List[Finding]:
    """Detects OWASP Agentic Top 10 risks: Goal Hijack, Tool Misuse, Credential Forwarding.

    Fix 2: Safe DevOps install commands are NOT flagged in ASI04.
    """
    findings = []

    args_str = json.dumps(trace.args)

    # ── ASI01/02: Tool argument injection ───────────────────────────────────
    system_override_patterns = [
        r"(?i)ignore\s+previous",
        r"(?i)you\s+are\s+now",
        r"(?i)system:\s*override",
    ]
    for pattern in system_override_patterns:
        if re.search(pattern, args_str):
            findings.append(Finding(
                id="ASI_01",
                category="Agentic Risks (ASI01/02)",
                framework_mapping="OWASP Agentic Top 10 2026",
                severity=Severity.CRITICAL,
                score=100,
                confidence=0.9,
                evidence=f"Goal hijack payload in tool arguments: {trace.tool_name}",
                provenance=locator,
                recommended_action=[
                    "Halt agent execution immediately",
                    "Review source of payload",
                ],
            ))
            break

    # ── ASI04: Insecure Tool Integration — dangerous shell commands only ────
    if trace.tool_name in ("run_command", "bash", "execute", "shell", "terminal"):
        flagged = False

        # Dangerous rm (system paths)
        if _DANGEROUS_RM_RE.search(args_str):
            flagged = True
            findings.append(Finding(
                id="ASI_04",
                category="Agentic Risks (ASI04)",
                framework_mapping="OWASP Agentic Top 10 2026",
                severity=Severity.CRITICAL,
                score=100,
                confidence=0.95,
                evidence=f"Destructive rm command in tool call: {trace.tool_name}",
                provenance=locator,
                recommended_action=["Block destructive shell commands in tool perimeter"],
            ))

        # curl/wget pipe to shell — only flag untrusted domains
        if not flagged:
            for m in _CURL_PIPE_RE.finditer(args_str):
                domain = m.group(2)
                if not _is_safe_domain(domain):
                    flagged = True
                    findings.append(Finding(
                        id="ASI_04",
                        category="Agentic Risks (ASI04)",
                        framework_mapping="OWASP Agentic Top 10 2026",
                        severity=Severity.CRITICAL,
                        score=100,
                        confidence=0.95,
                        evidence=f"Untrusted curl-pipe-shell in agent tool call: {m.group(0)[:100]}",
                        provenance=locator,
                        recommended_action=["Block pipe-to-shell from unknown domains in tool perimeter"],
                    ))
                    break

        if not flagged:
            for m in _WGET_PIPE_RE.finditer(args_str):
                domain = m.group(2)
                if not _is_safe_domain(domain):
                    findings.append(Finding(
                        id="ASI_04",
                        category="Agentic Risks (ASI04)",
                        framework_mapping="OWASP Agentic Top 10 2026",
                        severity=Severity.CRITICAL,
                        score=100,
                        confidence=0.95,
                        evidence=f"Untrusted wget-pipe-shell in agent tool call: {m.group(0)[:100]}",
                        provenance=locator,
                        recommended_action=["Block pipe-to-shell from unknown domains in tool perimeter"],
                    ))
                    break

    # ── ASI03: Credential forwarding in tool args ───────────────────────────
    aws_pattern = r"(AKIA[0-9A-Z]{16})"
    if re.search(aws_pattern, args_str):
        findings.append(Finding(
            id="ASI_03",
            category="Agentic Risks (ASI03)",
            framework_mapping="OWASP Agentic Top 10 2026",
            severity=Severity.CRITICAL,
            score=95,
            confidence=0.9,
            evidence=f"Credential detected in parameters for tool: {trace.tool_name}",
            provenance=locator,
            recommended_action=[
                "Verify agent is not exfiltrating keys",
                "Rotate keys if unsure",
            ],
        ))

    return findings
