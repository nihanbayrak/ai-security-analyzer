"""
Output Risk Detector — OWASP LLM05:2025

Fix 2: Safe DevOps commands allowlist.

A cybersecurity professional will immediately lose trust if `curl astral.sh/uv/install.sh | sh`
or `rm -rf node_modules` is flagged as "dangerous code". These are standard, widely used
DevOps install patterns from trusted domains.

Strategy:
  - SAFE_DOMAINS: known installer CDN domains — never flagged
  - SAFE_RM_PATHS: `rm -rf` targets that are normal cleanup (node_modules, __pycache__, etc.)
  - Only flag curl/wget pipe-to-shell if the domain is NOT in SAFE_DOMAINS
  - Only flag rm -rf if it targets / or a suspicious path (not project cleanup dirs)
"""

import re
from typing import List
from model import Finding, Severity, ProvenanceLocator

# ---------------------------------------------------------------------------
# Safe domain allowlist — curl/wget from these are normal DevOps installs
# ---------------------------------------------------------------------------

SAFE_DOMAINS = {
    # Python ecosystem
    "astral.sh",           # uv installer
    "bootstrap.pypa.io",   # pip bootstrap
    "install.python-poetry.org",
    "raw.githubusercontent.com",  # GitHub raw — broad but needed for most installs
    # Rust / system
    "sh.rustup.rs",
    "rustup.rs",
    # Container / k8s
    "get.docker.com",
    "get.k3s.io",
    "get.helm.sh",
    "raw.helm.sh",
    "kind.sigs.k8s.io",
    # Node
    "deb.nodesource.com",
    "rpm.nodesource.com",
    "install.node.dev",
    # General package managers
    "get.brew.sh",
    "homebrew.sh",
    # Cloud CLIs
    "awscli.amazonaws.com",
    "sdk.cloud.google.com",
    "aka.ms",              # Azure CLI
    # Other common DevTools
    "get.oh-my-zsh.sh",
    "install.oh-my-zsh.sh",
    "ohmyz.sh",
    "starship.rs",
    "nvm.sh",
    "volta.sh",
    "get.volta.sh",
    "bun.sh",
    "get.bun.sh",
}

# rm -rf paths that are standard project cleanup (not dangerous)
_SAFE_RM_RE = re.compile(
    r"rm\s+-rf\s+(?:"
    r"node_modules|\.next|dist|build|__pycache__|\.pytest_cache|\.mypy_cache|"
    r"\.ruff_cache|\.tox|\.eggs|target|\.cache|\.venv|venv|env|\.env|"
    r"coverage|htmlcov|\.coverage|\.DS_Store|Thumbs\.db|\.gradle|\.idea|"
    r"\.vscode|out|tmp|temp|\.tmp|\.temp|logs?|\.log"
    r")(?:\s|$)",
    re.IGNORECASE,
)

# rm -rf patterns that ARE dangerous (deleting / or critical system paths)
_DANGEROUS_RM_RE = re.compile(
    r"rm\s+-[rf]{1,3}\s+(?:"
    r"/\s*$|/\s+|"                      # rm -rf / (root deletion)
    r"/etc\b|/usr\b|/bin\b|/sbin\b|"   # critical system dirs
    r"/boot\b|/lib\b|/var\b|"
    r"/home\b|/root\b|/proc\b|"
    r"\$HOME\s*$|\$\{HOME\}|"
    r"~\s*$"                            # rm -rf ~ (home directory)
    r")",
    re.IGNORECASE,
)

# curl/wget pipe-to-shell — extract the URL to check the domain
_CURL_PIPE_RE = re.compile(
    r"curl\s+[^\|]*?(https?://([^/\s\"']+)[^\s\"']*)[^\|]*\|\s*(ba?sh|sh|zsh|fish|pwsh)",
    re.IGNORECASE,
)
_WGET_PIPE_RE = re.compile(
    r"wget\s+[^\|]*?(https?://([^/\s\"']+)[^\s\"']*)[^\s]*.*\|\s*(ba?sh|sh|zsh|fish)",
    re.IGNORECASE,
)

# PowerShell execution (less common legitimate use, higher risk)
_POWERSHELL_EXEC_RE = re.compile(
    r"(?:Invoke-Expression|IEX)\s*\(",
    re.IGNORECASE,
)

# JavaScript injection in output
_JS_INJECT_RE = re.compile(
    r"(?:<script\b[^>]*>[\s\S]*?</script>|javascript:\s*[^\s\"']{5,})",
    re.IGNORECASE,
)


def _is_safe_domain(domain: str) -> bool:
    """Return True if domain or any parent matches SAFE_DOMAINS."""
    domain = domain.lower().rstrip(".")
    if domain in SAFE_DOMAINS:
        return True
    # Check parent domains (e.g. "cdn.astral.sh" → "astral.sh")
    parts = domain.split(".")
    for i in range(1, len(parts)):
        if ".".join(parts[i:]) in SAFE_DOMAINS:
            return True
    return False


def detect_output_risks(text: str, locator: ProvenanceLocator) -> List[Finding]:
    """Checks assistant output for genuinely dangerous generated commands.

    Fix 2: Safe DevOps allowlist — standard installer scripts (uv, rustup,
    docker, poetry, etc.) are NOT flagged. Only unknown-domain pipe-to-shell
    and system-destructive rm -rf are flagged.
    """
    findings = []

    if locator.role != "assistant":
        return findings

    # ── 1. curl | sh — only flag non-safe domains ──────────────────────────
    for m in _CURL_PIPE_RE.finditer(text):
        url, domain, shell = m.group(1), m.group(2), m.group(3)
        if _is_safe_domain(domain):
            continue  # trusted installer CDN — not dangerous
        findings.append(Finding(
            id="OUT_CODE",
            category="Output Security",
            framework_mapping="OWASP LLM05:2025",
            severity=Severity.HIGH,
            score=80,
            confidence=0.85,
            evidence=f"Untrusted curl-pipe-shell: {m.group(0)[:120]}",
            provenance=locator,
            recommended_action=[
                "Verify the source domain before piping scripts to shell",
                "Download first, inspect, then run",
            ],
            safe_redaction="[DANGEROUS CURL PIPE REDACTED]",
        ))

    # ── 2. wget | sh — only flag non-safe domains ───────────────────────────
    for m in _WGET_PIPE_RE.finditer(text):
        url, domain, shell = m.group(1), m.group(2), m.group(3)
        if _is_safe_domain(domain):
            continue
        findings.append(Finding(
            id="OUT_CODE",
            category="Output Security",
            framework_mapping="OWASP LLM05:2025",
            severity=Severity.HIGH,
            score=80,
            confidence=0.85,
            evidence=f"Untrusted wget-pipe-shell: {m.group(0)[:120]}",
            provenance=locator,
            recommended_action=[
                "Verify the source domain before piping scripts to shell",
                "Download first, inspect, then run",
            ],
            safe_redaction="[DANGEROUS WGET PIPE REDACTED]",
        ))

    # ── 3. Dangerous rm -rf (system paths / root) ───────────────────────────
    m = _DANGEROUS_RM_RE.search(text)
    if m:
        # Skip if it also matches safe cleanup patterns (shouldn't overlap, but be safe)
        if not _SAFE_RM_RE.search(m.group(0)):
            findings.append(Finding(
                id="OUT_CODE",
                category="Output Security",
                framework_mapping="OWASP LLM05:2025",
                severity=Severity.CRITICAL,
                score=95,
                confidence=0.92,
                evidence=f"System-destructive rm command: {m.group(0)[:80]}",
                provenance=locator,
                recommended_action=[
                    "Never run AI-generated rm -rf commands targeting system directories",
                    "Double-check path before executing",
                ],
                safe_redaction="[DANGEROUS RM COMMAND REDACTED]",
            ))

    # ── 4. PowerShell Invoke-Expression ─────────────────────────────────────
    m = _POWERSHELL_EXEC_RE.search(text)
    if m:
        findings.append(Finding(
            id="OUT_CODE",
            category="Output Security",
            framework_mapping="OWASP LLM05:2025",
            severity=Severity.HIGH,
            score=75,
            confidence=0.80,
            evidence=f"PowerShell execution expression: {m.group(0)[:80]}",
            provenance=locator,
            recommended_action=[
                "Avoid Invoke-Expression with dynamic input",
                "Review full script before executing",
            ],
            safe_redaction="[POWERSHELL EXEC REDACTED]",
        ))

    # ── 5. JavaScript injection in output ───────────────────────────────────
    m = _JS_INJECT_RE.search(text)
    if m:
        findings.append(Finding(
            id="OUT_CODE",
            category="Output Security",
            framework_mapping="OWASP LLM05:2025",
            severity=Severity.HIGH,
            score=80,
            confidence=0.88,
            evidence=f"JavaScript injection pattern in output: {m.group(0)[:80]}",
            provenance=locator,
            recommended_action=[
                "Sanitize AI output before rendering in a browser context",
                "Use Content-Security-Policy headers",
            ],
            safe_redaction="[JS INJECTION REDACTED]",
        ))

    return findings
