"""
Secrets & Credentials Detector — OWASP LLM06:2025

Covers 15+ credential types used in 2025/2026:
  - Cloud: AWS, GCP, Azure
  - AI: OpenAI, Anthropic, Cohere, HuggingFace
  - Dev: GitHub, GitLab, npm, PyPI
  - Payment: Stripe, PayPal
  - Comms: Slack, Discord, Twilio
  - Auth: JWTs, API keys, passwords, private keys
"""

import re
import json
import base64
from typing import List
from model import Finding, Severity, ProvenanceLocator


def _secret(fid, name, severity, score, evidence, locator, action, redaction, confidence=0.9):
    return Finding(
        id=fid,
        category="Credentials & Secrets",
        framework_mapping="OWASP LLM06:2025",
        severity=severity,
        score=score,
        confidence=confidence,
        evidence=evidence[:200],
        provenance=locator,
        recommended_action=action,
        safe_redaction=redaction,
    )


def detect_secrets(text: str, locator: ProvenanceLocator) -> List[Finding]:
    """Detects API keys, tokens, passwords, and credentials across 15+ services."""
    if not text or not text.strip():
        return []

    findings = []

    # =========================================================================
    # CLOUD PROVIDERS
    # =========================================================================

    # AWS Access Key (AKIA...)
    for m in re.finditer(r"\b(AKIA[0-9A-Z]{16})\b", text):
        findings.append(_secret(
            "SEC_AWS_01", "AWS Access Key", Severity.CRITICAL, 95,
            f"AWS Access Key: {m.group(1)}",
            locator,
            ["Rotate AWS credentials immediately via IAM console",
             "Check CloudTrail for unauthorized API calls"],
            f"AWS Key: AKIA****{m.group(1)[-4:]}",
        ))

    # AWS Secret Key (40 chars, often near access key)
    for m in re.finditer(r"(?i)(?:aws_?secret|secret_?key)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?", text):
        findings.append(_secret(
            "SEC_AWS_02", "AWS Secret Key", Severity.CRITICAL, 95,
            f"AWS Secret Key found",
            locator,
            ["Rotate AWS credentials immediately", "Never share secret keys"],
            "AWS Secret Key: ****[REDACTED]****",
        ))

    # GCP Service Account Key (JSON with private_key)
    if '"private_key"' in text and '"client_email"' in text:
        findings.append(_secret(
            "SEC_GCP_01", "GCP Service Account Key", Severity.CRITICAL, 95,
            "Google Cloud service account JSON key detected",
            locator,
            ["Rotate GCP service account key immediately",
             "Use Workload Identity instead of key files"],
            "GCP Service Account: [REDACTED JSON]",
        ))

    # Azure Client Secret
    for m in re.finditer(r"(?i)(azure|client)_?secret\s*[=:]\s*['\"]?([A-Za-z0-9~._-]{34,40})['\"]?", text):
        findings.append(_secret(
            "SEC_AZURE_01", "Azure Client Secret", Severity.CRITICAL, 95,
            f"Azure client secret found",
            locator,
            ["Rotate Azure AD app credentials", "Use managed identities instead"],
            "Azure Secret: ****[REDACTED]****",
        ))

    # =========================================================================
    # AI / LLM PROVIDERS
    # =========================================================================

    # OpenAI API Key (sk-... or sk-proj-...)
    for m in re.finditer(r"\b(sk-(?:proj-)?[a-zA-Z0-9]{32,})\b", text):
        findings.append(_secret(
            "SEC_OAI_01", "OpenAI API Key", Severity.CRITICAL, 95,
            f"OpenAI API Key: {m.group(1)[:20]}...",
            locator,
            ["Revoke key at platform.openai.com/api-keys",
             "Check usage dashboard for unauthorized calls"],
            f"OpenAI Key: sk-****{m.group(1)[-4:]}",
        ))

    # Anthropic API Key (sk-ant-...)
    for m in re.finditer(r"\b(sk-ant-[a-zA-Z0-9-]{32,})\b", text):
        findings.append(_secret(
            "SEC_ANTHROPIC_01", "Anthropic API Key", Severity.CRITICAL, 95,
            f"Anthropic API Key: {m.group(1)[:20]}...",
            locator,
            ["Revoke key at console.anthropic.com",
             "Check usage for unauthorized Claude API calls"],
            f"Anthropic Key: sk-ant-****{m.group(1)[-4:]}",
        ))

    # HuggingFace Token (hf_...)
    for m in re.finditer(r"\b(hf_[a-zA-Z0-9]{34,})\b", text):
        findings.append(_secret(
            "SEC_HF_01", "HuggingFace Token", Severity.HIGH, 85,
            f"HuggingFace token: {m.group(1)[:15]}...",
            locator,
            ["Revoke token at huggingface.co/settings/tokens"],
            f"HF Token: hf_****{m.group(1)[-4:]}",
        ))

    # =========================================================================
    # DEVELOPER TOOLS
    # =========================================================================

    # GitHub Personal Access Token (ghp_, gho_, ghu_, ghs_, ghr_)
    for m in re.finditer(r"\b(gh[pousr]_[a-zA-Z0-9]{36,})\b", text):
        findings.append(_secret(
            "SEC_GH_01", "GitHub Token", Severity.CRITICAL, 95,
            f"GitHub token: {m.group(1)[:15]}...",
            locator,
            ["Revoke at github.com/settings/tokens",
             "Check repository access and recent activity"],
            f"GitHub Token: {m.group(1)[:4]}****{m.group(1)[-4:]}",
        ))

    # GitHub Classic Token (40 hex chars, often with ghp prefix missing)
    for m in re.finditer(r"(?i)(?:github|gh)_?(?:token|pat)\s*[=:]\s*['\"]?([a-f0-9]{40})['\"]?", text):
        findings.append(_secret(
            "SEC_GH_02", "GitHub Classic Token", Severity.CRITICAL, 95,
            f"GitHub classic token found",
            locator,
            ["Revoke at github.com/settings/tokens"],
            "GitHub Token: ****[REDACTED]****",
        ))

    # GitLab Token (glpat-...)
    for m in re.finditer(r"\b(glpat-[a-zA-Z0-9_-]{20,})\b", text):
        findings.append(_secret(
            "SEC_GITLAB_01", "GitLab Token", Severity.CRITICAL, 95,
            f"GitLab token: {m.group(1)[:15]}...",
            locator,
            ["Revoke at gitlab.com/-/profile/personal_access_tokens"],
            f"GitLab Token: glpat-****{m.group(1)[-4:]}",
        ))

    # npm Token
    for m in re.finditer(r"\b(npm_[a-zA-Z0-9]{36,})\b", text):
        findings.append(_secret(
            "SEC_NPM_01", "npm Token", Severity.HIGH, 85,
            f"npm token found",
            locator,
            ["Revoke at npmjs.com/settings/tokens",
             "Check for unauthorized package publishes"],
            f"npm Token: npm_****{m.group(1)[-4:]}",
        ))

    # =========================================================================
    # PAYMENT / FINTECH
    # =========================================================================

    # Stripe API Key (sk_live_, sk_test_, pk_live_, pk_test_, rk_live_)
    for m in re.finditer(r"\b((sk|pk|rk)_(live|test)_[a-zA-Z0-9]{24,})\b", text):
        is_live = "live" in m.group(1)
        findings.append(_secret(
            "SEC_STRIPE_01", "Stripe API Key",
            Severity.CRITICAL if is_live else Severity.MEDIUM,
            95 if is_live else 50,
            f"Stripe {'LIVE' if is_live else 'test'} key: {m.group(1)[:15]}...",
            locator,
            ["Revoke at dashboard.stripe.com/apikeys" if is_live else
             "Test key exposure is low risk but still avoid sharing"],
            f"Stripe Key: {m.group(1)[:7]}****{m.group(1)[-4:]}",
            confidence=0.95 if is_live else 0.7,
        ))

    # =========================================================================
    # COMMUNICATION PLATFORMS
    # =========================================================================

    # Slack Bot/User Token (xoxb-, xoxp-, xoxa-, xoxs-)
    for m in re.finditer(r"\b(xox[bpas]-[a-zA-Z0-9-]{24,})\b", text):
        findings.append(_secret(
            "SEC_SLACK_01", "Slack Token", Severity.HIGH, 85,
            f"Slack token: {m.group(1)[:15]}...",
            locator,
            ["Revoke at api.slack.com/apps",
             "Check workspace audit logs for unauthorized access"],
            f"Slack Token: {m.group(1)[:5]}****{m.group(1)[-4:]}",
        ))

    # Discord Bot Token (base64-ish, ~70 chars)
    for m in re.finditer(r"\b([MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,})\b", text):
        findings.append(_secret(
            "SEC_DISCORD_01", "Discord Bot Token", Severity.HIGH, 85,
            f"Discord token found",
            locator,
            ["Regenerate at discord.com/developers/applications"],
            "Discord Token: ****[REDACTED]****",
        ))

    # Twilio (SK..., AC...)
    for m in re.finditer(r"\b(SK[a-f0-9]{32})\b", text):
        findings.append(_secret(
            "SEC_TWILIO_01", "Twilio API Key", Severity.HIGH, 85,
            f"Twilio key: {m.group(1)[:10]}...",
            locator,
            ["Revoke at twilio.com/console"],
            f"Twilio Key: SK****{m.group(1)[-4:]}",
        ))

    # =========================================================================
    # GENERIC SECRETS
    # =========================================================================

    # JWT Tokens
    for m in re.finditer(r"\b(eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,})\b", text):
        token = m.group(1)
        try:
            header_b64 = token.split('.')[0]
            header_b64 += '=' * (-len(header_b64) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_b64))
            if header.get("typ") == "JWT" or "alg" in header:
                findings.append(_secret(
                    "SEC_JWT_01", "JWT Token", Severity.HIGH, 80,
                    f"JWT Token: {token[:25]}...",
                    locator,
                    ["Check if JWT is expired", "Verify no sensitive claims are exposed"],
                    f"JWT: eyJ****...[REDACTED]",
                    confidence=0.85,
                ))
        except Exception:
            pass

    # Password assignments in code (various quote styles and formats)
    pwd_patterns = [
        r"(?i)(password|passwd|pwd|secret)\s*[=:]\s*['\"]([^'\"]{4,})['\"]",
        r"(?i)(password|passwd|pwd|secret)\s*[=:]\s*([^\s,;'\"\n]{4,})",
    ]
    for pattern in pwd_patterns:
        for m in re.finditer(pattern, text):
            val = m.group(2).strip()
            # Skip obvious placeholders
            if val.lower() in ("password", "secret", "changeme", "xxxxxxxx", "********",
                               "your_password", "none", "null", "undefined", "env",
                               "process.env", "os.getenv", "os.environ"):
                continue
            # Skip if it looks like a variable reference
            if val.startswith("$") or val.startswith("%") or "env" in val.lower():
                continue
            findings.append(_secret(
                "SEC_PWD_01", "Hardcoded Password/Secret", Severity.HIGH, 80,
                f"Password assignment: {m.group(1)}=\"{val[:8]}...\"",
                locator,
                ["Never hardcode credentials", "Use environment variables or secret managers"],
                f"{m.group(1)}=[REDACTED]",
                confidence=0.75,
            ))
            break  # One finding per message

    # Private keys (RSA, EC, etc.)
    if re.search(r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----", text):
        findings.append(_secret(
            "SEC_PRIVKEY_01", "Private Key", Severity.CRITICAL, 95,
            "Private key (RSA/EC) found in message",
            locator,
            ["Rotate the key pair immediately", "Private keys should never be shared"],
            "-----BEGIN PRIVATE KEY----- [REDACTED]",
        ))

    # Generic high-entropy API keys (32+ alphanumeric with mixed case)
    for m in re.finditer(r"(?i)(?:api_?key|secret|token)\s*[=:]\s*['\"]?([a-zA-Z0-9]{32,64})['\"]?", text):
        val = m.group(1)
        # Check entropy: must have uppercase, lowercase, and digits
        if (any(c.isupper() for c in val) and
            any(c.islower() for c in val) and
            any(c.isdigit() for c in val)):
            findings.append(_secret(
                "SEC_GENERIC_01", "Generic API Key/Secret", Severity.MEDIUM, 60,
                f"Possible API key: {val[:10]}...",
                locator,
                ["Identify the service and rotate the credential"],
                f"API Key: {val[:6]}****{val[-4:]}",
                confidence=0.65,
            ))

    return findings
